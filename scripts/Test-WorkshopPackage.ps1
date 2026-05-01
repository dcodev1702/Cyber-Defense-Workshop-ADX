[CmdletBinding()]
param(
    [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [string]$DataDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$errors = New-Object System.Collections.Generic.List[string]

function Add-TestError {
    param([string]$Message)
    $script:errors.Add($Message) | Out-Null
}

$scriptFiles = Get-ChildItem -Path (Join-Path $Root 'scripts') -Include '*.ps1', '*.psm1' -Recurse
foreach ($scriptFile in $scriptFiles) {
    $tokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($scriptFile.FullName, [ref]$tokens, [ref]$parseErrors) | Out-Null
    foreach ($parseError in $parseErrors) {
        Add-TestError "PowerShell parse error in $($scriptFile.FullName): $($parseError.Message)"
    }
}

$manifestPath = Join-Path $Root 'metadata\tables.manifest.json'
if (-not (Test-Path $manifestPath)) {
    Add-TestError "Missing manifest: $manifestPath"
}
else {
    try {
        $manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json
    }
    catch {
        Add-TestError "Manifest is not valid JSON: $($_.Exception.Message)"
        $manifest = @()
    }

    foreach ($entry in $manifest) {
        $schemaPath = Join-Path $Root "schemas\$($entry.name).schema.json"
        if (-not (Test-Path $schemaPath)) {
            Add-TestError "Missing schema for table $($entry.name): $schemaPath"
        }
    }
}

$schemaFiles = Get-ChildItem -Path (Join-Path $Root 'schemas') -Filter '*.schema.json'
foreach ($schemaFile in $schemaFiles) {
    try {
        $schema = Get-Content -Path $schemaFile.FullName -Raw | ConvertFrom-Json
    }
    catch {
        Add-TestError "Schema is not valid JSON: $($schemaFile.FullName): $($_.Exception.Message)"
        continue
    }

    if (-not $schema.tableName) {
        Add-TestError "Schema missing tableName: $($schemaFile.FullName)"
    }
    if (-not $schema.columns -or $schema.columns.Count -eq 0) {
        Add-TestError "Schema has no columns: $($schemaFile.FullName)"
    }
    foreach ($column in $schema.columns) {
        if (-not $column.name -or -not $column.type) {
            Add-TestError "Schema has malformed column in $($schemaFile.FullName)"
        }
        if ($column.type -notin @('bool', 'datetime', 'dynamic', 'guid', 'int', 'long', 'real', 'string')) {
            Add-TestError "Unsupported ADX type '$($column.type)' in $($schemaFile.FullName)"
        }
    }
}

if ([string]::IsNullOrWhiteSpace($DataDirectory)) {
    $DataDirectory = Join-Path $Root 'data\generated'
}
elseif (-not [System.IO.Path]::IsPathRooted($DataDirectory)) {
    $DataDirectory = Join-Path (Get-Location).Path $DataDirectory
}
if (-not (Test-Path $DataDirectory)) {
    Add-TestError "Missing generated data directory: $DataDirectory"
}
else {
    foreach ($dataFile in (Get-ChildItem -Path $DataDirectory -Filter '*.json')) {
        $table = $dataFile.BaseName
        $schemaPath = Join-Path $Root "schemas\$table.schema.json"
        if (-not (Test-Path $schemaPath)) {
            Add-TestError "Generated data has no schema: $($dataFile.FullName)"
            continue
        }

        $schema = Get-Content -Path $schemaPath -Raw | ConvertFrom-Json
        $schemaColumns = @($schema.columns.name)
        $schemaColumnSet = @{}
        foreach ($column in $schemaColumns) {
            $schemaColumnSet[$column] = $true
        }

        $lineNumber = 0
        foreach ($line in (Get-Content -Path $dataFile.FullName)) {
            $lineNumber++
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }
            try {
                $record = $line | ConvertFrom-Json
            }
            catch {
                Add-TestError "Invalid JSON in $($dataFile.FullName) line $lineNumber`: $($_.Exception.Message)"
                continue
            }

            $recordColumns = @($record.PSObject.Properties.Name)
            foreach ($column in $recordColumns) {
                if (-not $schemaColumnSet.ContainsKey($column)) {
                    Add-TestError "$($dataFile.Name) line $lineNumber has column not in schema: $column"
                }
            }
            foreach ($column in $schemaColumns) {
                if ($recordColumns -notcontains $column) {
                    Add-TestError "$($dataFile.Name) line $lineNumber missing schema column: $column"
                }
            }
        }
    }

    $linuxDeviceIds = @{}
    $linuxDeviceNames = @{}
    $deviceInfoPath = Join-Path $DataDirectory 'DeviceInfo.json'
    if (Test-Path $deviceInfoPath) {
        foreach ($line in (Get-Content -Path $deviceInfoPath)) {
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }

            $record = $line | ConvertFrom-Json
            if ([string]$record.OSPlatform -match 'Ubuntu|Linux' -or [string]$record.OSDistribution -match 'Ubuntu|Linux') {
                if ($record.DeviceId) {
                    $linuxDeviceIds[[string]$record.DeviceId] = $true
                }
                if ($record.DeviceName) {
                    $linuxDeviceNames[[string]$record.DeviceName] = $true
                }
            }
        }
    }

    $linuxEvidence = @{
        LinuxPath = 0
        SharedObject = 0
        SshOrSudo = 0
        Vulnerability = 0
    }
    $linuxCves = @(
        'CVE-2024-6387',
        'CVE-2024-47176',
        'CVE-2024-47076',
        'CVE-2024-47175',
        'CVE-2024-47177',
        'CVE-2025-32463',
        'CVE-2025-32462',
        'CVE-2023-4911',
        'CVE-2024-53197',
        'CVE-2024-5535'
    )

    foreach ($dataFile in (Get-ChildItem -Path $DataDirectory -Filter '*.json')) {
        $table = $dataFile.BaseName
        $lineNumber = 0
        foreach ($line in (Get-Content -Path $dataFile.FullName)) {
            $lineNumber++
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }

            $record = $line | ConvertFrom-Json
            $deviceIdProperty = $record.PSObject.Properties['DeviceId']
            $deviceNameProperty = $record.PSObject.Properties['DeviceName']
            $deviceId = if ($deviceIdProperty) { [string]$deviceIdProperty.Value } else { '' }
            $deviceName = if ($deviceNameProperty) { [string]$deviceNameProperty.Value } else { '' }
            $isLinuxRecord = ($deviceId -and $linuxDeviceIds.ContainsKey($deviceId)) -or ($deviceName -and $linuxDeviceNames.ContainsKey($deviceName))
            if (-not $isLinuxRecord) {
                continue
            }

            if ($table -eq 'DeviceRegistryEvents') {
                Add-TestError "$($dataFile.Name) line $lineNumber is a Linux device row in Windows-only DeviceRegistryEvents."
            }

            foreach ($fieldName in @('FolderPath', 'InitiatingProcessFolderPath', 'ProcessCommandLine', 'InitiatingProcessCommandLine', 'RegistryKey', 'FileName')) {
                $property = $record.PSObject.Properties[$fieldName]
                if (-not $property -or $null -eq $property.Value) {
                    continue
                }

                $value = [string]$property.Value
                if ($value -match '^[A-Za-z]:\\|\\Windows\\|HKEY_|\.dll(\s|$|")') {
                    Add-TestError "$($dataFile.Name) line $lineNumber has Windows artifact '$fieldName=$value' on Linux device $deviceName."
                }
                if ($value -match '^/| /') {
                    $linuxEvidence.LinuxPath++
                }
                if ($table -eq 'DeviceImageLoadEvents' -and $value -match '\.so(\.|$)') {
                    $linuxEvidence.SharedObject++
                }
                if ($value -match '\b(sshd|ssh|sudo|auditd|apt|dpkg|bash)\b') {
                    $linuxEvidence.SshOrSudo++
                }
            }

            if ($table -eq 'DeviceLogonEvents') {
                if ([string]$record.Protocol -in @('Kerberos', 'NTLM', 'Negotiate')) {
                    Add-TestError "$($dataFile.Name) line $lineNumber has Windows auth protocol '$($record.Protocol)' on Linux device $deviceName."
                }
                if ([string]$record.LogonType -in @('RemoteInteractive', 'CachedInteractive')) {
                    Add-TestError "$($dataFile.Name) line $lineNumber has Windows logon type '$($record.LogonType)' on Linux device $deviceName."
                }
            }

            if ($table -like 'DeviceTvm*') {
                $cveProperty = $record.PSObject.Properties['CveId']
                if ($cveProperty -and [string]$cveProperty.Value -in $linuxCves) {
                    $linuxEvidence.Vulnerability++
                }
            }
        }
    }

    if ($linuxDeviceIds.Count -gt 0) {
        if ($linuxEvidence.LinuxPath -eq 0) {
            Add-TestError 'Linux validation expected at least one Linux path in generated device telemetry.'
        }
        if ($linuxEvidence.SharedObject -eq 0) {
            Add-TestError 'Linux validation expected at least one .so shared object image-load row.'
        }
        if ($linuxEvidence.SshOrSudo -eq 0) {
            Add-TestError 'Linux validation expected at least one SSH/sudo/audit/package process indicator.'
        }
        if ($linuxEvidence.Vulnerability -eq 0) {
            Add-TestError 'Linux validation expected at least one Linux TVM CVE row.'
        }
    }
}

if ($errors.Count -gt 0) {
    $errors | ForEach-Object { Write-Error $_ }
    throw "Workshop package validation failed with $($errors.Count) error(s)."
}

Write-Host 'Workshop package validation passed.'
