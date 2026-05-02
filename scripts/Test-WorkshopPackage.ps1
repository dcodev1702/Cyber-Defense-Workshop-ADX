<#
.SYNOPSIS
Validates the workshop package, schemas, scripts, and generated telemetry.

.DESCRIPTION
Runs PowerShell parser checks across scripts/modules, verifies schema and manifest
consistency, validates generated NDJSON files against table schemas, and enforces
Linux telemetry realism checks such as Linux paths, .so image loads, SSH/sudo
evidence, TVM CVEs, and Oracle branch evidence.

.EXAMPLE
.\scripts\Test-WorkshopPackage.ps1

.EXAMPLE
.\scripts\Test-WorkshopPackage.ps1 -DataDirectory "$env:TEMP\CyberDefenseKqlWorkshop\cyber-defend-q0xxzc\generated"

.NOTES
Name: Test-WorkshopPackage.ps1
Date: 2026-05-01
Authors: dcodev1702 and GitHub Copilot CLI w/ ChatGPT 5.5 xhigh
Dependencies: Local repository schemas, metadata manifest, generated NDJSON telemetry.
Key commands: Parser.ParseFile, ConvertFrom-Json, Get-ChildItem, Get-Content.
#>
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

function Test-GeneratedFileContainsText {
    param(
        [Parameter(Mandatory)][string]$DataDirectory,
        [Parameter(Mandatory)][string]$FileName,
        [Parameter(Mandatory)][string[]]$Needles,
        [Parameter(Mandatory)][string]$Description
    )

    $filePath = Join-Path $DataDirectory $FileName
    if (-not (Test-Path $filePath)) {
        Add-TestError "Scenario validation expected $FileName for $Description."
        return
    }

    $content = [System.IO.File]::ReadAllText($filePath)
    foreach ($needle in $Needles) {
        if (-not $content.Contains($needle)) {
            Add-TestError "Scenario validation missing '$needle' in $FileName for $Description."
        }
    }
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

$realExportSchemaChecks = @(
    @{ Table = 'DeviceTvmCertificateInfo'; Csv = 'sample\DeviceTvmCertificateInfo-Real.csv' },
    @{ Table = 'DeviceTvmHardwareFirmware'; Csv = 'sample\DeviceTvmHardwareFirmware-Real.csv' },
    @{ Table = 'DeviceTvmInfoGathering'; Csv = 'sample\DeviceTVMInfoGrathering-Real.csv' },
    @{ Table = 'DeviceTvmInfoGatheringKB'; Csv = 'sample\DeviceTvmInfoGatheringKB-Real.csv' },
    @{ Table = 'DeviceTvmSecureConfigurationAssessment'; Csv = 'sample\DeviceTvmSecureConfigurationAssessment-Real.csv' },
    @{ Table = 'DeviceTvmSoftwareEvidenceBeta'; Csv = 'sample\DeviceTvmSoftwareEvidenceBeta-Real.csv' },
    @{ Table = 'DeviceTvmSoftwareInventory'; Csv = 'sample\DeviceTvmSoftwareInventory-Real.csv' },
    @{ Table = 'DeviceTvmSoftwareVulnerabilities'; Csv = 'sample\DeviceTvmSoftwareVulnerabilities-Real.csv' },
    @{ Table = 'DeviceTvmSoftwareVulnerabilitiesKB'; Csv = 'sample\DeviceTvmSoftwareVulnerabilitiesKB-Real.csv' },
    @{ Table = 'SecurityIncident'; Csv = 'sample\SecurityIncident-Real.csv' }
)
foreach ($check in $realExportSchemaChecks) {
    $table = [string]$check.Table
    $csvPath = Join-Path $Root ([string]$check.Csv)
    $schemaPath = Join-Path $Root "schemas\$table.schema.json"
    if (-not (Test-Path $csvPath)) {
        Add-TestError "Missing real export sample for $table`: $csvPath"
        continue
    }
    if (-not (Test-Path $schemaPath)) {
        Add-TestError "Missing schema for real export table $table`: $schemaPath"
        continue
    }

    $csvFirstRow = Import-Csv -Path $csvPath | Select-Object -First 1
    if (-not $csvFirstRow) {
        Add-TestError "Real export sample for $table has no rows: $csvPath"
        continue
    }

    $csvColumns = @($csvFirstRow.PSObject.Properties.Name)
    $schema = Get-Content -Path $schemaPath -Raw | ConvertFrom-Json
    $schemaColumns = @($schema.columns.name)
    if (($csvColumns -join '|') -ne ($schemaColumns -join '|')) {
        Add-TestError "Schema columns for $table do not match real export header order. CSV=[$($csvColumns -join ', ')] Schema=[$($schemaColumns -join ', ')]"
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
        PythonOrGo = 0
        OracleAccess = 0
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
                if ($value -match '\b(python3|\.py|ora_collect_linux_amd64)\b') {
                    $linuxEvidence.PythonOrGo++
                }
                if ($value -match '(oracle|ORCL|1521|/u01/app/oracle|/opt/oracle)' ) {
                    $linuxEvidence.OracleAccess++
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
        if ($linuxEvidence.PythonOrGo -eq 0) {
            Add-TestError 'Linux validation expected Python or Go-style Linux tooling evidence.'
        }
        if ($linuxEvidence.OracleAccess -eq 0) {
            Add-TestError 'Linux validation expected Oracle database access evidence.'
        }
    }

    $scenarioChecks = @(
        @{
            FileName = 'SigninLogs.json'
            Needles = @('victor.alvarez@usag-cyber.local', '185.225.73.18', '"IsRisky":true')
            Description = 'risky Victor Alvarez Entra sign-in'
        },
        @{
            FileName = 'CloudAppEvents.json'
            Needles = @('OAuthAppConsentGranted', 'USAG Cyber Sync Helper', 'ServicePrincipalCredentialAdded', 'MIDNIGHT BLIZZARD')
            Description = 'OAuth consent and service-principal credential abuse'
        },
        @{
            FileName = 'AuditLogs.json'
            Needles = @('Consent to application', 'Add service principal credentials', 'USAG Cyber Sync Helper', 'T1098.001')
            Description = 'audit evidence for OAuth consent and service-principal persistence'
        },
        @{
            FileName = 'AADServicePrincipalSignInLogs.json'
            Needles = @('USAG Cyber Sync Helper', 'Microsoft Graph', 'client secret')
            Description = 'malicious OAuth service-principal sign-in'
        },
        @{
            FileName = 'GraphApiAuditEvents.json'
            Needles = @('addPassword', 'Mail.Read', 'Files.Read.All', 'Directory.ReadWrite.All', 'victor.alvarez@usag-cyber.local')
            Description = 'Graph API mailbox, file, directory, and service-principal operations'
        },
        @{
            FileName = 'MicrosoftGraphActivityLogs.json'
            Needles = @('addPassword', 'messages', 'drive/root/children', 'GraphPowerShell')
            Description = 'Microsoft Graph activity log collection path'
        },
        @{
            FileName = 'DeviceProcessEvents.json'
            Needles = @('reg.exe', 'esentutl.exe', 'Rubeus.exe', 'procdump64.exe', 'PwDump7.exe', 'gsecdump.exe', 'LaZagne.exe', 'mimikatz.exe', 'rundll32.exe')
            Description = 'required credential-access tool coverage'
        },
        @{
            FileName = 'DeviceRegistryEvents.json'
            Needles = @('HKEY_CURRENT_USER\\Software\\USAGCyber\\VPN', 'SavedPassword')
            Description = 'registry credential exposure'
        },
        @{
            FileName = 'DeviceTvmInfoGathering.json'
            Needles = @('DeviceTvmInfoGathering', 'TenantId', 'SourceSystem', 'MachineGroup', 'AvPlatformVersion', 'AvSignatureVersion', 'AvScanResults', 'AsrConfigurationStates', 'EBPFStatus')
            Description = 'Defender Vulnerability Management info gathering telemetry shape'
        },
        @{
            FileName = 'DeviceTvmSoftwareVulnerabilitiesKB.json'
            Needles = @('DeviceTvmSoftwareVulnerabilitiesKB', 'CvssVector', 'CveSupportability', 'EpssScore', 'AffectedSoftware')
            Description = 'Defender Vulnerability Management vulnerability knowledge base shape'
        },
        @{
            FileName = 'SecurityIncident.json'
            Needles = @('SecurityIncident', 'Microsoft XDR', 'ProviderIncidentId', 'RelatedAnalyticRuleIds', 'AdditionalData')
            Description = 'Microsoft Sentinel SecurityIncident telemetry shape'
        },
        @{
            FileName = 'IdentityLogonEvents.json'
            Needles = @('RC4_HMAC', 'MSSQLSvc/sql01.usag-cyber.local:1433', 'RemoteInteractive', 'WinRM')
            Description = 'Kerberoasting and service-account lateral movement'
        },
        @{
            FileName = 'DeviceLogonEvents.json'
            Needles = @('svc_sql', 'AADCONNECT01.usag-cyber.local', 'RemoteInteractive')
            Description = 'service-account logon to Entra Connect'
        },
        @{
            FileName = 'AlertInfo.json'
            Needles = @('MIDNIGHT-BLIZZARD-000', 'Suspicious OAuth service principal persistence', 'T1528,T1098.001,T1550.001')
            Description = 'OAuth service-principal alert'
        },
        @{
            FileName = 'AlertEvidence.json'
            Needles = @('MIDNIGHT-BLIZZARD-000', 'USAG Cyber Sync Helper', 'OAuthApplicationId')
            Description = 'OAuth service-principal alert evidence'
        }
    )

    foreach ($scenarioCheck in $scenarioChecks) {
        Test-GeneratedFileContainsText -DataDirectory $DataDirectory -FileName $scenarioCheck['FileName'] -Needles $scenarioCheck['Needles'] -Description $scenarioCheck['Description']
    }
}

if ($errors.Count -gt 0) {
    $errors | ForEach-Object { Write-Error $_ }
    throw "Workshop package validation failed with $($errors.Count) error(s)."
}

Write-Host 'Workshop package validation passed.'
