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
}

if ($errors.Count -gt 0) {
    $errors | ForEach-Object { Write-Error $_ }
    throw "Workshop package validation failed with $($errors.Count) error(s)."
}

Write-Host 'Workshop package validation passed.'
