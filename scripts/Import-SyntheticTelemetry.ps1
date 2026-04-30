[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ClusterUri,
    [Parameter(Mandatory)][string]$DatabaseName,
    [string]$DataDirectory = (Join-Path $PSScriptRoot '..\data\generated'),
    [string]$SchemaDirectory = (Join-Path $PSScriptRoot '..\schemas'),
    [string[]]$TableName,
    [int]$BatchSize = 500,
    [switch]$ClearExistingData
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'AdxWorkshop.Common.psm1') -Force

if (-not (Test-Path $DataDirectory)) {
    throw "Data directory not found: $DataDirectory"
}

$files = Get-ChildItem -Path $DataDirectory -Filter '*.json'
if ($TableName) {
    $files = $files | Where-Object { $TableName -contains $_.BaseName }
}

foreach ($file in ($files | Sort-Object Name)) {
    $table = $file.BaseName
    $schemaPath = Join-Path $SchemaDirectory "$table.schema.json"
    if (-not (Test-Path $schemaPath)) {
        Write-Warning "Skipping $($file.Name): no matching schema file."
        continue
    }

    $lines = @(Get-Content -Path $file.FullName | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($lines.Count -eq 0) {
        Write-Host "Skipping $table because $($file.Name) is empty."
        continue
    }

    $schema = Get-Content -Path $schemaPath -Raw | ConvertFrom-Json
    $mappingName = if ($schema.adx.mappingName) { [string]$schema.adx.mappingName } else { "${table}_JsonMapping" }
    $tableIdentifier = ConvertTo-WorkshopKustoIdentifier -Name $table

    if ($ClearExistingData) {
        Write-Host "Clearing existing data from $table"
        Invoke-WorkshopAdxManagementCommand -ClusterUri $ClusterUri -DatabaseName $DatabaseName -Command ".clear table $tableIdentifier data" | Out-Null
    }

    for ($offset = 0; $offset -lt $lines.Count; $offset += $BatchSize) {
        $batch = $lines[$offset..([Math]::Min($offset + $BatchSize - 1, $lines.Count - 1))]
        $payload = [string]::Join([Environment]::NewLine, @($batch))
        $command = ".ingest inline into table $tableIdentifier with (format='multijson', ingestionMappingReference=$(ConvertTo-WorkshopKustoStringLiteral -Value $mappingName)) <|$([Environment]::NewLine)$payload"
        Invoke-WorkshopAdxManagementCommand -ClusterUri $ClusterUri -DatabaseName $DatabaseName -Command $command -ServerTimeoutSeconds 1800 | Out-Null
        Write-Host "Ingested $($batch.Count) rows into $table"
    }
}
