<#
.SYNOPSIS
Imports generated workshop telemetry files into Azure Data Explorer.

.DESCRIPTION
Verifies the configured ADX cluster is running (auto-starting it when permitted),
loads schema-aligned NDJSON files from a data directory, optionally clears existing
table data, and ingests each file into its matching ADX table in inline batches.

.EXAMPLE
.\scripts\Import-SyntheticTelemetry.ps1 -ClusterUri 'https://dibsecadx.eastus2.kusto.windows.net' -DatabaseName CyberDefenseKqlWorkshop -DataDirectory "$env:TEMP\CyberDefenseKqlWorkshop\CyberDefenseKqlWorkshop\generated" -ClearExistingData

.EXAMPLE
.\scripts\Import-SyntheticTelemetry.ps1 -ClusterUri 'https://dibsecadx.eastus2.kusto.windows.net' -DatabaseName CyberDefenseKqlWorkshop -TableName DeviceInfo,IdentityInfo

.NOTES
Name: Import-SyntheticTelemetry.ps1
Date: 2026-05-01
Authors: dcodev1702 and GitHub Copilot CLI w/ ChatGPT 5.5 xhigh
Dependencies: scripts\AdxWorkshop.Common.psm1, Az.Accounts/Az.Kusto or Azure CLI for cluster-state checks, ADX database access, generated NDJSON files, schema JSON files.
Key commands: Assert-WorkshopAdxClusterRunning, .clear table data, .ingest inline, Invoke-WorkshopAdxManagementCommand.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ClusterUri,
    [Parameter(Mandatory)][string]$DatabaseName,
    [string]$SubscriptionName,
    [string]$SubscriptionId,
    [string]$ResourceGroupName = 'ADX',
    [string]$ClusterName = 'dibsecadx',
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

Assert-WorkshopAdxClusterRunning `
    -ResourceGroupName $ResourceGroupName `
    -ClusterName $ClusterName `
    -SubscriptionName $SubscriptionName `
    -SubscriptionId $SubscriptionId `
    -ClusterUri $ClusterUri | Out-Null

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
