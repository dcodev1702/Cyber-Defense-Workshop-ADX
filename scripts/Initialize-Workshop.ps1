[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ResourceGroupName,
    [Parameter(Mandatory)][string]$ClusterName,
    [string]$ClusterUri,
    [string]$DatabaseName = 'CyberDefenseKqlWorkshop',
    [TimeSpan]$SoftDeletePeriod = ([TimeSpan]::FromDays(30)),
    [TimeSpan]$HotCachePeriod = ([TimeSpan]::FromDays(7)),
    [switch]$SkipDatabaseCreate,
    [switch]$ForceRecreateTables,
    [switch]$SkipGenerateData,
    [switch]$SkipIngest,
    [datetime]$ScenarioStartTime = '2026-04-30T13:00:00Z'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$schemaDirectory = Join-Path $PSScriptRoot '..\schemas'
$dataDirectory = Join-Path $PSScriptRoot '..\data\generated'

if (-not $SkipDatabaseCreate) {
    if (-not (Get-Command Get-AzContext -ErrorAction SilentlyContinue)) {
        throw 'Az.Accounts is required to create the ADX database. Install-Module Az.Accounts, Az.Kusto and run Connect-AzAccount.'
    }
    if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
        Connect-AzAccount | Out-Null
    }
    if (-not (Get-Command New-AzKustoDatabase -ErrorAction SilentlyContinue)) {
        throw 'Az.Kusto is required to create the ADX database. Install-Module Az.Kusto and retry.'
    }

    $existingDatabase = Get-AzKustoDatabase -ResourceGroupName $ResourceGroupName -ClusterName $ClusterName -Name $DatabaseName -ErrorAction SilentlyContinue
    if (-not $existingDatabase) {
        Write-Host "Creating ADX database $DatabaseName on cluster $ClusterName"
        New-AzKustoDatabase -ResourceGroupName $ResourceGroupName -ClusterName $ClusterName -Name $DatabaseName -SoftDeletePeriod $SoftDeletePeriod -HotCachePeriod $HotCachePeriod | Out-Null
    }
    else {
        Write-Host "ADX database $DatabaseName already exists"
    }
}

if ([string]::IsNullOrWhiteSpace($ClusterUri)) {
    if (-not (Get-Command Get-AzKustoCluster -ErrorAction SilentlyContinue)) {
        throw 'ClusterUri was not supplied and Az.Kusto is not available to discover it.'
    }

    $cluster = Get-AzKustoCluster -ResourceGroupName $ResourceGroupName -Name $ClusterName
    $ClusterUri = $cluster.Uri
}

& (Join-Path $PSScriptRoot 'Initialize-AdxTables.ps1') -ClusterUri $ClusterUri -DatabaseName $DatabaseName -SchemaDirectory $schemaDirectory -ForceRecreate:$ForceRecreateTables

if (-not $SkipGenerateData) {
    & (Join-Path $PSScriptRoot 'New-SyntheticTelemetry.ps1') -SchemaDirectory $schemaDirectory -OutputDirectory $dataDirectory -StartTime $ScenarioStartTime
}

if (-not $SkipIngest) {
    & (Join-Path $PSScriptRoot 'Import-SyntheticTelemetry.ps1') -ClusterUri $ClusterUri -DatabaseName $DatabaseName -SchemaDirectory $schemaDirectory -DataDirectory $dataDirectory -ClearExistingData:$ForceRecreateTables
}

Write-Host "Workshop setup complete. ADX Web UI: https://dataexplorer.azure.com/clusters/$($ClusterUri.TrimEnd('/').Split('/')[2])/databases/$DatabaseName"
