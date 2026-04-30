[CmdletBinding()]
param(
    [string]$SubscriptionName,
    [string]$SubscriptionId,
    [string]$ResourceGroupName = 'ADX',
    [string]$ClusterName = 'dibsecadx',
    [string]$ClusterUri = 'https://dibsecadx.eastus2.kusto.windows.net',
    [string]$DataIngestionUri = 'https://ingest-dibsecadx.eastus2.kusto.windows.net',
    [string]$DatabaseName = 'CyberDefenseKqlWorkshop',
    [TimeSpan]$SoftDeletePeriod = ([TimeSpan]::FromDays(365)),
    [TimeSpan]$HotCachePeriod = ([TimeSpan]::FromDays(365)),
    [switch]$SkipDatabaseCreate,
    [switch]$OverwriteDatabase,
    [switch]$ForceRecreateTables,
    [switch]$SkipGenerateData,
    [switch]$SkipIngest,
    [int]$NormalRowsPerTable = -1,
    [int]$NormalMinRowsPerTable = 5000,
    [int]$NormalMaxRowsPerTable = 10000,
    [int]$NormalLookbackDays = 7,
    [int]$RandomSeed = 1702,
    [int]$SyntheticUserCount = 6000,
    [int]$SyntheticServiceAccountCount = 4000,
    [Alias('ScenarioStartTime')]
    [datetime]$TelemetryEndTime = (Get-Date).ToUniversalTime()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($SkipDatabaseCreate -and $OverwriteDatabase) {
    throw '-OverwriteDatabase cannot be used with -SkipDatabaseCreate because database creation is skipped.'
}

$schemaDirectory = Join-Path $PSScriptRoot '..\schemas'
$dataDirectory = Join-Path $PSScriptRoot '..\data\generated'
$requestedDatabaseName = $DatabaseName

if (-not $SkipDatabaseCreate) {
    if (-not (Get-Command Get-AzContext -ErrorAction SilentlyContinue)) {
        throw 'Az.Accounts is required to create the ADX database. Install-Module Az.Accounts, Az.Kusto and run Connect-AzAccount.'
    }
    if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
        Connect-AzAccount | Out-Null
    }
    if ($SubscriptionId) {
        Set-AzContext -Subscription $SubscriptionId | Out-Null
    }
    elseif ($SubscriptionName) {
        Set-AzContext -Subscription $SubscriptionName | Out-Null
    }
    if (-not (Get-Command New-AzKustoDatabase -ErrorAction SilentlyContinue)) {
        throw 'Az.Kusto is required to create the ADX database. Install-Module Az.Kusto and retry.'
    }
    foreach ($commandName in @('Get-AzKustoCluster', 'Get-AzKustoDatabase', 'Remove-AzKustoDatabase')) {
        if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
            throw "Az.Kusto command '$commandName' is required. Update Az.Kusto and retry."
        }
    }

    $resolvedSubscriptionId = (Get-AzContext).Subscription.Id
    $kustoCommonScope = @{
        ResourceGroupName = $ResourceGroupName
    }
    if (-not [string]::IsNullOrWhiteSpace($resolvedSubscriptionId)) {
        $kustoCommonScope['SubscriptionId'] = $resolvedSubscriptionId
    }

    $cluster = Get-AzKustoCluster @kustoCommonScope -Name $ClusterName
    if ([string]::IsNullOrWhiteSpace($ClusterUri)) {
        $ClusterUri = $cluster.Uri
    }
    $dataIngestionUriProperty = $cluster.PSObject.Properties['DataIngestionUri']
    if ([string]::IsNullOrWhiteSpace($DataIngestionUri) -and $dataIngestionUriProperty -and $dataIngestionUriProperty.Value) {
        $DataIngestionUri = $dataIngestionUriProperty.Value
    }

    $kustoDatabaseScope = $kustoCommonScope.Clone()
    $kustoDatabaseScope['ClusterName'] = $ClusterName

    $existingDatabase = Get-AzKustoDatabase @kustoDatabaseScope -Name $DatabaseName -ErrorAction SilentlyContinue
    if ($existingDatabase -and $OverwriteDatabase) {
        Write-Host "Removing existing ADX database $DatabaseName because -OverwriteDatabase was supplied"
        Remove-AzKustoDatabase @kustoDatabaseScope -Name $DatabaseName -Confirm:$false | Out-Null

        $deleteDeadline = (Get-Date).AddMinutes(10)
        do {
            Start-Sleep -Seconds 10
            $existingDatabase = Get-AzKustoDatabase @kustoDatabaseScope -Name $DatabaseName -ErrorAction SilentlyContinue
        } while ($existingDatabase -and (Get-Date) -lt $deleteDeadline)

        if ($existingDatabase) {
            throw "Timed out waiting for ADX database '$DatabaseName' to be removed."
        }
    }
    elseif ($existingDatabase) {
        $suffix = Get-Date -Format 'yyyyMMddHHmmss'
        $candidateName = "${DatabaseName}_${suffix}"
        while (Get-AzKustoDatabase @kustoDatabaseScope -Name $candidateName -ErrorAction SilentlyContinue) {
            Start-Sleep -Seconds 1
            $suffix = Get-Date -Format 'yyyyMMddHHmmss'
            $candidateName = "${DatabaseName}_${suffix}"
        }

        Write-Host "ADX database $DatabaseName already exists; creating new database $candidateName because -OverwriteDatabase was not supplied"
        $DatabaseName = $candidateName
    }

    if (-not (Get-AzKustoDatabase @kustoDatabaseScope -Name $DatabaseName -ErrorAction SilentlyContinue)) {
        Write-Host "Creating ADX database $DatabaseName on cluster $ClusterName with retention $SoftDeletePeriod and hot cache $HotCachePeriod"
        New-AzKustoDatabase `
            @kustoDatabaseScope `
            -Name $DatabaseName `
            -Kind ReadWrite `
            -Location $cluster.Location `
            -SoftDeletePeriod $SoftDeletePeriod `
            -HotCachePeriod $HotCachePeriod | Out-Null
    }
    else {
        Write-Host "ADX database $DatabaseName already exists and will be used"
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
    & (Join-Path $PSScriptRoot 'New-SyntheticTelemetry.ps1') `
        -SchemaDirectory $schemaDirectory `
        -OutputDirectory $dataDirectory `
        -TelemetryEndTime $TelemetryEndTime `
        -NormalRowsPerTable $NormalRowsPerTable `
        -NormalMinRowsPerTable $NormalMinRowsPerTable `
        -NormalMaxRowsPerTable $NormalMaxRowsPerTable `
        -NormalLookbackDays $NormalLookbackDays `
        -RandomSeed $RandomSeed `
        -SyntheticUserCount $SyntheticUserCount `
        -SyntheticServiceAccountCount $SyntheticServiceAccountCount
}

if (-not $SkipIngest) {
    & (Join-Path $PSScriptRoot 'Import-SyntheticTelemetry.ps1') -ClusterUri $ClusterUri -DatabaseName $DatabaseName -SchemaDirectory $schemaDirectory -DataDirectory $dataDirectory -ClearExistingData:$ForceRecreateTables
}

Write-Host "Workshop setup complete."
Write-Host "Requested database name: $requestedDatabaseName"
Write-Host "Deployed database name:  $DatabaseName"
Write-Host "Cluster URI:             $ClusterUri"
Write-Host "Data ingestion URI:      $DataIngestionUri"
Write-Host "ADX Web UI:              https://dataexplorer.azure.com/clusters/$($ClusterUri.TrimEnd('/').Split('/')[2])/databases/$DatabaseName"
