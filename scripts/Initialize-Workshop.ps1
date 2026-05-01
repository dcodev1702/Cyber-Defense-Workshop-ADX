[CmdletBinding()]
param(
    [string]$SubscriptionName,
    [string]$SubscriptionId,
    [string]$ResourceGroupName = 'ADX',
    [string]$ClusterName = 'dibsecadx',
    [string]$ClusterUri = 'https://dibsecadx.eastus2.kusto.windows.net',
    [string]$DataIngestionUri = 'https://ingest-dibsecadx.eastus2.kusto.windows.net',
    [string]$DatabaseName = 'CyberDefenseKqlWorkshop',
    [string]$DataDirectory,
    [ValidateSet('New', 'Existing')]
    [string]$TelemetryImport = 'New',
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

Import-Module (Join-Path $PSScriptRoot 'AdxWorkshop.Common.psm1') -Force

if ($SkipDatabaseCreate -and $OverwriteDatabase) {
    throw '-OverwriteDatabase cannot be used with -SkipDatabaseCreate because database creation is skipped.'
}

function Get-WorkshopNdjsonRowCount {
    param([Parameter(Mandatory)][string]$Path)

    $count = 0
    foreach ($line in [System.IO.File]::ReadLines((Resolve-Path -Path $Path).Path)) {
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            $count++
        }
    }

    return $count
}

$schemaDirectory = Join-Path $PSScriptRoot '..\schemas'
$requestedDatabaseName = $DatabaseName
$dataDirectoryWasProvided = -not [string]::IsNullOrWhiteSpace($DataDirectory)
$clusterStateVerified = $false
$effectiveSubscriptionId = $SubscriptionId

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
    $effectiveSubscriptionId = $resolvedSubscriptionId
    $kustoCommonScope = @{
        ResourceGroupName = $ResourceGroupName
    }
    if (-not [string]::IsNullOrWhiteSpace($resolvedSubscriptionId)) {
        $kustoCommonScope['SubscriptionId'] = $resolvedSubscriptionId
    }

    $cluster = Assert-WorkshopAdxClusterRunning -ResourceGroupName $ResourceGroupName -ClusterName $ClusterName -SubscriptionId $resolvedSubscriptionId -ClusterUri $ClusterUri
    $clusterStateVerified = $true
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

if (-not $clusterStateVerified) {
    Assert-WorkshopAdxClusterRunning `
        -ResourceGroupName $ResourceGroupName `
        -ClusterName $ClusterName `
        -SubscriptionName $SubscriptionName `
        -SubscriptionId $effectiveSubscriptionId `
        -ClusterUri $ClusterUri | Out-Null
    $clusterStateVerified = $true
}

if ([string]::IsNullOrWhiteSpace($DataDirectory)) {
    $safeDatabaseName = $DatabaseName -replace '[^A-Za-z0-9_.-]', '_'
    $DataDirectory = Join-Path ([System.IO.Path]::GetTempPath()) "CyberDefenseKqlWorkshop\$safeDatabaseName\generated"
}
elseif (-not [System.IO.Path]::IsPathRooted($DataDirectory)) {
    $DataDirectory = Join-Path (Get-Location).Path $DataDirectory
}
$summaryPath = Join-Path (Split-Path -Path $DataDirectory -Parent) 'scenario-summary.json'

if ($TelemetryImport -eq 'Existing') {
    if (-not $dataDirectoryWasProvided) {
        throw "-TelemetryImport Existing requires -DataDirectory so the script knows which generated telemetry files to import."
    }
    if (-not (Test-Path $DataDirectory)) {
        throw "Generated telemetry directory not found: $DataDirectory"
    }
    if (-not (Get-ChildItem -Path $DataDirectory -Filter '*.json' -File -ErrorAction SilentlyContinue)) {
        throw "Generated telemetry directory does not contain JSON telemetry files: $DataDirectory"
    }

    $missingTelemetryFiles = New-Object System.Collections.Generic.List[string]
    foreach ($schemaFile in (Get-ChildItem -Path $schemaDirectory -Filter '*.schema.json')) {
        $tableName = $schemaFile.Name -replace '\.schema\.json$', ''
        $telemetryFilePath = Join-Path $DataDirectory "$tableName.json"
        if (-not (Test-Path $telemetryFilePath)) {
            $missingTelemetryFiles.Add("$tableName.json") | Out-Null
        }
    }
    if ($missingTelemetryFiles.Count -gt 0) {
        throw "Generated telemetry directory is missing required table files: $($missingTelemetryFiles -join ', ')"
    }

    $identityInfoPath = Join-Path $DataDirectory 'IdentityInfo.json'
    $identityAccountInfoPath = Join-Path $DataDirectory 'IdentityAccountInfo.json'
    $identityInfoRows = Get-WorkshopNdjsonRowCount -Path $identityInfoPath
    $identityAccountInfoRows = Get-WorkshopNdjsonRowCount -Path $identityAccountInfoPath
    if ($identityInfoRows -eq 0 -or $identityAccountInfoRows -eq 0) {
        throw "Existing telemetry cache must include non-empty IdentityInfo.json and IdentityAccountInfo.json files."
    }
    Write-Host "Existing identity cache: IdentityInfo=$identityInfoRows row(s); IdentityAccountInfo=$identityAccountInfoRows row(s)."
}

& (Join-Path $PSScriptRoot 'Initialize-AdxTables.ps1') -ClusterUri $ClusterUri -DatabaseName $DatabaseName -SchemaDirectory $schemaDirectory -ForceRecreate:$ForceRecreateTables

if (($TelemetryImport -eq 'New') -and (-not $SkipGenerateData)) {
    & (Join-Path $PSScriptRoot 'New-SyntheticTelemetry.ps1') `
        -SchemaDirectory $schemaDirectory `
        -OutputDirectory $DataDirectory `
        -SummaryPath $summaryPath `
        -TelemetryEndTime $TelemetryEndTime `
        -NormalRowsPerTable $NormalRowsPerTable `
        -NormalMinRowsPerTable $NormalMinRowsPerTable `
        -NormalMaxRowsPerTable $NormalMaxRowsPerTable `
        -NormalLookbackDays $NormalLookbackDays `
        -RandomSeed $RandomSeed `
        -SyntheticUserCount $SyntheticUserCount `
        -SyntheticServiceAccountCount $SyntheticServiceAccountCount
}
elseif ($TelemetryImport -eq 'Existing') {
    Write-Host "Using existing generated telemetry from $DataDirectory"
}

if (-not $SkipIngest) {
    $importArguments = @{
        ClusterUri = $ClusterUri
        DatabaseName = $DatabaseName
        SchemaDirectory = $schemaDirectory
        DataDirectory = $DataDirectory
        ClearExistingData = [bool]$ForceRecreateTables
        ResourceGroupName = $ResourceGroupName
        ClusterName = $ClusterName
        SubscriptionName = $SubscriptionName
        SubscriptionId = $effectiveSubscriptionId
    }
    & (Join-Path $PSScriptRoot 'Import-SyntheticTelemetry.ps1') @importArguments
}

Write-Host "Workshop setup complete."
Write-Host "Requested database name: $requestedDatabaseName"
Write-Host "Deployed database name:  $DatabaseName"
Write-Host "Cluster URI:             $ClusterUri"
Write-Host "Data ingestion URI:      $DataIngestionUri"
Write-Host "Telemetry import mode:   $TelemetryImport"
Write-Host "Generated data cache:    $DataDirectory"
Write-Host "Scenario summary cache:  $summaryPath"
Write-Host "ADX Web UI:              https://dataexplorer.azure.com/clusters/$($ClusterUri.TrimEnd('/').Split('/')[2])/databases/$DatabaseName"
