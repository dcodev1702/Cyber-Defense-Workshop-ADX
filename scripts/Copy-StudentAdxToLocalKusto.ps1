<#
.SYNOPSIS
Copies the live Student ADX database into a local Kusto emulator.

.DESCRIPTION
Reads table schemas and rows directly from the configured Azure Data Explorer
database, writes one NDJSON export file per source table, creates a persistent
database in the local Kusto emulator, ingests the exported rows, and validates
source and local row counts. The Azure database is the only source of data.

.EXAMPLE
.\scripts\Copy-StudentAdxToLocalKusto.ps1

.EXAMPLE
.\scripts\Copy-StudentAdxToLocalKusto.ps1 -ForceRecreate

.NOTES
Requires Azure CLI authentication that can query the Student ADX database, a
running local Kusto emulator on http://localhost:8080, and the standard Docker
mounts documented in README.md.
#>
[CmdletBinding()]
param(
    [string]$SourceClusterUri = 'https://usag-wiesbaden-cys26.northeurope.kusto.windows.net',
    [string]$SourceDatabaseName = 'cyber-defend-usagwsbdn-cys26',
    [string]$AzureCliSubscriptionName = 'Security',
    [string]$LocalKustoUri = 'http://localhost:8080',
    [string]$LocalDatabaseName = 'CyberDefendStudentSnapshot',
    [string]$LocalDataMountPath = '/workshop-data',
    [string]$LocalStateMountPath = '/kustodata',
    [string]$LocalStateDirectory = (Join-Path $PSScriptRoot '..' 'data' 'local-kusto'),
    [string]$ExportRootDirectory = (Join-Path $PSScriptRoot '..' 'data' 'local-export'),
    [string[]]$TableName,
    [switch]$ForceRecreate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'AdxWorkshop.Common.psm1') -Force

function Get-SourceAdxAccessToken {
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        throw 'Azure CLI is required. Install it, run az login, and retry.'
    }

    $token = & az account get-access-token `
        --subscription $AzureCliSubscriptionName `
        --resource 'https://kusto.kusto.windows.net' `
        --query accessToken `
        --output tsv 2>&1

    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace([string]$token)) {
        throw "Could not acquire an Azure Data Explorer token using Azure CLI subscription '$AzureCliSubscriptionName': $token"
    }

    return ([string]$token).Trim()
}

function Get-KustoProviderError {
    param([Parameter(Mandatory)]$ErrorRecord)

    $message = $ErrorRecord.Exception.Message
    if ($ErrorRecord.Exception.Response) {
        $reader = New-Object System.IO.StreamReader($ErrorRecord.Exception.Response.GetResponseStream())
        try {
            $responseText = $reader.ReadToEnd()
            if (-not [string]::IsNullOrWhiteSpace($responseText)) {
                $message = "$message`n$responseText"
            }
        }
        finally {
            $reader.Dispose()
        }
    }

    return $message
}

function Invoke-SourceAdxRequest {
    param(
        [Parameter(Mandatory)][ValidateSet('mgmt', 'query')][string]$Operation,
        [Parameter(Mandatory)][string]$Command,
        [Parameter(Mandatory)][string]$AccessToken
    )

    $body = @{
        db = $SourceDatabaseName
        csl = $Command
        properties = @{
            Options = @{
                servertimeout = '00:10:00'
            }
        }
    } | ConvertTo-Json -Depth 10 -Compress

    try {
        return Invoke-RestMethod `
            -Method Post `
            -Uri "$($SourceClusterUri.TrimEnd('/'))/v1/rest/$Operation" `
            -Headers @{ Authorization = "Bearer $AccessToken" } `
            -ContentType 'application/json; charset=utf-8' `
            -Body $body `
            -TimeoutSec 900
    }
    catch {
        throw "Source ADX $Operation request failed.`nCommand: $Command`nProvider response: $(Get-KustoProviderError -ErrorRecord $_)"
    }
}

function Invoke-LocalKustoRequest {
    param(
        [Parameter(Mandatory)][ValidateSet('mgmt', 'query')][string]$Operation,
        [Parameter(Mandatory)][string]$Command,
        [string]$DatabaseName
    )

    $body = [ordered]@{ csl = $Command }
    if (-not [string]::IsNullOrWhiteSpace($DatabaseName)) {
        $body.db = $DatabaseName
    }

    try {
        return Invoke-RestMethod `
            -Method Post `
            -Uri "$($LocalKustoUri.TrimEnd('/'))/v1/rest/$Operation" `
            -ContentType 'application/json; charset=utf-8' `
            -Body ($body | ConvertTo-Json -Depth 10 -Compress) `
            -TimeoutSec 900
    }
    catch {
        throw "Local Kusto $Operation request failed. Ensure the emulator is running at $LocalKustoUri.`nCommand: $Command`nProvider response: $(Get-KustoProviderError -ErrorRecord $_)"
    }
}

function Get-KustoResponseRows {
    param([Parameter(Mandatory)]$Response)

    if (-not $Response.Tables -or $Response.Tables.Count -eq 0) {
        return @()
    }

    $result = $Response.Tables[0]
    if (-not $result.Rows) {
        return @()
    }

    $rows = foreach ($row in $result.Rows) {
        $record = [ordered]@{}
        for ($index = 0; $index -lt $result.Columns.Count; $index++) {
            $record[[string]$result.Columns[$index].ColumnName] = $row[$index]
        }
        [pscustomobject]$record
    }

    return @($rows)
}

function Get-KustoPrimaryTable {
    param([Parameter(Mandatory)]$Response)

    if (-not $Response.Tables -or $Response.Tables.Count -eq 0) {
        throw 'The Kusto response did not include a result table.'
    }

    return $Response.Tables[0]
}

function Write-KustoRowsAsNdjson {
    param(
        [Parameter(Mandatory)]$ResultTable,
        [Parameter(Mandatory)][string]$Path
    )

    $directory = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
    $writer = New-Object System.IO.StreamWriter($Path, $false, $utf8WithoutBom)
    $rowCount = 0L

    try {
        foreach ($row in @($ResultTable.Rows)) {
            $record = [ordered]@{}
            for ($index = 0; $index -lt $ResultTable.Columns.Count; $index++) {
                $record[[string]$ResultTable.Columns[$index].ColumnName] = $row[$index]
            }
            $writer.WriteLine(($record | ConvertTo-Json -Depth 100 -Compress))
            $rowCount++
        }
    }
    finally {
        $writer.Dispose()
    }

    return $rowCount
}

function Write-Utf8JsonFile {
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)][string]$Path
    )

    $json = $InputObject | ConvertTo-Json -Depth 100
    $utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json, $utf8WithoutBom)
}

function Get-SourceTableSchema {
    param(
        [Parameter(Mandatory)][string]$TableName,
        [Parameter(Mandatory)][string]$AccessToken
    )

    $tableIdentifier = ConvertTo-WorkshopKustoIdentifier -Name $TableName
    $response = Invoke-SourceAdxRequest -Operation query -Command "$tableIdentifier | getschema" -AccessToken $AccessToken
    $schemaRows = @(Get-KustoResponseRows -Response $response | Sort-Object { [int]$_.ColumnOrdinal })
    if ($schemaRows.Count -eq 0) {
        throw "Source table '$TableName' did not return a schema."
    }

    foreach ($column in $schemaRows) {
        if ([string]::IsNullOrWhiteSpace([string]$column.ColumnName) -or [string]::IsNullOrWhiteSpace([string]$column.ColumnType)) {
            throw "Source table '$TableName' returned an incomplete column definition."
        }
    }

    return $schemaRows
}

function Get-SourceTableRowCount {
    param(
        [Parameter(Mandatory)][string]$TableName,
        [Parameter(Mandatory)][string]$AccessToken
    )

    $tableIdentifier = ConvertTo-WorkshopKustoIdentifier -Name $TableName
    $response = Invoke-SourceAdxRequest -Operation query -Command "$tableIdentifier | count" -AccessToken $AccessToken
    $rows = @(Get-KustoResponseRows -Response $response)
    if ($rows.Count -ne 1) {
        throw "Could not determine the source row count for '$TableName'."
    }

    return [long]$rows[0].Count
}

function Get-LocalTableRowCount {
    param([Parameter(Mandatory)][string]$TableName)

    $tableIdentifier = ConvertTo-WorkshopKustoIdentifier -Name $TableName
    $response = Invoke-LocalKustoRequest -Operation query -DatabaseName $LocalDatabaseName -Command "$tableIdentifier | count"
    $rows = @(Get-KustoResponseRows -Response $response)
    if ($rows.Count -ne 1) {
        throw "Could not determine the local row count for '$TableName'."
    }

    return [long]$rows[0].Count
}

function Test-LocalDatabaseExists {
    $response = Invoke-LocalKustoRequest -Operation mgmt -Command '.show databases | project DatabaseName'
    $databaseNames = @(Get-KustoResponseRows -Response $response | ForEach-Object { [string]$_.DatabaseName })
    return $databaseNames -contains $LocalDatabaseName
}

$accessToken = Get-SourceAdxAccessToken
$sourceTables = @(
    Get-KustoResponseRows -Response (Invoke-SourceAdxRequest -Operation mgmt -Command '.show tables | project TableName' -AccessToken $accessToken) |
        ForEach-Object { [string]$_.TableName } |
        Sort-Object
)
if ($sourceTables.Count -eq 0) {
    throw "The source database '$SourceDatabaseName' does not contain any tables."
}

if ($TableName) {
    $unknownTableNames = @($TableName | Where-Object { $_ -notin $sourceTables })
    if ($unknownTableNames.Count -gt 0) {
        throw "The following table(s) are not present in the source database: $($unknownTableNames -join ', ')."
    }
    $sourceTables = @($sourceTables | Where-Object { $_ -in $TableName })
}

$snapshotName = '{0}-{1}' -f ($SourceDatabaseName -replace '[^A-Za-z0-9_.=-]', '_'), (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$snapshotDirectory = Join-Path $ExportRootDirectory $snapshotName
$containerSnapshotDirectory = "$($LocalDataMountPath.TrimEnd('/'))/local-export/$snapshotName"
New-Item -ItemType Directory -Path $snapshotDirectory -Force | Out-Null

$databaseIdentifier = ConvertTo-WorkshopKustoIdentifier -Name $LocalDatabaseName
$databaseStateDirectory = Join-Path $LocalStateDirectory (Join-Path 'dbs' $LocalDatabaseName)
$databaseExists = Test-LocalDatabaseExists
if (($databaseExists -or (Test-Path $databaseStateDirectory)) -and -not $ForceRecreate) {
    throw "The local database '$LocalDatabaseName' already exists. Re-run with -ForceRecreate to replace it."
}

if ($ForceRecreate) {
    if ($databaseExists) {
        Invoke-LocalKustoRequest -Operation mgmt -Command ".drop database $databaseIdentifier ifexists" | Out-Null
    }
    if (Test-Path $databaseStateDirectory) {
        Remove-Item -Path $databaseStateDirectory -Recurse -Force
    }
}

$containerMetadataPath = '@"' + "$($LocalStateMountPath.TrimEnd('/'))/dbs/$LocalDatabaseName/md" + '"'
$containerDataPath = '@"' + "$($LocalStateMountPath.TrimEnd('/'))/dbs/$LocalDatabaseName/data" + '"'
$createDatabaseCommand = ".create database $databaseIdentifier persist ($containerMetadataPath, $containerDataPath)"
Invoke-LocalKustoRequest -Operation mgmt -Command $createDatabaseCommand | Out-Null

$tableManifests = New-Object System.Collections.Generic.List[object]
foreach ($currentTableName in $sourceTables) {
    Write-Host "Exporting live source table $currentTableName"
    $tableIdentifier = ConvertTo-WorkshopKustoIdentifier -Name $currentTableName
    $schemaRows = @(Get-SourceTableSchema -TableName $currentTableName -AccessToken $accessToken)
    $sourceRowsBefore = Get-SourceTableRowCount -TableName $currentTableName -AccessToken $accessToken
    $sourceDataResponse = Invoke-SourceAdxRequest -Operation query -Command "set notruncation; $tableIdentifier" -AccessToken $accessToken
    $sourceDataTable = Get-KustoPrimaryTable -Response $sourceDataResponse
    $exportFileName = "$currentTableName.ndjson"
    $exportFilePath = Join-Path $snapshotDirectory $exportFileName
    $exportedRows = Write-KustoRowsAsNdjson -ResultTable $sourceDataTable -Path $exportFilePath
    $sourceRowsAfter = Get-SourceTableRowCount -TableName $currentTableName -AccessToken $accessToken

    if ($sourceRowsBefore -ne $exportedRows -or $sourceRowsAfter -ne $exportedRows) {
        throw "Source table '$currentTableName' changed during export or its result was truncated. Source counts: $sourceRowsBefore/$sourceRowsAfter; exported rows: $exportedRows."
    }

    $columnDeclarations = foreach ($column in $schemaRows) {
        "$(ConvertTo-WorkshopKustoIdentifier -Name ([string]$column.ColumnName)):$([string]$column.ColumnType)"
    }
    Invoke-LocalKustoRequest -Operation mgmt -DatabaseName $LocalDatabaseName -Command ".create table $tableIdentifier ($($columnDeclarations -join ', '))" | Out-Null

    $mappingName = "${currentTableName}_LocalJsonMapping"
    $mapping = foreach ($column in $schemaRows) {
        [ordered]@{
            column = [string]$column.ColumnName
            path = '$.' + [string]$column.ColumnName
            datatype = [string]$column.ColumnType
        }
    }
    $mappingJson = $mapping | ConvertTo-Json -Depth 10 -Compress
    $mappingCommand = ".create-or-alter table $tableIdentifier ingestion json mapping $(ConvertTo-WorkshopKustoStringLiteral -Value $mappingName) $(ConvertTo-WorkshopKustoStringLiteral -Value $mappingJson)"
    Invoke-LocalKustoRequest -Operation mgmt -DatabaseName $LocalDatabaseName -Command $mappingCommand | Out-Null

    if ($exportedRows -gt 0) {
        $containerExportFilePath = "$containerSnapshotDirectory/$exportFileName"
        $ingestCommand = ".ingest into table $tableIdentifier (@`"$containerExportFilePath`") with (format='multijson', ingestionMappingReference=$(ConvertTo-WorkshopKustoStringLiteral -Value $mappingName))"
        Invoke-LocalKustoRequest -Operation mgmt -DatabaseName $LocalDatabaseName -Command $ingestCommand | Out-Null
    }

    $localRows = Get-LocalTableRowCount -TableName $currentTableName
    if ($localRows -ne $exportedRows) {
        throw "Local validation failed for '$currentTableName'. Exported rows: $exportedRows; local rows: $localRows."
    }

    $tableManifests.Add([ordered]@{
        tableName = $currentTableName
        sourceRows = $sourceRowsAfter
        localRows = $localRows
        columnCount = $schemaRows.Count
        exportFile = $exportFileName
    }) | Out-Null
    Write-Host "Validated ${currentTableName}: $localRows row(s)"
}

$tableManifestArray = @($tableManifests | ForEach-Object { $_ })
$manifest = [ordered]@{
    manifestVersion = 1
    capturedOn = (Get-Date).ToUniversalTime().ToString('o')
    source = [ordered]@{
        clusterUri = $SourceClusterUri
        databaseName = $SourceDatabaseName
        tableCount = $sourceTables.Count
    }
    local = [ordered]@{
        kustoUri = $LocalKustoUri
        databaseName = $LocalDatabaseName
        persistentStateDirectory = $LocalStateDirectory
    }
    snapshotDirectory = $snapshotDirectory
    tables = $tableManifestArray
}
$manifestPath = Join-Path $snapshotDirectory 'local-kusto-manifest.json'
Write-Utf8JsonFile -InputObject $manifest -Path $manifestPath
$localTotalRows = [long](($tableManifestArray | ForEach-Object { [long]$_['localRows'] } | Measure-Object -Sum).Sum)

[pscustomobject]@{
    SourceClusterUri = $SourceClusterUri
    SourceDatabaseName = $SourceDatabaseName
    SourceTableCount = $sourceTables.Count
    LocalKustoUri = $LocalKustoUri
    LocalDatabaseName = $LocalDatabaseName
    LocalTotalRows = $localTotalRows
    ManifestPath = $manifestPath
} | Format-List