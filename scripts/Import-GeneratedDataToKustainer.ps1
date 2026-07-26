<#
.SYNOPSIS
Loads the generated workshop telemetry into the local Kustainer emulator.

.DESCRIPTION
Creates or merges each table from its schema, applies a JSON ingestion mapping,
clears any existing rows, and ingests the generated NDJSON from the read-only
/workshop-data mount. Finishes by reconciling ingested row counts against the
files on disk.

The local emulator is unauthenticated, so this talks to the REST endpoint
directly rather than through Invoke-WorkshopAdxManagementCommand, which always
demands an Azure bearer token.

.EXAMPLE
pwsh -NoProfile -File .\scripts\Import-GeneratedDataToKustainer.ps1
#>
#Requires -Version 7
[CmdletBinding()]
param(
    [string]$ClusterUri = 'http://127.0.0.1:8080',
    [string]$Database = 'CyberDefendStudentSnapshot',
    [string]$ContainerDataPath = '/workshop-data/generated',
    [string]$ManifestPath = (Join-Path $PSScriptRoot '..\metadata\tables.manifest.json'),
    [string]$SchemaDirectory = (Join-Path $PSScriptRoot '..\schemas'),
    [string]$DataDirectory = (Join-Path $PSScriptRoot '..\data\generated'),
    [string[]]$TableName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-KustoRest {
    param(
        [Parameter(Mandatory)][ValidateSet('mgmt', 'query')][string]$Endpoint,
        [Parameter(Mandatory)][string]$Command
    )

    $body = @{ db = $Database; csl = $Command } | ConvertTo-Json -Depth 4 -Compress
    $uri = "$ClusterUri/v1/rest/$Endpoint"
    return Invoke-RestMethod -Method Post -Uri $uri -Body $body -ContentType 'application/json' -ErrorAction Stop
}

function ConvertTo-KustoType {
    param([Parameter(Mandatory)][string]$Type)

    switch ($Type.ToLowerInvariant()) {
        'string'   { 'string' }
        'datetime' { 'datetime' }
        'long'     { 'long' }
        'int'      { 'int' }
        'real'     { 'real' }
        'double'   { 'real' }
        'bool'     { 'bool' }
        'boolean'  { 'bool' }
        'guid'     { 'guid' }
        'dynamic'  { 'dynamic' }
        'timespan' { 'timespan' }
        default    { 'string' }
    }
}

$tables = @((Get-Content -Raw $ManifestPath | ConvertFrom-Json) | ForEach-Object { $_.name })
if ($TableName) {
    $requested = @($TableName | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $tables = @($tables | Where-Object { $requested -contains $_ })
}
if (-not $tables) { throw 'No tables selected.' }

Write-Host ("Cluster  : {0}" -f $ClusterUri)
Write-Host ("Database : {0}" -f $Database)
Write-Host ("Tables   : {0}" -f $tables.Count)
Write-Host ''

$failures = [System.Collections.Generic.List[string]]::new()
$index = 0

foreach ($table in $tables) {
    $index++
    $schemaPath = Join-Path $SchemaDirectory "$table.schema.json"
    $dataPath = Join-Path $DataDirectory "$table.json"

    if (-not (Test-Path $schemaPath)) { $failures.Add("$table (no schema)"); continue }
    if (-not (Test-Path $dataPath)) { $failures.Add("$table (no data)"); continue }

    $schema = Get-Content -Raw $schemaPath | ConvertFrom-Json
    $columns = @($schema.columns)

    $columnSpec = ($columns | ForEach-Object { '{0}:{1}' -f $_.name, (ConvertTo-KustoType -Type $_.type) }) -join ', '
    $mappingName = "${table}_LocalJsonMapping"
    $mappingSpec = ($columns | ForEach-Object {
        '{{"column":"{0}","Properties":{{"Path":"$.{0}"}}}}' -f $_.name
    }) -join ', '

    try {
        Invoke-KustoRest -Endpoint mgmt -Command ".create-merge table ['$table'] ($columnSpec)" | Out-Null
        Invoke-KustoRest -Endpoint mgmt -Command ".create-or-alter table ['$table'] ingestion json mapping '$mappingName' '[$mappingSpec]'" | Out-Null
        Invoke-KustoRest -Endpoint mgmt -Command ".clear table ['$table'] data" | Out-Null
        Invoke-KustoRest -Endpoint mgmt -Command ".ingest into table ['$table'] (@`"$ContainerDataPath/$table.json`") with (format='multijson', ingestionMappingReference='$mappingName')" | Out-Null

        Write-Host ("[{0,2}/{1}] {2,-46} ingested" -f $index, $tables.Count, $table)
    }
    catch {
        Write-Host ("[{0,2}/{1}] {2,-46} FAILED: {3}" -f $index, $tables.Count, $table, $_.Exception.Message) -ForegroundColor Red
        $failures.Add("$table ($($_.Exception.Message))")
    }
}

Write-Host ''
Write-Host 'Reconciling row counts...' -ForegroundColor Cyan

$mismatches = [System.Collections.Generic.List[object]]::new()
$totalIngested = 0

foreach ($table in $tables) {
    $dataPath = Join-Path $DataDirectory "$table.json"
    if (-not (Test-Path $dataPath)) { continue }

    $expected = 0
    $reader = [IO.File]::OpenText($dataPath)
    try { while ($null -ne $reader.ReadLine()) { $expected++ } } finally { $reader.Dispose() }

    try {
        $result = Invoke-KustoRest -Endpoint query -Command "['$table'] | count"
        $actual = [int]@($result.Tables)[0].Rows[0][0]
    }
    catch {
        $actual = -1
    }

    $totalIngested += [Math]::Max($actual, 0)
    if ($actual -ne $expected) {
        $mismatches.Add([pscustomobject]@{ Table = $table; Expected = $expected; Actual = $actual })
    }
}

Write-Host ("Total rows in database : {0:N0}" -f $totalIngested)

if ($failures.Count -gt 0) {
    Write-Host ("Failures: {0}" -f $failures.Count) -ForegroundColor Red
    $failures | ForEach-Object { Write-Host "    $_" }
}

if ($mismatches.Count -gt 0) {
    Write-Host ("Row count mismatches: {0}" -f $mismatches.Count) -ForegroundColor Yellow
    $mismatches | Format-Table -AutoSize
    exit 1
}

Write-Host 'All tables ingested and reconciled.' -ForegroundColor Green
