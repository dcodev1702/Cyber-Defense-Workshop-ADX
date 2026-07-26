<#
.SYNOPSIS
Compares generated workshop telemetry against the real field profiles.

.DESCRIPTION
Reads each generated NDJSON table and measures, per column, how closely the
synthetic data matches the shape of the real telemetry recorded in
metadata\field-profiles.

Three defects are reported:

  Sparse    a column that real telemetry populates but the generated table
            leaves empty or nearly empty. This is the "wall of blank columns"
            failure.
  Overfull  a column that is empty in production but populated here, which
            invents signal that no analyst would ever see.
  Foreign   a value outside the vocabulary observed in production, for
            categorical columns that have one.

Tables with no field profile are skipped and reported separately, since their
schema comes from Microsoft Learn rather than tenant telemetry.

.EXAMPLE
pwsh -NoProfile -File .\scripts\Test-SyntheticDataQuality.ps1

.EXAMPLE
pwsh -NoProfile -File .\scripts\Test-SyntheticDataQuality.ps1 -TableName AgentsInfo -Detailed

.NOTES
Requires PowerShell 7. Exits non-zero when any table falls below -MinimumScore.
#>
#Requires -Version 7
[CmdletBinding()]
param(
    [string[]]$TableName,
    [string]$DataDirectory = (Join-Path $PSScriptRoot '..\data\generated'),
    [string]$ProfileDirectory = (Join-Path $PSScriptRoot '..\metadata\field-profiles'),
    [string]$OverridePath = (Join-Path $PSScriptRoot '..\metadata\profile-overrides.json'),
    [int]$SampleRows = 1500,
    [double]$SparseTolerance = 0.25,
    [double]$MinimumScore = 0.80,
    [switch]$Detailed
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Columns the workshop deliberately populates even though production leaves them
# empty. Shared with the generator so the two cannot disagree about intent.
$overrides = @{}
if (Test-Path $OverridePath) {
    $overrideDocument = Get-Content -Raw $OverridePath | ConvertFrom-Json
    foreach ($entry in $overrideDocument.PSObject.Properties) {
        if ($entry.Name.StartsWith('$')) { continue }
        $overrides[$entry.Name] = @($entry.Value.columns)
    }
}

function Read-NdjsonSample {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][int]$Limit)

    $rows = [System.Collections.Generic.List[object]]::new()
    $reader = [IO.File]::OpenText($Path)
    try {
        while ($rows.Count -lt $Limit) {
            $line = $reader.ReadLine()
            if ($null -eq $line) { break }
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            $rows.Add(($line | ConvertFrom-Json))
        }
    }
    finally { $reader.Dispose() }
    return $rows
}

if (-not (Test-Path $ProfileDirectory)) { throw "No field profiles at $ProfileDirectory" }
if (-not (Test-Path $DataDirectory)) { throw "No generated data at $DataDirectory" }

$profileFiles = Get-ChildItem $ProfileDirectory -Filter '*.profile.json'
if ($TableName) {
    $requested = @($TableName | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $profileFiles = @($profileFiles | Where-Object { $requested -contains ($_.BaseName -replace '\.profile$', '') })
}

$results = [System.Collections.Generic.List[object]]::new()
$skipped = [System.Collections.Generic.List[string]]::new()

foreach ($file in $profileFiles) {
    $doc = Get-Content -Raw $file.FullName | ConvertFrom-Json
    $table = [string]$doc.tableName
    $dataPath = Join-Path $DataDirectory "$table.json"

    if (-not (Test-Path $dataPath)) { $skipped.Add("$table (no generated data)"); continue }

    $rows = Read-NdjsonSample -Path $dataPath -Limit $SampleRows
    if ($rows.Count -eq 0) { $skipped.Add("$table (empty file)"); continue }

    $exempt = @()
    if ($overrides.ContainsKey($table)) { $exempt = $overrides[$table] }

    $sparse = [System.Collections.Generic.List[object]]::new()
    $overfull = [System.Collections.Generic.List[string]]::new()
    $foreign = [System.Collections.Generic.List[object]]::new()
    $checked = 0

    foreach ($property in $doc.columns.PSObject.Properties) {
        $column = $property.Name
        $observed = $property.Value
        if (-not $rows[0].PSObject.Properties[$column]) { continue }
        $checked++

        $values = foreach ($row in $rows) {
            $bag = $row.PSObject.Properties[$column]
            if ($bag) { $bag.Value }
        }
        $filled = @($values | Where-Object { $null -ne $_ -and -not ([string]$_ -match '^\s*$') })
        $actualFill = $filled.Count / $rows.Count

        $isEmptyInProd = [bool]$observed.PSObject.Properties['alwaysEmpty']

        if ($isEmptyInProd) {
            # Deliberately populated columns are expected to be full here.
            if ($exempt -contains $column) { continue }
            if ($actualFill -gt 0.05) { $overfull.Add($column) }
            continue
        }

        $expectedFill = [double]$observed.fillRate
        if ($expectedFill -gt 0.10 -and $actualFill -lt ($expectedFill - $SparseTolerance)) {
            $sparse.Add([pscustomobject]@{
                Column = $column; Expected = $expectedFill; Actual = $actualFill
            })
        }

        $vocabulary = @($observed.topValues | ForEach-Object { [string]$_.value })
        if ($vocabulary.Count -gt 0 -and $filled.Count -gt 0) {
            $outside = @($filled | Where-Object { $vocabulary -notcontains [string]$_ })
            $foreignRate = $outside.Count / $filled.Count
            if ($foreignRate -gt 0.5) {
                $foreign.Add([pscustomobject]@{
                    Column = $column; Rate = $foreignRate
                    Example = [string](@($outside)[0])
                })
            }
        }
    }

    $defects = $sparse.Count + $overfull.Count + $foreign.Count
    $score = if ($checked -gt 0) { [Math]::Round(1.0 - ($defects / $checked), 4) } else { 1.0 }

    $results.Add([pscustomobject]@{
        Table = $table; Rows = $rows.Count; Columns = $checked
        Sparse = $sparse.Count; Overfull = $overfull.Count; Foreign = $foreign.Count
        Score = $score
        SparseDetail = $sparse; OverfullDetail = $overfull; ForeignDetail = $foreign
    })
}

$sorted = @($results | Sort-Object Score)

Write-Host ''
Write-Host ('{0,-44} {1,6} {2,5} {3,6} {4,8} {5,7} {6,7}' -f 'Table', 'Rows', 'Cols', 'Sparse', 'Overfull', 'Foreign', 'Score')
Write-Host ('-' * 92)
foreach ($r in $sorted) {
    $colour = if ($r.Score -lt $MinimumScore) { 'Red' } elseif ($r.Score -lt 0.95) { 'Yellow' } else { 'Green' }
    Write-Host ('{0,-44} {1,6} {2,5} {3,6} {4,8} {5,7} {6,7:P1}' -f `
        $r.Table, $r.Rows, $r.Columns, $r.Sparse, $r.Overfull, $r.Foreign, $r.Score) -ForegroundColor $colour
}

if ($Detailed) {
    foreach ($r in $sorted | Where-Object { $_.Sparse -gt 0 -or $_.Overfull -gt 0 -or $_.Foreign -gt 0 }) {
        Write-Host ''
        Write-Host ("=== {0} ===" -f $r.Table) -ForegroundColor Cyan
        foreach ($s in $r.SparseDetail) {
            Write-Host ('  SPARSE   {0,-34} production {1,6:P0} -> generated {2,6:P0}' -f $s.Column, $s.Expected, $s.Actual)
        }
        foreach ($o in $r.OverfullDetail) {
            Write-Host ('  OVERFULL {0,-34} empty in production but populated here' -f $o)
        }
        foreach ($f in $r.ForeignDetail) {
            $example = $f.Example
            if ($example.Length -gt 40) { $example = $example.Substring(0, 40) + '...' }
            Write-Host ('  FOREIGN  {0,-34} {1,5:P0} outside vocabulary, e.g. {2}' -f $f.Column, $f.Rate, $example)
        }
    }
}

$failing = @($results | Where-Object { $_.Score -lt $MinimumScore })

Write-Host ''
Write-Host ('Tables scored : {0}' -f $results.Count) -ForegroundColor Cyan
if ($results.Count -gt 0) {
    Write-Host ('Mean score    : {0:P1}' -f (($results | Measure-Object Score -Average).Average))
    Write-Host ('Total sparse  : {0}' -f (($results | Measure-Object Sparse -Sum).Sum))
    Write-Host ('Total overfull: {0}' -f (($results | Measure-Object Overfull -Sum).Sum))
    Write-Host ('Total foreign : {0}' -f (($results | Measure-Object Foreign -Sum).Sum))
}
if ($skipped.Count -gt 0) {
    Write-Host ('Skipped       : {0}' -f $skipped.Count) -ForegroundColor Yellow
    if ($Detailed) { $skipped | ForEach-Object { Write-Host "    $_" } }
}

if ($failing.Count -gt 0) {
    Write-Host ''
    Write-Host ("{0} table(s) below the {1:P0} quality bar." -f $failing.Count, $MinimumScore) -ForegroundColor Red
    exit 1
}

Write-Host ''
Write-Host 'All profiled tables meet the quality bar.' -ForegroundColor Green
