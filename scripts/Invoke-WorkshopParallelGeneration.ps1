<#
.SYNOPSIS
Generates the workshop telemetry set across several worker processes.

.DESCRIPTION
New-SyntheticTelemetry.ps1 is single-threaded and takes about 46 minutes for the
full 79-table set. The tables are independent of one another, so the work splits
cleanly across processes; this runner partitions them and reconciles the result.

Measured on an 8-physical-core machine: 8 workers is the sweet spot at roughly
13 minutes. More workers do not help. Scaling was 4.7x at 8 workers and only
5.2x at 16, because every worker re-pays the ~2 minute setup phase (identities,
devices, scenario acts) while SMT adds little to CPU-bound PowerShell. At 16
workers the duplicated setup outweighs the extra throughput and the full run is
slower than at 8. Memory is never the constraint: a worker peaks at about 520 MB.

Correctness rests on two properties of the generator, both verified by
Test-WorkshopGenerationDeterminism.ps1:

  * a table's output does not depend on which other tables ran first, and
  * the same inputs produce the same bytes in any process.

Neither held until the reseed ordering and the hashtable enumeration order were
fixed; without them a parallel run would produce a different dataset every time.

.EXAMPLE
.\scripts\Invoke-WorkshopParallelGeneration.ps1

.EXAMPLE
.\scripts\Invoke-WorkshopParallelGeneration.ps1 -WorkerCount 4

.NOTES
Name: Invoke-WorkshopParallelGeneration.ps1
Date: 2026-07-26
Authors: dcodev1702 and GitHub Copilot
Dependencies: PowerShell 7, scripts/New-SyntheticTelemetry.ps1, metadata/tables.manifest.json.
Key commands: Start-Process, Get-FileHash, ConvertFrom-Json.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 64)]
    [int]$WorkerCount = 8,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..' 'data' 'generated'),
    [string]$SummaryPath,
    [datetime]$TelemetryEndTime = (Get-Date).ToUniversalTime(),
    [int]$RandomSeed = 1702,
    [int]$NormalRowsPerTable = -1,
    [int]$NormalMinRowsPerTable = 5000,
    [int]$NormalMaxRowsPerTable = 10000,
    [hashtable]$TableRowOverride = @{ DeviceProcessEvents = 32000 },
    [int]$SyntheticUserCount = 6000,
    [int]$SyntheticServiceAccountCount = 4000,
    [int]$SyntheticDeviceCount = 3000,
    [int]$AadUserRiskEventCount = 5500,
    [string[]]$TableName,
    [string]$ManifestPath = (Join-Path $PSScriptRoot '..' 'metadata' 'tables.manifest.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'WorkshopProgress.ps1')

$generator = Join-Path $PSScriptRoot 'New-SyntheticTelemetry.ps1'
if (-not (Test-Path -LiteralPath $generator)) {
    throw "Generator not found at $generator."
}

if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path

if ([string]::IsNullOrWhiteSpace($SummaryPath)) {
    $SummaryPath = Join-Path (Split-Path -Path $OutputDirectory -Parent) 'scenario-summary.json'
}

# ---- which tables ------------------------------------------------------------

$tables = if ($TableName -and $TableName.Count -gt 0) {
    @($TableName)
}
else {
    @((Get-Content -Raw -LiteralPath $ManifestPath | ConvertFrom-Json) | ForEach-Object { [string]$_.name })
}
$tables = @($tables | Sort-Object -Unique)
if ($tables.Count -eq 0) { throw 'No tables to generate.' }

$WorkerCount = [Math]::Min($WorkerCount, $tables.Count)

# ---- partition ---------------------------------------------------------------

# Longest-processing-time-first. Row counts are the only cost signal available
# before a run, and they are a good one: generation time is very close to linear
# in rows (measured 4.471 ms/row). Without this, the worker that happens to draw
# DeviceProcessEvents (32,000 rows, five times any other table) sets the wall
# time on its own.
#
# Note this map is used for WEIGHTING only. It is forwarded to the workers just
# when the caller bound it, so an unbound run leaves the generator's own default
# in force in every worker -- one source of truth for the 32,000, and no way for
# a copy here to drift away from it. The generator asserts the count it wrote.
$midpoint = [int](($NormalMinRowsPerTable + $NormalMaxRowsPerTable) / 2)
$weights = @{}
foreach ($table in $tables) {
    $weights[$table] = if ($TableRowOverride -and $TableRowOverride.ContainsKey($table)) {
        [int]$TableRowOverride[$table]
    }
    else { $midpoint }
}

$buckets = @(
    for ($i = 0; $i -lt $WorkerCount; $i++) {
        [pscustomobject]@{ Index = $i; Load = [long]0; Tables = [System.Collections.Generic.List[string]]::new() }
    }
)

# Sorted by weight descending, then by name, so the assignment is deterministic
# and a rerun puts the same tables on the same worker.
foreach ($table in ($tables | Sort-Object @{ Expression = { $weights[$_] }; Descending = $true }, @{ Expression = { $_ }; Descending = $false })) {
    $target = @($buckets | Sort-Object Load, Index)[0]
    $target.Tables.Add($table)
    $target.Load += $weights[$table]
}

$buckets = @($buckets | Where-Object { $_.Tables.Count -gt 0 })

# ---- child arguments ---------------------------------------------------------

# Only parameters the caller actually bound are forwarded, with one deliberate
# exception below. -NormalRowsPerTable is the reason: the generator treats *being
# passed at all* as "this overrides the per-table row targets", so forwarding the
# default -1 would silently drop DeviceProcessEvents from 32,000 rows to a random
# 5,000-10,000 and quietly shrink the dataset.
$forwarded = [System.Collections.Generic.List[string]]::new()
foreach ($name in @('NormalRowsPerTable', 'NormalMinRowsPerTable', 'NormalMaxRowsPerTable',
                    'SyntheticUserCount', 'SyntheticServiceAccountCount', 'SyntheticDeviceCount',
                    'AadUserRiskEventCount')) {
    if ($PSBoundParameters.ContainsKey($name)) {
        $forwarded.Add(('-{0} {1}' -f $name, [int]$PSBoundParameters[$name]))
    }
}
if ($PSBoundParameters.ContainsKey('TableRowOverride')) {
    $pairs = @($TableRowOverride.GetEnumerator() | Sort-Object Key | ForEach-Object { "'{0}'={1}" -f $_.Key, [int]$_.Value })
    $forwarded.Add('-TableRowOverride @{' + ($pairs -join '; ') + '}')
}

# The end time is pinned once and passed to every worker. Its default is "now",
# evaluated per process, so leaving it unset would give each worker its own
# timeline and scatter the tables across a several-minute spread.
$endTime = $TelemetryEndTime.ToUniversalTime().ToString('o')
$common = "-TelemetryEndTime '$endTime' -RandomSeed $RandomSeed " + ($forwarded -join ' ')

$workDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ('cdw-parallel-' + [guid]::NewGuid().ToString('n').Substring(0, 8))
New-Item -ItemType Directory -Path $workDirectory -Force | Out-Null

Write-Host ''
Write-Host ("Generating {0} table(s) across {1} worker(s)." -f $tables.Count, $buckets.Count) -ForegroundColor Cyan
Write-Host ("Output    : {0}" -f $OutputDirectory)
Write-Host ("End time  : {0}" -f $endTime)
Write-Host ''

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$workers = @()

foreach ($bucket in $buckets) {
    # Each worker writes its own summary. They all compute the same one, but eight
    # processes writing a single path concurrently is a truncated file waiting to
    # happen; one is copied to the canonical location once every worker succeeds.
    $workerSummary = Join-Path $workDirectory ('summary-{0}.json' -f $bucket.Index)
    $workerLog = Join-Path $workDirectory ('worker-{0}.log' -f $bucket.Index)
    $tableList = ($bucket.Tables | ForEach-Object { "'" + $_ + "'" }) -join ','

    $command = "& '$generator' -OutputDirectory '$OutputDirectory' -SummaryPath '$workerSummary' $common -TableName $tableList"

    $process = Start-Process -FilePath 'pwsh' `
        -ArgumentList '-NoProfile', '-Command', $command `
        -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $workerLog `
        -RedirectStandardError ($workerLog + '.err')

    $workers += [pscustomobject]@{
        Index    = $bucket.Index
        Process  = $process
        Tables   = @($bucket.Tables)
        Load     = $bucket.Load
        Log      = $workerLog
        Summary  = $workerSummary
    }

    Write-Host ("  worker {0}: {1,2} table(s), ~{2,7:n0} rows" -f $bucket.Index, $bucket.Tables.Count, $bucket.Load)
}

function Get-WorkshopCompletedTableCount {
    <#
        Counts finished tables across the running workers.

        The generator logs one "Wrote N row(s) to ..." line per completed table, so
        the redirected worker logs are already a progress feed and no extra plumbing
        between the processes is needed. Counting output files instead would overcount:
        the writer creates the file up front and fills it afterwards, so a table would
        look finished the moment it started.

        FileShare.ReadWrite matters -- the worker still holds the handle, and opening
        with anything stricter throws while the run is live, which is exactly when the
        count is wanted.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Workers)

    $done = 0
    foreach ($worker in $Workers) {
        if (-not (Test-Path -LiteralPath $worker.Log)) { continue }
        try {
            $stream = [System.IO.FileStream]::new($worker.Log, [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            $reader = [System.IO.StreamReader]::new($stream)
            try {
                while ($null -ne ($line = $reader.ReadLine())) {
                    if ($line -like 'Wrote *') { $done++ }
                }
            }
            finally {
                $reader.Dispose()
                $stream.Dispose()
            }
        }
        catch {
            # A transient read failure only costs one refresh of the meter.
        }
    }

    return $done
}

Write-Host ''

$activity = 'Generating workshop telemetry'
$totalTables = $tables.Count
$lastDone = -1

while ($true) {
    $live = @($workers | Where-Object { -not $_.Process.HasExited })
    $done = Get-WorkshopCompletedTableCount -Workers $workers

    # Redrawn on every tick rather than only when a table finishes. Tables take about
    # eleven seconds each here, so refreshing on completion alone leaves the elapsed
    # clock apparently frozen and gives no sign the run is alive. A redirected stream
    # still gets one line per completed table, because 500 ms updates would bury the
    # log.
    if (-not [Console]::IsOutputRedirected -or $done -ne $lastDone) {
        Write-WorkshopProgressBar -Activity $activity -Completed $done -Total $totalTables `
            -Elapsed $stopwatch.Elapsed -Detail ("{0} worker(s) busy" -f $live.Count)
    }
    $lastDone = $done

    if ($live.Count -eq 0) { break }
    $null = $live[0].Process.WaitForExit(500)
}

Complete-WorkshopProgressBar -Activity $activity
$stopwatch.Stop()

# ---- reconcile ---------------------------------------------------------------

$failed = @($workers | Where-Object { $_.Process.ExitCode -ne 0 })
foreach ($worker in $failed) {
    Write-Host ("worker {0} exited {1}" -f $worker.Index, $worker.Process.ExitCode) -ForegroundColor Red
    foreach ($path in @($worker.Log, ($worker.Log + '.err'))) {
        if (Test-Path -LiteralPath $path) {
            $tail = @(Get-Content -LiteralPath $path -Tail 15)
            $tail | ForEach-Object { Write-Host ('    ' + $_) -ForegroundColor DarkGray }
        }
    }
}

$missing = @($tables | Where-Object { -not (Test-Path -LiteralPath (Join-Path $OutputDirectory ($_ + '.json'))) })

Write-Host ''
Write-Host ("Elapsed   : {0:n2} min" -f $stopwatch.Elapsed.TotalMinutes) -ForegroundColor Cyan
Write-Host ("Tables    : {0} of {1} present" -f ($tables.Count - $missing.Count), $tables.Count)

if ($failed.Count -gt 0 -or $missing.Count -gt 0) {
    if ($missing.Count -gt 0) {
        Write-Host ("Missing   : {0}" -f ($missing -join ', ')) -ForegroundColor Red
    }
    Write-Host 'Parallel generation FAILED. The output directory is incomplete; do not import it.' -ForegroundColor Red
    exit 1
}

# Every worker ran the same setup, so any of the summaries is the summary.
Copy-Item -LiteralPath $workers[0].Summary -Destination $SummaryPath -Force
Remove-Item -LiteralPath $workDirectory -Recurse -Force -ErrorAction SilentlyContinue

$rows = 0
foreach ($table in $tables) {
    foreach ($line in [System.IO.File]::ReadLines((Join-Path $OutputDirectory ($table + '.json')))) { $rows++ }
}
Write-Host ("Rows      : {0:n0}" -f $rows)
Write-Host 'Parallel generation complete.' -ForegroundColor Green
