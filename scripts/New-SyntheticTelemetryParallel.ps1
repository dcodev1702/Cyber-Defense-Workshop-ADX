<#
.SYNOPSIS
Generates the full synthetic telemetry set in parallel across worker processes.

.DESCRIPTION
scripts\New-SyntheticTelemetry.ps1 builds the MIDNIGHT BLIZZARD scenario records once,
then streams ambient rows per table. At workshop volume (dozens of tables at thousands
of rows each) the per-row cost dominates and a single PowerShell process leaves most
of the machine idle.

This driver partitions the table list across worker processes, each invoking the
generator with a disjoint -TableName subset and writing directly into the shared output
directory. Because the generator reseeds its random stream per table from
RandomSeed XOR tableSeed, every table produces identical rows regardless of which
worker handled it or how the tables were partitioned.

Row counts are resolved per table from a profile so reference and knowledge base tables
keep sensible volumes while event tables get the full workshop row count. High volume
endpoint tables can be raised individually through TableRowOverride.

.EXAMPLE
.\scripts\New-SyntheticTelemetryParallel.ps1 -RowsPerTable 8000

.EXAMPLE
.\scripts\New-SyntheticTelemetryParallel.ps1 -RowsPerTable 8000 -ThrottleLimit 12 -OutputDirectory .\data\generated

.EXAMPLE
.\scripts\New-SyntheticTelemetryParallel.ps1 -TableRowOverride @{ DeviceProcessEvents = 32000; DeviceNetworkEvents = 16000 }

.EXAMPLE
.\scripts\New-SyntheticTelemetryParallel.ps1 -TableName DeviceProcessEvents, SecurityEvent -RowsPerTable 8000

.NOTES
Name: New-SyntheticTelemetryParallel.ps1
Date: 2026-07-24
Authors: dcodev1702 and GitHub Copilot
Dependencies: PowerShell 7, scripts\New-SyntheticTelemetry.ps1, local schema JSON files, optional field profiles under sample\<DTG>\_field-profiles.
Key commands: Start-Process, Wait-Process, Get-ChildItem, Measure-Command.
#>
[CmdletBinding()]
param(
    [string]$SchemaDirectory = (Join-Path $PSScriptRoot '..\schemas'),
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\data\generated'),
    [string]$FieldProfileDirectory,
    [ValidateRange(1, 1000000)]
    [int]$RowsPerTable = 8000,
    [hashtable]$TableRowOverride,
    [ValidateRange(1, 64)]
    [int]$ThrottleLimit = [Math]::Max(2, [Environment]::ProcessorCount - 1),
    [int]$RandomSeed = 1702,
    [int]$NormalLookbackDays = 7,
    [string[]]$TableName,
    [switch]$DisableProfileGrounding,
    [switch]$KeepWorkerLogs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "PowerShell 7 or later is required. Detected $($PSVersionTable.PSVersion). Run this script from pwsh."
}

$generatorPath = Join-Path $PSScriptRoot 'New-SyntheticTelemetry.ps1'
if (-not (Test-Path $generatorPath)) {
    throw "Generator not found at $generatorPath"
}
if (-not (Test-Path $SchemaDirectory)) {
    throw "Schema directory not found: $SchemaDirectory"
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$OutputDirectory = (Resolve-Path $OutputDirectory).Path
$SchemaDirectory = (Resolve-Path $SchemaDirectory).Path

# Reference and knowledge base tables describe a catalog, not an event stream. Giving
# them the full event row count produces nonsense such as thousands of distinct CVE
# knowledge base entries. DeviceTvmSoftwareVulnerabilitiesKB is intentionally excluded
# from this reduction and runs at the full row count.
$script:ReferenceTableRowFactor = @{
    DeviceBaselineComplianceProfiles         = 0.05
    DeviceTvmBrowserExtensionsKB             = 0.10
    DeviceTvmInfoGatheringKB                 = 0.05
    DeviceTvmSecureConfigurationAssessmentKB = 0.10
}

# Tables that carry far more volume than the rest in a real estate. Process creation is
# by a wide margin the highest volume endpoint table, so it gets its own target.
$script:DefaultTableRowOverride = @{
    DeviceProcessEvents = 32000
}

function Get-WorkshopTableRowTarget {
    param([Parameter(Mandatory)][string]$Table)

    if ($TableRowOverride -and $TableRowOverride.ContainsKey($Table)) {
        return [int]$TableRowOverride[$Table]
    }
    if ($script:DefaultTableRowOverride.ContainsKey($Table)) {
        return [int]$script:DefaultTableRowOverride[$Table]
    }
    if ($script:ReferenceTableRowFactor.ContainsKey($Table)) {
        return [Math]::Max(50, [int]($RowsPerTable * $script:ReferenceTableRowFactor[$Table]))
    }
    return $RowsPerTable
}

$allTables = @(
    Get-ChildItem -Path $SchemaDirectory -Filter '*.schema.json' |
        ForEach-Object { (Get-Content -Path $_.FullName -Raw | ConvertFrom-Json).tableName } |
        Sort-Object -Unique
)
if ($TableName) {
    $requested = @($TableName | Select-Object -Unique)
    $unknown = @($requested | Where-Object { $allTables -notcontains $_ })
    if ($unknown.Count -gt 0) {
        throw "Unknown table(s): $($unknown -join ', ')"
    }
    $allTables = @($allTables | Where-Object { $requested -contains $_ })
}

if ($allTables.Count -eq 0) {
    throw 'No tables selected.'
}

# Group tables by row target so each worker invocation can pass a single
# -NormalRowsPerTable value, then round robin the groups across workers so no single
# worker gets all the wide tables.
$byTarget = @{}
foreach ($table in $allTables) {
    $target = Get-WorkshopTableRowTarget -Table $table
    if (-not $byTarget.ContainsKey($target)) {
        $byTarget[$target] = [System.Collections.Generic.List[string]]::new()
    }
    $byTarget[$target].Add($table)
}

$batches = [System.Collections.Generic.List[pscustomobject]]::new()
foreach ($target in ($byTarget.Keys | Sort-Object)) {
    $tables = @($byTarget[$target])
    $workerCount = [Math]::Min($ThrottleLimit, $tables.Count)

    # Build the bucket list explicitly. An array subexpression would unroll the empty
    # List objects, because a List is enumerable, and produce an empty array.
    $buckets = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $workerCount; $i++) {
        $buckets.Add([System.Collections.Generic.List[string]]::new())
    }

    for ($i = 0; $i -lt $tables.Count; $i++) {
        $buckets[$i % $workerCount].Add($tables[$i])
    }
    foreach ($bucket in $buckets) {
        if ($bucket.Count -eq 0) { continue }
        $batches.Add([pscustomobject]@{ Rows = $target; Tables = @($bucket) })
    }
}

Write-Host "Tables      : $($allTables.Count)"
Write-Host "Rows/table  : $RowsPerTable (reference tables reduced)"
foreach ($overrideTable in ($allTables | Where-Object { (Get-WorkshopTableRowTarget -Table $_) -ne $RowsPerTable } | Sort-Object)) {
    Write-Host ("  override  : {0,-44} {1}" -f $overrideTable, (Get-WorkshopTableRowTarget -Table $overrideTable))
}
Write-Host "Workers     : $ThrottleLimit"
Write-Host "Batches     : $($batches.Count)"
Write-Host "Output      : $OutputDirectory"
Write-Host ''

$logRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("workshop-gen-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $logRoot -Force | Out-Null

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$running = [System.Collections.Generic.List[pscustomobject]]::new()
$completed = [System.Collections.Generic.List[pscustomobject]]::new()
$queue = [System.Collections.Generic.Queue[pscustomobject]]::new()
foreach ($batch in $batches) { $queue.Enqueue($batch) }

$batchIndex = 0
while ($queue.Count -gt 0 -or $running.Count -gt 0) {
    while ($running.Count -lt $ThrottleLimit -and $queue.Count -gt 0) {
        $batch = $queue.Dequeue()
        $batchIndex++
        $logPath = Join-Path $logRoot "batch-$batchIndex.log"

        # Each worker writes only its own tables into the shared output directory, and
        # the summary is redirected so parallel workers cannot race on one file.
        # Table names are joined with commas because pwsh -File binds a space separated
        # list positionally instead of as an array.
        $arguments = @(
            '-NoProfile'
            '-NonInteractive'
            '-File', $generatorPath
            '-SchemaDirectory', $SchemaDirectory
            '-OutputDirectory', $OutputDirectory
            '-SummaryPath', (Join-Path $logRoot "summary-$batchIndex.json")
            '-NormalRowsPerTable', $batch.Rows
            '-NormalLookbackDays', $NormalLookbackDays
            '-RandomSeed', $RandomSeed
            '-TableName', ($batch.Tables -join ',')
        )

        if ($FieldProfileDirectory) {
            $arguments += @('-FieldProfileDirectory', $FieldProfileDirectory)
        }
        if ($DisableProfileGrounding) {
            $arguments += '-DisableProfileGrounding'
        }

        $process = Start-Process -FilePath (Get-Process -Id $PID).Path `
            -ArgumentList $arguments `
            -NoNewWindow -PassThru `
            -RedirectStandardOutput $logPath `
            -RedirectStandardError "$logPath.err"

        $running.Add([pscustomobject]@{
                Index   = $batchIndex
                Process = $process
                Batch   = $batch
                LogPath = $logPath
            })
        Write-Host ("  [start] batch {0,-3} rows={1,-6} tables={2}" -f $batchIndex, $batch.Rows, ($batch.Tables -join ', '))
    }

    Start-Sleep -Milliseconds 400
    $finished = @($running | Where-Object { $_.Process.HasExited })
    foreach ($item in $finished) {
        $exitCode = $item.Process.ExitCode
        $status = if ($exitCode -eq 0) { 'ok' } else { 'FAILED' }
        Write-Host ("  [ {0} ] batch {1,-3} exit={2}" -f $status, $item.Index, $exitCode)
        if ($exitCode -ne 0) {
            $errPath = "$($item.LogPath).err"
            if (Test-Path $errPath) {
                Get-Content $errPath -Tail 20 | ForEach-Object { Write-Host "        $_" -ForegroundColor Red }
            }
        }
        $completed.Add([pscustomobject]@{ Index = $item.Index; ExitCode = $exitCode; Tables = $item.Batch.Tables })
        [void]$running.Remove($item)
    }
}
$stopwatch.Stop()

$failures = @($completed | Where-Object { $_.ExitCode -ne 0 })

Write-Host ''
$generated = Get-ChildItem -Path $OutputDirectory -Filter '*.json' -File |
    Where-Object { $allTables -contains [System.IO.Path]::GetFileNameWithoutExtension($_.Name) }
$totalRows = 0
foreach ($file in $generated) {
    $lines = 0
    $reader = [System.IO.StreamReader]::new($file.FullName)
    try { while ($null -ne $reader.ReadLine()) { $lines++ } } finally { $reader.Dispose() }
    $totalRows += $lines
}

Write-Host "Elapsed     : $($stopwatch.Elapsed.ToString('hh\:mm\:ss'))"
Write-Host "Files       : $($generated.Count)"
Write-Host "Total rows  : $totalRows"
Write-Host "Total size  : $([math]::Round((($generated | Measure-Object Length -Sum).Sum) / 1MB, 1)) MB"
if ($totalRows -gt 0) {
    Write-Host "Throughput  : $([math]::Round($totalRows / $stopwatch.Elapsed.TotalSeconds, 0)) rows/sec"
}

if ($KeepWorkerLogs) {
    Write-Host "Worker logs : $logRoot"
}
elseif ($failures.Count -eq 0) {
    Remove-Item -Path $logRoot -Recurse -Force -ErrorAction SilentlyContinue
}
else {
    Write-Host "Worker logs : $logRoot" -ForegroundColor Yellow
}

if ($failures.Count -gt 0) {
    throw "$($failures.Count) batch(es) failed: $((($failures | ForEach-Object { $_.Tables -join ',' }) -join ' | '))"
}
