<#
.SYNOPSIS
Go/no-go check before running a class, with the one repairable item repaired.

.DESCRIPTION
Everything here failed at least once during preparation, and in every case some
other signal said the workshop was fine. That is the point of this script: it
checks the things that are quiet when they break.

  1. All four containers are up, and Kustainer is healthy.
  2. Which emulator build is running. Reported, not asserted: the image
     deliberately tracks `latest`, so the build is expected to move. What that
     move costs is a re-import, and check 4 is what catches it -- a persistent
     database written by one build cannot be attached by another.
  3. The read-only gateway is running the policy its source describes, not a
     stale build. `docker compose ps` cannot tell the difference.
  4. The database holds the expected tables and rows. This is the gate that
     catches an emulator version move.
  5. The connector cannot route around the gateway to Kustainer's published
     port. This one lives in the host firewall and does not survive a Docker
     engine restart, so it is reapplied here rather than merely reported.
  6. The student path answers through the gateway.

Only item 5 is repaired, because it is the only one whose repair is safe and
instant. Everything else is reported with the command that fixes it: rebuilding
the gateway or re-importing the database are deliberate acts, not something a
preflight should do behind you.

.EXAMPLE
.\scripts\Test-WorkshopReadiness.ps1

.EXAMPLE
.\scripts\Test-WorkshopReadiness.ps1 -NoRepair
Reports the isolation rule without reapplying it.

.NOTES
Exit code 0 when the workshop is ready to run, 1 otherwise.
#>
#Requires -Version 7
[CmdletBinding()]
param(
    [string]$ClusterUri = 'http://127.0.0.1:8080',
    [string]$Database = 'CyberDefendStudentSnapshot',
    [int]$ExpectedTables = 79,
    # Must equal the NDJSON payload the importer loads, not a remembered figure:
    #   (Get-ChildItem data/generated/*.json | ForEach-Object {
    #       [System.Linq.Enumerable]::Count([System.IO.File]::ReadLines($_.FullName)) }
    #    | Measure-Object -Sum).Sum
    # Update this whenever the generator's output changes, or the preflight fails
    # on correct data and sends you to re-import something already loaded.
    [int]$ExpectedRows = 637370,
    [string]$GatewayContainer = 'cyber-conf-wiesbaden-kusto-readonly-gateway',
    [string]$KustoContainer = 'cyber-conf-wiesbaden-kusto',
    [switch]$NoRepair
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Failures = 0
$script:Remedies = @()

function Report {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Ok,
        [string]$Detail = '',
        [string]$Remedy = ''
    )

    if ($Ok) {
        Write-Host ('  PASS  {0}{1}' -f $Name.PadRight(46), $Detail) -ForegroundColor Green
    }
    else {
        Write-Host ('  FAIL  {0}{1}' -f $Name.PadRight(46), $Detail) -ForegroundColor Red
        $script:Failures++
        if ($Remedy) { $script:Remedies += $Remedy }
    }
}

function Write-Info {
    param([Parameter(Mandatory)][string]$Name, [string]$Detail = '')
    Write-Host ('  INFO  {0}{1}' -f $Name.PadRight(46), $Detail) -ForegroundColor DarkGray
}

function Invoke-Kusto {
    param([Parameter(Mandatory)][string]$Csl, [string]$Endpoint = 'query')

    $body = @{ db = $Database; csl = $Csl } | ConvertTo-Json -Compress
    return @((Invoke-RestMethod -Method Post -Uri "$ClusterUri/v1/rest/$Endpoint" `
                -Body $body -ContentType 'application/json' -TimeoutSec 240).Tables)[0]
}

Write-Host ''
Write-Host 'Workshop readiness' -ForegroundColor Cyan
Write-Host ''

# ---- 1. containers -------------------------------------------------------------

$running = @(docker ps --filter 'name=cyber-conf-wiesbaden' --format '{{.Names}}')
$expected = @(
    'cyber-conf-wiesbaden-kusto',
    'cyber-conf-wiesbaden-kusto-readonly-gateway',
    'cyber-conf-wiesbaden-kusto-defaultdb-cleaner',
    'cyber-conf-wiesbaden-cloudflared'
)
$missing = @($expected | Where-Object { $_ -notin $running })
Report -Name 'all four containers running' -Ok ($missing.Count -eq 0) `
    -Detail $(if ($missing.Count) { "missing: $($missing -join ', ')" } else { '' }) `
    -Remedy 'docker compose start'

$kustoHealth = (docker inspect $KustoContainer --format '{{.State.Health.Status}}' 2>$null)
Report -Name 'kustainer healthy' -Ok ("$kustoHealth".Trim() -eq 'healthy') -Detail "$kustoHealth"

# ---- 2. which emulator build is running ----------------------------------------

# Reported rather than asserted. The image tracks `latest` by choice, so the
# build moves when Microsoft ships. The cost of a move is that the persisted
# database cannot be attached by the new build -- which surfaces as check 4
# failing on row counts, with the import as the documented remedy. Recording the
# build here means that failure is immediately explainable rather than mysterious.
$buildDetail = 'engine not answering'
try {
    $version = Invoke-Kusto -Csl '.show version' -Endpoint 'mgmt'
    $columns = @($version.Columns | ForEach-Object { $_.ColumnName })
    $buildDetail = '{0}  ({1})' -f `
        $version.Rows[0][$columns.IndexOf('BuildVersion')], `
        $version.Rows[0][$columns.IndexOf('ProductVersion')]
}
catch { }

Write-Info -Name 'emulator build' -Detail $buildDetail

# ---- 3. the gateway is running its own source ----------------------------------

# `docker compose ps` reports healthy for a stale policy build, so ask the policy.
function Test-GatewayPolicy {
    param([Parameter(Mandatory)][string]$Csl)

    $script = @"
fetch('http://127.0.0.1:8081/v1/rest/mgmt', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ db: '$Database', csl: '$Csl' })
}).then(r => { console.log(r.status); process.exit(0); })
  .catch(() => { console.log('0'); process.exit(0); });
"@
    $result = docker exec $GatewayContainer node -e $script 2>$null
    return [int]("$result".Trim())
}

$allowed = Test-GatewayPolicy -Csl '.show tables'
$blocked = Test-GatewayPolicy -Csl '.show queries'
Report -Name 'gateway policy is live, not a stale build' -Ok ($allowed -eq 200 -and $blocked -eq 403) `
    -Detail ".show tables=$allowed .show queries=$blocked" `
    -Remedy 'docker compose up -d --build kusto-readonly-gateway'

# ---- 4. the data ---------------------------------------------------------------

$tables = 0
$rows = 0
try {
    $summary = Invoke-Kusto -Csl 'union withsource=T * | summarize Tables = dcount(T), Rows = count()'
    $tables = [int]$summary.Rows[0][0]
    $rows = [long]$summary.Rows[0][1]
}
catch { }

Report -Name 'database holds the workshop data' -Ok ($tables -eq $ExpectedTables -and $rows -eq $ExpectedRows) `
    -Detail ('{0} tables, {1:N0} rows' -f $tables, $rows) `
    -Remedy '.\scripts\Import-GeneratedDataToKustainer.ps1   (also the remedy after an emulator version move)'

# ---- 5. the network boundary (repaired, not just reported) ---------------------

$isolationScript = Join-Path $PSScriptRoot 'Set-WorkshopNetworkIsolation.ps1'
$isolationTest = Join-Path $PSScriptRoot 'Test-WorkshopNetworkIsolation.ps1'

if (-not $NoRepair) {
    # Idempotent, and it clears its own stale rules first. A Docker engine restart
    # silently drops this rule, which is why it is reapplied rather than reported.
    & pwsh -NoProfile -File $isolationScript | Out-Null
}

& pwsh -NoProfile -File $isolationTest | Out-Null
Report -Name 'connector cannot bypass the gateway' -Ok ($LASTEXITCODE -eq 0) `
    -Detail $(if ($NoRepair) { '(not repaired: -NoRepair)' } else { '(reapplied)' }) `
    -Remedy '.\scripts\Set-WorkshopNetworkIsolation.ps1; .\scripts\Test-WorkshopNetworkIsolation.ps1'

# ---- 6. the student path -------------------------------------------------------

$gatewayEdge = (docker inspect $GatewayContainer --format '{{(index .NetworkSettings.Networks "cyber-conf-wiesbaden-edge").IPAddress}}' 2>$null)
$studentOk = $false
if ($gatewayEdge) {
    docker run --rm --network cyber-conf-wiesbaden-edge alpine:3.21 `
        timeout 5 nc -z "$($gatewayEdge.Trim())" 8081 2>&1 | Out-Null
    $studentOk = ($LASTEXITCODE -eq 0)
}
Report -Name 'gateway reachable on the student path' -Ok $studentOk -Detail "$gatewayEdge`:8081"

# ---- verdict -------------------------------------------------------------------

Write-Host ''
if ($script:Failures -gt 0) {
    Write-Host ("NOT READY: {0} check(s) failed." -f $script:Failures) -ForegroundColor Red
    Write-Host ''
    $script:Remedies | Select-Object -Unique | ForEach-Object { Write-Host ('  ' + $_) }
    Write-Host ''
    exit 1
}

Write-Host 'READY. The stack, the data, the gateway policy, and the boundary all check out.' -ForegroundColor Green
Write-Host ''
exit 0
