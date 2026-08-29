<#
.SYNOPSIS
Generates and validates the focused TTP challenge telemetry fixture.

.DESCRIPTION
Runs the required parallel-generation wrapper in a child PowerShell process so
its exit code is explicit, then counts NDJSON records line by line and runs the
TTP matrix/flag validator. The focused fixture has no ambient rows; it exists to
prove the challenge chains before a full workshop regeneration.

.EXAMPLE
.\scripts\Test-WorkshopTtpGeneration.ps1
#>
#Requires -Version 7
[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path ([System.IO.Path]::GetTempPath()) 'cyber-conf-ttp-scenario'),
    [ValidateRange(1, 7)]
    [int]$WorkerCount = 1
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$generatorRunner = Join-Path $PSScriptRoot 'Invoke-WorkshopParallelGeneration.ps1'
$validator = Join-Path $PSScriptRoot 'Test-WorkshopTtpFlags.ps1'
$tables = @(
    'OfficeActivity'
    'CloudAppEvents'
    'AADServicePrincipalSignInLogs'
    'AADNonInteractiveUserSignInLogs'
    'SigninLogs'
    'AuditLogs'
    'GraphAPIAuditEvents'
)

$activeWorkers = @(
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -eq 'pwsh.exe' -and
            $_.ProcessId -ne $PID -and
            $_.CommandLine -match 'New-SyntheticTelemetry\.ps1'
        }
)
if ($activeWorkers.Count -gt 0) {
    throw "Refusing to overlap $($activeWorkers.Count) active telemetry generator worker(s)."
}

$temporaryRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputDirectory)
if (-not $resolvedOutput.StartsWith($temporaryRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
    [System.IO.Path]::GetFileName($resolvedOutput) -notlike 'cyber-conf-ttp-*') {
    throw "OutputDirectory must be a cyber-conf-ttp-* directory beneath $temporaryRoot"
}
$OutputDirectory = $resolvedOutput
$summaryPath = "$OutputDirectory-summary.json"

if (Test-Path -LiteralPath $OutputDirectory) {
    Remove-Item -LiteralPath $OutputDirectory -Recurse -Force
}
if (Test-Path -LiteralPath $summaryPath) {
    Remove-Item -LiteralPath $summaryPath -Force
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$arguments = [System.Collections.Generic.List[string]]::new()
foreach ($argument in @(
        '-NoProfile',
        '-File', $generatorRunner,
        '-WorkerCount', [string]$WorkerCount,
        '-OutputDirectory', $OutputDirectory,
        '-SummaryPath', $summaryPath,
        '-TableName', ($tables -join ',')
    )) {
    $arguments.Add($argument)
}
foreach ($argument in @(
        '-NormalRowsPerTable', '0',
        '-SyntheticUserCount', '3',
        '-SyntheticServiceAccountCount', '2',
        '-SyntheticDeviceCount', '18',
        '-AadUserRiskEventCount', '5000'
    )) {
    $arguments.Add($argument)
}

$previousProgressStyle = $env:WORKSHOP_PROGRESS_STYLE
$env:WORKSHOP_PROGRESS_STYLE = 'Lines'
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
try {
    & pwsh @arguments
    $generationExitCode = $LASTEXITCODE
}
finally {
    $stopwatch.Stop()
    $env:WORKSHOP_PROGRESS_STYLE = $previousProgressStyle
}

Write-Host "GENERATION_EXIT_CODE=$generationExitCode"
Write-Host ('ELAPSED_SECONDS={0}' -f [math]::Round($stopwatch.Elapsed.TotalSeconds, 2))
if ($generationExitCode -ne 0) {
    throw "Focused TTP generation failed with exit code $generationExitCode."
}

$files = @(Get-ChildItem -LiteralPath $OutputDirectory -Filter '*.json' -File | Sort-Object Name)
Write-Host "GENERATED_FILE_COUNT=$($files.Count)"
if ($files.Count -ne $tables.Count) {
    throw "Expected $($tables.Count) generated files, found $($files.Count)."
}

foreach ($file in $files) {
    $rowCount = [System.Linq.Enumerable]::Count([System.IO.File]::ReadLines($file.FullName))
    Write-Host "FILE=$($file.Name);ROWS=$rowCount"
}

$forwardingAddress = 'archive@threat-actor.diaries.cn'
$retiredForwardingAddress = 'archive@{0}' -f 'proton-mail.example'
$officeForwardingRows = 0
$cloudForwardingRows = 0
foreach ($fileName in @('OfficeActivity.json', 'CloudAppEvents.json')) {
    $filePath = Join-Path $OutputDirectory $fileName
    foreach ($line in [System.IO.File]::ReadLines($filePath)) {
        if ($line.Contains($retiredForwardingAddress, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Retired forwarding address found in $fileName."
        }
        if (-not $line.Contains($forwardingAddress, [System.StringComparison]::OrdinalIgnoreCase)) { continue }

        $record = $line | ConvertFrom-Json
        if ($fileName -eq 'OfficeActivity.json' -and
            [string]$record.Operation -eq 'Set-Mailbox' -and
            [string]$record.Parameters -like "*ForwardingSmtpAddress=$forwardingAddress*") {
            $officeForwardingRows++
        }
        elseif ($fileName -eq 'CloudAppEvents.json' -and
            [string]$record.ActionType -eq 'MailboxForwardingConfigured' -and
            [string]$record.RawEventData.ForwardingDestination -eq $forwardingAddress) {
            $cloudForwardingRows++
        }
    }
}
if ($officeForwardingRows -ne 1 -or $cloudForwardingRows -ne 1) {
    throw "Expected one forwarding row in each required table; OfficeActivity=$officeForwardingRows CloudAppEvents=$cloudForwardingRows."
}

$summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
$summaryMatches = @($summary.identityAttackVectors | Where-Object {
        [string]$_.Technique -eq 'T1114.003' -and [string]$_.Command -like "*$forwardingAddress*"
    })
if ($summaryMatches.Count -ne 1) {
    throw "Expected one T1114.003 scenario summary entry for $forwardingAddress; found $($summaryMatches.Count)."
}
Write-Host "FORWARDING_ADDRESS_VALIDATION=OfficeActivity:$officeForwardingRows;CloudAppEvents:$cloudForwardingRows;ScenarioSummary:$($summaryMatches.Count)"

& pwsh -NoProfile -File $validator -DataDirectory $OutputDirectory
$validatorExitCode = $LASTEXITCODE
Write-Host "VALIDATOR_EXIT_CODE=$validatorExitCode"
if ($validatorExitCode -ne 0) {
    throw "TTP flag validator failed with exit code $validatorExitCode."
}

Write-Host 'Focused TTP generation and validation passed.'