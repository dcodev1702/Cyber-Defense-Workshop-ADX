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
    [ValidateRange(1, 11)]
    [int]$WorkerCount = 1
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$generatorRunner = Join-Path $PSScriptRoot 'Invoke-WorkshopParallelGeneration.ps1'
$validator = Join-Path $PSScriptRoot 'Test-WorkshopTtpFlags.ps1'
$trackedSummaryPath = Join-Path $PSScriptRoot '..' 'data' 'scenario-summary.json'
$expectedRowCount = 113
$tables = @(
    'OfficeActivity'
    'CloudAppEvents'
    'AADServicePrincipalSignInLogs'
    'AADNonInteractiveUserSignInLogs'
    'SigninLogs'
    'AuditLogs'
    'GraphAPIAuditEvents'
    'EntraIdSignInEvents'
    'IdentityQueryEvents'
    'AzureActivity'
    'DeviceProcessEvents'
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
        '-TableName', ($tables -join ','),
        '-DisableTableRowOverrides'
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

$totalRowCount = 0
foreach ($file in $files) {
    $rowCount = [System.Linq.Enumerable]::Count([System.IO.File]::ReadLines($file.FullName))
    $totalRowCount += $rowCount
    Write-Host "FILE=$($file.Name);ROWS=$rowCount"
}
Write-Host "TOTAL_ROWS=$totalRowCount"
if ($totalRowCount -ne $expectedRowCount) {
    throw "Expected $expectedRowCount focused TTP rows, found $totalRowCount."
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
$trackedSummary = Get-Content -LiteralPath $trackedSummaryPath -Raw | ConvertFrom-Json
$matrix = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..' 'metadata' 'ttp-flag-matrix.json') -Raw | ConvertFrom-Json
$inboxTtp = @($matrix.categories.ttps | Where-Object { [string]$_.id -ceq 'malicious-inbox-rules' })
if ($inboxTtp.Count -ne 1) {
    throw "Expected one malicious-inbox-rules matrix entry; found $($inboxTtp.Count)."
}

$officeRows = @([System.IO.File]::ReadLines((Join-Path $OutputDirectory 'OfficeActivity.json')) | ForEach-Object { $_ | ConvertFrom-Json })
$signinRows = @([System.IO.File]::ReadLines((Join-Path $OutputDirectory 'SigninLogs.json')) | ForEach-Object { $_ | ConvertFrom-Json })
$nonInteractiveRows = @([System.IO.File]::ReadLines((Join-Path $OutputDirectory 'AADNonInteractiveUserSignInLogs.json')) | ForEach-Object { $_ | ConvertFrom-Json })
$inboxRuleRows = @($officeRows | Where-Object {
        [string]$_.Operation -ceq 'New-InboxRule' -and
        [string]$_.Parameters -like '*MoveToFolder*' -and
        [string]$_.Parameters -like '*DeleteMessage*'
    })
if ($inboxRuleRows.Count -ne 1) {
    throw "Expected one malicious inbox-rule seed row; found $($inboxRuleRows.Count)."
}

$inboxRule = $inboxRuleRows[0]
$inboxSigninRows = @($signinRows | Where-Object {
        [string]$_.UserPrincipalName -ceq [string]$inboxRule.UserId -and
        [string]$_.IPAddress -ceq [string]$inboxRule.ClientIP -and
        [string]$_.AppDisplayName -ceq 'Office 365 Exchange Online' -and
        -not [string]::IsNullOrWhiteSpace([string]$_.SessionId)
    })
if ($inboxSigninRows.Count -ne 1) {
    throw "Expected one non-empty inbox-rule authentication session; found $($inboxSigninRows.Count)."
}

$inboxSessionId = [string]$inboxSigninRows[0].SessionId
$inboxContinuationRows = @($nonInteractiveRows | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_.SessionId) -and
        [string]$_.SessionId -ceq $inboxSessionId
    })
if ($inboxContinuationRows.Count -ne 1) {
    throw "Expected one inbox-rule continuation for SessionId '$inboxSessionId'; found $($inboxContinuationRows.Count)."
}

$interactiveCorrelationId = [string]$inboxSigninRows[0].CorrelationId
$continuationCorrelationId = [string]$inboxContinuationRows[0].CorrelationId
if ([string]::IsNullOrWhiteSpace($interactiveCorrelationId) -or
    [string]::IsNullOrWhiteSpace($continuationCorrelationId) -or
    $interactiveCorrelationId -ceq $continuationCorrelationId) {
    throw 'Inbox-rule events must share a non-empty SessionId and retain distinct non-empty request CorrelationId values.'
}
if ([string]$inboxContinuationRows[0].AuthenticationDetails -notlike "*$([string]$inboxTtp[0].flag)*") {
    throw 'Inbox-rule continuation does not contain the matrix-declared final evidence flag.'
}
Write-Host 'INBOX_RULE_CORRELATION=SharedNonEmptySessionId:True;DistinctCorrelationIds:True'

$expectedScenarioIds = @($matrix.categories.ttps | Where-Object { [bool]$_.scenario } | ForEach-Object { [string]$_.id } | Sort-Object)
$actualScenarioIds = @($summary.ttpScenario | ForEach-Object { [string]$_.Id } | Sort-Object)
if ($actualScenarioIds.Count -ne 7 -or (Compare-Object -ReferenceObject $expectedScenarioIds -DifferenceObject $actualScenarioIds)) {
    throw "Generated TTP scenario does not match the seven matrix-designated challenges."
}
Write-Host "TTP_SCENARIO_COUNT=$($actualScenarioIds.Count)"

$expectedScenarioJson = ConvertTo-Json -InputObject @($trackedSummary.ttpScenario) -Depth 5 -Compress
$actualScenarioJson = ConvertTo-Json -InputObject @($summary.ttpScenario) -Depth 5 -Compress
if ($actualScenarioJson -cne $expectedScenarioJson) {
    throw 'Generated TTP scenario does not exactly match the tracked scenario narrative.'
}
Write-Host 'TTP_SCENARIO_FULL_MATCH=True'

$summaryMatches = @($summary.identityAttackVectors | Where-Object {
        [string]$_.Technique -eq 'T1114.003' -and [string]$_.Command -like "*$forwardingAddress*"
    })
if ($summaryMatches.Count -ne 1) {
    throw "Expected one T1114.003 scenario summary entry for $forwardingAddress; found $($summaryMatches.Count)."
}
Write-Host "FORWARDING_ADDRESS_VALIDATION=OfficeActivity:$officeForwardingRows;CloudAppEvents:$cloudForwardingRows;ScenarioSummary:$($summaryMatches.Count)"

& pwsh -NoProfile -File $validator -DataDirectory $OutputDirectory -ScenarioSummaryPath $summaryPath
$validatorExitCode = $LASTEXITCODE
Write-Host "VALIDATOR_EXIT_CODE=$validatorExitCode"
if ($validatorExitCode -ne 0) {
    throw "TTP flag validator failed with exit code $validatorExitCode."
}

Write-Host 'Focused TTP generation and validation passed.'