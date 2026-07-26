<#
.SYNOPSIS
Blocks real tenant data from reaching the repository through field profiles.

.DESCRIPTION
metadata\field-profiles\ is tracked, because those profiles are what make the
generated telemetry reproducible. That makes this script the last line of defence
between live tenant telemetry and a public repository.

Every captured value vocabulary is scanned for an embedded GUID, an Azure
subscription, resource group or tenant path, an onmicrosoft domain, a user
principal name, an address, a bearer token or JWT, or a long hex string. Any hit
fails the run.

Column-name filtering alone is not sufficient: SourceAgentId carries Azure
resource IDs containing a live subscription GUID, and a scan of the profiles
found 70 such columns before this check existed.

Exits 0 when clean and 1 when anything is found, so it can be used as a gate.

.EXAMPLE
pwsh -NoProfile -File .\scripts\Test-FieldProfileSafety.ps1

.EXAMPLE
pwsh -NoProfile -File .\scripts\Test-FieldProfileSafety.ps1 -Quiet
#>
#Requires -Version 7
[CmdletBinding()]
param(
    [string]$ProfileDirectory = (Join-Path $PSScriptRoot '..' 'metadata' 'field-profiles'),
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ProfileDirectory)) {
    Write-Host ("No field profiles at {0}; nothing to scan." -f $ProfileDirectory)
    exit 0
}

$indicators = [ordered]@{
    'embedded GUID'      = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    'subscription path'  = '(?i)/subscriptions/'
    'resource group'     = '(?i)/resourcegroups/'
    'tenant path'        = '(?i)/tenants/'
    'onmicrosoft domain' = '(?i)\.onmicrosoft\.com'
    'UPN'                = '(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}'
    'credential'         = '(?i)(bearer\s+[a-z0-9._-]{8,}|eyJ[a-zA-Z0-9._-]{10,})'
    'long hex'           = '\b[0-9a-fA-F]{32,}\b'
}

# Version strings are shaped like an address, so the IPv4 test is applied only to
# columns that are not version fields. Mirrors Export-WorkshopTelemetryProfiles.ps1.
$ipIndicator = '\b\d{1,3}(\.\d{1,3}){3}\b'

$findings = [System.Collections.Generic.List[object]]::new()
$vocabCount = 0

foreach ($file in Get-ChildItem $ProfileDirectory -Filter '*.profile.json') {
    $doc = Get-Content -Raw $file.FullName | ConvertFrom-Json
    foreach ($property in $doc.columns.PSObject.Properties) {
        $values = @($property.Value.topValues | ForEach-Object { [string]$_.value })
        if ($values.Count -eq 0) { continue }
        $vocabCount++

        $tests = [ordered]@{}
        foreach ($label in $indicators.Keys) { $tests[$label] = $indicators[$label] }
        if ($property.Name -notmatch '(?i)version') { $tests['IPv4'] = $ipIndicator }

        foreach ($label in $tests.Keys) {
            $hit = @($values | Where-Object { $_ -match $tests[$label] }) | Select-Object -First 1
            if ($hit) {
                $sample = [string]$hit
                if ($sample.Length -gt 48) { $sample = $sample.Substring(0, 48) + '...' }
                $findings.Add([pscustomobject]@{
                    Table = $doc.tableName; Column = $property.Name; Indicator = $label; Sample = $sample
                })
                break
            }
        }
    }
}

$profileCount = @(Get-ChildItem $ProfileDirectory -Filter '*.profile.json').Count

if (-not $Quiet) {
    Write-Host ("Profiles scanned            : {0}" -f $profileCount)
    Write-Host ("Columns with a vocabulary   : {0}" -f $vocabCount)
    Write-Host ''
}

if ($findings.Count -eq 0) {
    Write-Host ("CLEAN: {0} profile(s), {1} vocabularies, no tenant data found." -f $profileCount, $vocabCount) -ForegroundColor Green
    exit 0
}

Write-Host ("TENANT DATA FOUND IN {0} COLUMN(S). Commit blocked." -f $findings.Count) -ForegroundColor Red
$findings | Format-Table -AutoSize | Out-String -Width 160 | Write-Host
Write-Host 'Regenerate the profiles with scripts/Export-WorkshopTelemetryProfiles.ps1, which suppresses these values, then rerun this check.' -ForegroundColor Yellow
exit 1
