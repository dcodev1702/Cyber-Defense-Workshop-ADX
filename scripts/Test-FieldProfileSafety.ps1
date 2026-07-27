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

# Indicators live in one file so this gate, the schema builder and the profile
# exporter cannot drift apart. See WorkshopSensitiveContent.ps1. The IPv4 test is
# opt-in per column there, because version strings are shaped like an address.
. (Join-Path $PSScriptRoot 'WorkshopSensitiveContent.ps1')

$findings = [System.Collections.Generic.List[object]]::new()
$vocabCount = 0

foreach ($file in Get-ChildItem $ProfileDirectory -Filter '*.profile.json') {
    $doc = Get-Content -Raw $file.FullName | ConvertFrom-Json
    foreach ($property in $doc.columns.PSObject.Properties) {
        $values = @($property.Value.topValues | ForEach-Object { [string]$_.value })
        if ($values.Count -eq 0) { continue }
        $vocabCount++

        $tests = [ordered]@{}
        foreach ($label in (Get-WorkshopSensitiveIndicator -IncludeIPv4:($property.Name -notmatch '(?i)version')).GetEnumerator()) {
            $tests[$label.Key] = $label.Value
        }

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
