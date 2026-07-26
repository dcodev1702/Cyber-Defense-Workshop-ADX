<#
.SYNOPSIS
Derives a dashboard variant that points at a different cluster.

.DESCRIPTION
The workshop has two delivery paths and therefore needs two copies of the same
dashboard: one aimed at the local emulator reached through the Cloudflare proxy,
and one aimed at the managed Azure ADX cluster. A dashboard's data source names
the cluster, so a file built for one path renders "Access denied" on every tile
when imported against the other.

Keeping two hand-edited copies is how forty queries drift apart, so the variant
is derived instead. This rewrites only the `clusterUri` and `database` fields of
the data source and copies every other byte through untouched, which makes the
two files provably identical apart from where they point --
Test-WorkshopDashboardParity.ps1 asserts exactly that.

A JSON round trip is deliberately avoided: the student handout is minified on a
single line, and reserialising it would reformat the whole file, hide the real
change in the diff, and risk altering values the portal wrote.

.EXAMPLE
.\scripts\New-WorkshopDashboardVariant.ps1 `
  -InputPath .\STUDENT-GUIDES\dashboard-CYBER-DEFEND-V4.json `
  -OutputPath .\STUDENT-GUIDES\dashboard-CYBER-DEFEND-V4-azure.json `
  -ClusterUri 'https://dibsecadx.eastus2.kusto.windows.net' `
  -DatabaseName 'cyber-defend-q0xxzc'

.NOTES
Exit code 0 on success. Fails if the input has no recognisable data source, so a
silent no-op cannot masquerade as a successful build.
#>
#Requires -Version 7
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$InputPath,
    [Parameter(Mandatory)][string]$OutputPath,
    [Parameter(Mandatory)][string]$ClusterUri,
    [Parameter(Mandatory)][string]$DatabaseName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $InputPath -PathType Leaf)) {
    throw "Dashboard not found: $InputPath"
}

$resolvedInput = (Resolve-Path -LiteralPath $InputPath).Path
$content = [System.IO.File]::ReadAllText($resolvedInput)

# Matches the data source pair in both schema versions, minified or indented.
# Deliberately no named groups: .NET numbers unnamed groups first and named ones
# after, so mixing the two silently shifts the indexes and the rebuilt string
# comes out malformed.
$pattern = '("clusterUri"\s*:\s*")[^"]*("\s*,\s*"database"\s*:\s*")[^"]*(")'
$dataSourceMatches = [regex]::Matches($content, $pattern)

if ($dataSourceMatches.Count -eq 0) {
    throw "No clusterUri/database pair found in $InputPath. Refusing to write a variant that changes nothing."
}

$updated = [regex]::Replace($content, $pattern, {
        param($match)
        $match.Groups[1].Value + $ClusterUri.TrimEnd('/') + $match.Groups[2].Value + $DatabaseName + $match.Groups[3].Value
    })

# The rewrite has to leave the document parseable; a variant that renders
# "Access denied" is at least visible, but one that will not load at all is
# worse than the problem it was built to solve.
try {
    $null = $updated | ConvertFrom-Json
}
catch {
    throw "The rewritten dashboard is not valid JSON, so it was not written: $($_.Exception.Message)"
}

# Preserve the input's encoding decision rather than imposing one: these files
# are consumed by a browser upload, not by a text editor.
$hasBom = $false
$firstBytes = [System.IO.File]::ReadAllBytes($resolvedInput) | Select-Object -First 3
if ($firstBytes.Count -eq 3 -and $firstBytes[0] -eq 0xEF -and $firstBytes[1] -eq 0xBB -and $firstBytes[2] -eq 0xBF) {
    $hasBom = $true
}

$outputDirectory = Split-Path -Parent $OutputPath
if ($outputDirectory -and -not (Test-Path -LiteralPath $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

[System.IO.File]::WriteAllText($OutputPath, $updated, (New-Object System.Text.UTF8Encoding $hasBom))

Write-Host ("Wrote {0}" -f $OutputPath)
Write-Host ("  data sources rewritten : {0}" -f $dataSourceMatches.Count)
Write-Host ("  clusterUri             : {0}" -f $ClusterUri.TrimEnd('/'))
Write-Host ("  database               : {0}" -f $DatabaseName)
