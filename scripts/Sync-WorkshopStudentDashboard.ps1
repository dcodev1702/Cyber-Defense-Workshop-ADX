<#
.SYNOPSIS
Syncs the student dashboard's query text from the generated dashboard.

.DESCRIPTION
The student handout is schema 76 and the generator emits schema 20, so the
handout has always been maintained by hand. That means every query fix has to be
made twice, and the second time is the one that gets forgotten: after the
has-operator and anchoring fixes landed in the generator, the handout still
carried seventeen stale fragments, so a student importing it would have run the
broken tiles the instructor had already fixed.

The two files hold the same forty tiles in the same order, so the query text can
be copied across by position. That makes the handout a build output for its
queries while leaving its schema-76 container, layout, and visual options alone.

Structure is verified rather than assumed: tile count and every tile title must
match by position before anything is written, and the re-serialised document is
compared field by field against the original with query text masked, so a JSON
round trip cannot quietly alter a value the portal authored.

.EXAMPLE
.\scripts\Sync-WorkshopStudentDashboard.ps1

.EXAMPLE
.\scripts\Sync-WorkshopStudentDashboard.ps1 -WhatIf
Reports what would change without writing.

.NOTES
Run after New-WorkshopDashboard.ps1, then regenerate the Azure variant with
New-WorkshopDashboardVariant.ps1. Test-WorkshopDashboardParity.ps1 proves the
result.
#>
#Requires -Version 7
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$GeneratedJsonPath = (Join-Path $PSScriptRoot '..' 'dashboards' 'cyber-defense-workshop-dashboard.json'),
    [string]$StudentJsonPath = (Join-Path $PSScriptRoot '..' 'STUDENT-GUIDES' 'dashboard-CYBER-DEFEND-V4.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

foreach ($path in @($GeneratedJsonPath, $StudentJsonPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Dashboard not found: $path" }
}

$generated = Get-Content -LiteralPath $GeneratedJsonPath -Raw | ConvertFrom-Json
$studentRaw = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $StudentJsonPath).Path)
$student = $studentRaw | ConvertFrom-Json

$generatedTiles = @($generated.tiles)
$studentTiles = @($student.tiles)

if ($generatedTiles.Count -ne $studentTiles.Count) {
    throw ("Tile counts differ: generated {0}, student {1}." -f $generatedTiles.Count, $studentTiles.Count)
}

# Matched on tile id, not position. The two files hold the same forty tiles but
# in different order -- 'Compromised User - Endpoint Activity' is tile 24 in the
# generated dashboard and tile 39 in the handout -- so a positional sync would
# have written each query onto the wrong tile. The ids correspond exactly, as do
# the page ids, because both come from the same deterministic generator.
$generatedById = @{}
foreach ($tile in $generatedTiles) { $generatedById[[string]$tile.id] = $tile }

$missing = @($studentTiles | Where-Object { -not $generatedById.ContainsKey([string]$_.id) })
if ($missing.Count -gt 0) {
    throw ("{0} student tile(s) have no matching id in the generated dashboard, e.g. '{1}'. Refusing to sync." -f $missing.Count, $missing[0].title)
}

foreach ($tile in $studentTiles) {
    $match = $generatedById[[string]$tile.id]
    if ([string]$match.title -ne [string]$tile.title) {
        throw ("Tile {0} titles differ: '{1}' vs '{2}'. The two dashboards are no longer the same dashboard." -f $tile.id, $match.title, $tile.title)
    }
}

$queriesById = @{}
foreach ($query in @($student.queries)) { $queriesById[[string]$query.id] = $query }

$updated = 0
foreach ($tile in $studentTiles) {
    $sourceQuery = [string]$generatedById[[string]$tile.id].query
    if ([string]::IsNullOrWhiteSpace($sourceQuery)) { continue }

    $reference = $tile.queryRef
    if (-not $reference) { continue }

    $id = $null
    foreach ($candidate in @('queryId', 'id', 'baseQueryId')) {
        if ($reference.PSObject.Properties[$candidate] -and $reference.$candidate) { $id = [string]$reference.$candidate; break }
    }
    if (-not $id -or -not $queriesById.ContainsKey($id)) { continue }

    $target = $queriesById[$id]
    if ([string]$target.text -ne $sourceQuery) {
        Write-Host ("  update  {0}" -f $tile.title)
        $target.text = $sourceQuery
        $updated++
    }
}

if ($updated -eq 0) {
    Write-Host 'The student dashboard queries already match the generated dashboard.'
    exit 0
}

$serialized = $student | ConvertTo-Json -Depth 100 -Compress

# A round trip must not change anything except the query text. Compare the
# re-parsed document against the original with query text masked, because the
# portal authored values here and silently rewriting one would be worse than the
# drift this script exists to remove.
function Get-MaskedShape {
    param([Parameter(Mandatory)]$Document)
    $clone = $Document | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    foreach ($query in @($clone.queries)) { $query.text = 'MASKED' }
    return ($clone | ConvertTo-Json -Depth 100 -Compress)
}

if ((Get-MaskedShape -Document ($serialized | ConvertFrom-Json)) -ne (Get-MaskedShape -Document ($studentRaw | ConvertFrom-Json))) {
    throw 'The re-serialised dashboard differs from the original in more than query text. Nothing was written.'
}

if ($PSCmdlet.ShouldProcess($StudentJsonPath, "Sync $updated query text(s) from the generated dashboard")) {
    [System.IO.File]::WriteAllText($StudentJsonPath, $serialized, (New-Object System.Text.UTF8Encoding $false))
    Write-Host ("Synced {0} query text(s) into {1}" -f $updated, $StudentJsonPath)
    Write-Host 'Regenerate the Azure variant and confirm with Test-WorkshopDashboardParity.ps1.'
}
