#Requires -Version 7
<#
.SYNOPSIS
Verifies the tenant and subscription identity invariants across generated tables.

.DESCRIPTION
The workshop models a single Microsoft Entra tenant, so every table that carries
a tenant column must carry the same GUID. Azure resources are spread across a
small pool of subscriptions so resource IDs are not all identical, capped so a
student can still reason about the environment.

Checks:
  1. exactly one distinct tenant GUID across all tables
  2. no more than -MaximumSubscriptions distinct subscription GUIDs
  3. no patterned placeholder GUIDs such as 11111111-2222-...

.EXAMPLE
pwsh -NoProfile -File .\scripts\Test-WorkshopIdentityInvariants.ps1
#>
[CmdletBinding()]
param(
    [string]$DataDirectory = (Join-Path $PSScriptRoot '..\data\generated'),
    [int]$MaximumSubscriptions = 25,
    [int]$LinesPerTable = 400
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$dir = $DataDirectory
if (-not (Test-Path $dir)) { throw "No generated data at $dir" }

$guidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'

# The all-zero GUID is a well-known placeholder rather than a real subscription.
# It legitimately appears in management group and Microsoft Graph scoped
# identifiers, so it does not count against the subscription budget.
$wellKnownGuids = @('00000000-0000-0000-0000-000000000000')

$tenants = @{}
$subscriptions = @{}
$placeholders = @{}
$tablesWithTenant = 0
$files = Get-ChildItem $dir -Filter '*.json'

foreach ($file in $files) {
    $sawTenant = $false
    $reader = [IO.File]::OpenText($file.FullName)
    try {
        $lineNumber = 0
        while ($null -ne ($line = $reader.ReadLine())) {
            $lineNumber++
            if ($lineNumber -gt $LinesPerTable) { break }

            foreach ($m in [regex]::Matches($line, '"(?:TenantId|AADTenantId|WorkspaceTenantId)"\s*:\s*"(' + $guidPattern + ')"')) {
                $tenants[$m.Groups[1].Value.ToLowerInvariant()] = $true
                $sawTenant = $true
            }
            foreach ($m in [regex]::Matches($line, '(?i)/subscriptions/(' + $guidPattern + ')')) {
                $subscriptions[$m.Groups[1].Value.ToLowerInvariant()] = $true
            }
            foreach ($m in [regex]::Matches($line, '"(?:SubscriptionId|AzureVmSubscriptionId|WorkspaceSubscriptionId|resource_subscriptionId_g)"\s*:\s*"(' + $guidPattern + ')"')) {
                $subscriptions[$m.Groups[1].Value.ToLowerInvariant()] = $true
            }
            foreach ($m in [regex]::Matches($line, '(1111111|2222222|3333333|12345678)[0-9a-fA-F-]*')) {
                $placeholders[$m.Value] = $true
            }
        }
    }
    finally { $reader.Dispose() }
    if ($sawTenant) { $tablesWithTenant++ }
}

Write-Host ("Tables scanned                 : {0}" -f $files.Count)
Write-Host ("Tables carrying a tenant GUID  : {0}" -f $tablesWithTenant)
Write-Host ''
Write-Host ("Distinct tenant GUIDs          : {0}" -f $tenants.Count) -ForegroundColor $(if ($tenants.Count -eq 1) { 'Green' } else { 'Red' })
$tenants.Keys | ForEach-Object { Write-Host "    $_" }

Write-Host ''
$countedSubscriptions = @($subscriptions.Keys | Where-Object { $wellKnownGuids -notcontains $_ })
$wellKnownSeen = @($subscriptions.Keys | Where-Object { $wellKnownGuids -contains $_ })

Write-Host ("Distinct subscription GUIDs    : {0} (limit {1})" -f $countedSubscriptions.Count, $MaximumSubscriptions) -ForegroundColor $(if ($countedSubscriptions.Count -le $MaximumSubscriptions -and $countedSubscriptions.Count -gt 0) { 'Green' } else { 'Red' })
$countedSubscriptions | Sort-Object | ForEach-Object { Write-Host "    $_" }
if ($wellKnownSeen.Count -gt 0) {
    Write-Host ("Well-known placeholders ignored: {0}" -f ($wellKnownSeen -join ', '))
}

Write-Host ''
if ($placeholders.Count -eq 0) {
    Write-Host 'No patterned placeholder GUIDs remain.' -ForegroundColor Green
} else {
    Write-Host 'Patterned placeholders still present:' -ForegroundColor Red
    $placeholders.Keys | ForEach-Object { Write-Host "    $_" }
}

$ok = ($tenants.Count -eq 1) -and ($countedSubscriptions.Count -le $MaximumSubscriptions) -and ($placeholders.Count -eq 0)
Write-Host ''
if ($ok) { Write-Host 'IDENTITY INVARIANTS HOLD.' -ForegroundColor Green } else { Write-Host 'IDENTITY INVARIANTS VIOLATED.' -ForegroundColor Red; exit 1 }
