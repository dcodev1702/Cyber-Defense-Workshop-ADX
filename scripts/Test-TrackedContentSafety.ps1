<#
.SYNOPSIS
Scans tracked text files for live tenant identifiers.

.DESCRIPTION
The field-profile gate only ever looked at metadata/field-profiles/*.profile.json.
That left every .ps1, .md, .json and .bicep in the repository unscanned, which is
where the tenant GUID, both subscriptions, the uami-adx-backup object id and the
DIBSecCom workspace id were actually sitting on 2026-07-27. This closes that gap.

Two rules, because they need different treatment:

  1. STRUCTURAL indicators -- /subscriptions/, portal tenant deep links, an
     onmicrosoft domain, a bearer token or JWT. These are unambiguous: no
     legitimate synthetic value looks like this, so any hit fails.

  2. BARE GUIDs -- ambiguous. The repository legitimately contains ~190 of them:
     dashboard tile ids, Microsoft well-known first-party application ids, the
     synthetic tenant and its subscription pool. Failing on all of them would make
     the gate noise, and a noisy gate gets bypassed. So known GUIDs are recorded
     in a baseline and only NEW ones fail. That is the shape that matters: the
     DIBSecCom workspace id would have been new once.

The baseline stores SHA-256 hashes, not the values. A baseline holding literal
identifiers would itself become the leak this script exists to prevent, and the
failure message names the file and line, so review happens at the source.

.PARAMETER Staged
Scan staged blob contents rather than the working tree. Pre-commit mode.

.PARAMETER UpdateBaseline
Rewrite the baseline from what is currently in the tree. Review the diff: every
entry added is a GUID you are declaring safe to publish.

.EXAMPLE
pwsh -NoProfile -File scripts/Test-TrackedContentSafety.ps1

.EXAMPLE
pwsh -NoProfile -File scripts/Test-TrackedContentSafety.ps1 -UpdateBaseline
#>
#Requires -Version 7
[CmdletBinding()]
param(
    [switch]$Staged,
    [switch]$UpdateBaseline,
    [switch]$Quiet,
    [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [string]$BaselinePath = (Join-Path $PSScriptRoot '..' 'metadata' 'identifier-baseline.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'WorkshopSensitiveContent.ps1')

$guidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'

# Only text a human or a template can carry an identifier in. Deliberately not
# extension-agnostic: a binary scan produces false positives and no insight.
$textFilePattern = '\.(ps1|psm1|psd1|md|json|ya?ml|bicep|bicepparam|mjs|cjs|js|ts|kql|txt|env|example|sh|sql|csv|ndjson)$'

# field-profiles has its own dedicated scanner (Test-FieldProfileSafety.ps1) which
# understands vocabularies; running this one over it would duplicate and confuse.
# The safety scripts themselves necessarily contain these patterns as source code --
# a scanner that fails on its own regex definitions is a scanner nobody keeps.
$excludedPathPattern = '^(metadata/field-profiles/|metadata/identifier-baseline\.json$|scripts/WorkshopSensitiveContent\.ps1$|scripts/Test-TrackedContentSafety\.ps1$|scripts/Test-FieldProfileSafety\.ps1$)'

function Get-Sha256Hex {
    param([Parameter(Mandatory)][string]$Value)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value.ToLowerInvariant())
        return -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })
    }
    finally { $sha.Dispose() }
}

Push-Location $Root
try {
    $paths = if ($Staged) {
        @(git diff --cached --name-only --diff-filter=ACM) | Where-Object { $_ }
    }
    else {
        @(git ls-files) | Where-Object { $_ }
    }

    $paths = @($paths |
        Where-Object { ($_ -replace '\\', '/') -match $textFilePattern } |
        Where-Object { ($_ -replace '\\', '/') -notmatch $excludedPathPattern })

    # Structural rules, each deliberately narrow. A bare '/resourceGroups/' was the
    # first draft and it fired 14 times on the generator's own synthetic resource
    # paths -- a rule that cries wolf on synthetic data trains people to ignore it.
    # What makes a path dangerous is the subscription or tenant GUID in it, so the
    # GUID is part of every pattern here.
    $structural = [ordered]@{
        'subscription path'       = '(?i)/subscriptions/[0-9a-f]{8}-[0-9a-f]{4}-'
        'tenant path'             = '(?i)/tenants/[0-9a-f]{8}-[0-9a-f]{4}-'
        'portal tenant deep link' = '(?i)portal\.azure\.com/#@[0-9a-f]{8}-[0-9a-f]{4}-'
        'credential'              = '(?i)(bearer\s+[a-z0-9._-]{16,}|eyJ[a-zA-Z0-9._-]{20,})'
        'log analytics endpoint'  = '(?i)[0-9a-f]{8}-[0-9a-f-]{27}\.(ods|oms)\.opinsights\.azure\.com'
    }

    # Microsoft's documented example domains. contoso.onmicrosoft.com is what the
    # student instructions are supposed to say, so flagging it is a false positive.
    $exampleTenantPattern = '(?i)^(contoso|fabrikam|adventureworks|northwind|example|tailwind|tailspin|woodgrove)$'
    $onmicrosoftPattern = '(?i)([a-z0-9-]+)\.onmicrosoft\.com'

    $baseline = @{}
    if (Test-Path -LiteralPath $BaselinePath) {
        $document = Get-Content -LiteralPath $BaselinePath -Raw | ConvertFrom-Json
        foreach ($entry in @($document.allowed)) { $baseline[[string]$entry] = $true }
    }

    $structuralFindings = [System.Collections.Generic.List[object]]::new()
    $newGuidFindings = [System.Collections.Generic.List[object]]::new()
    $seenGuidHashes = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($path in $paths) {
        $content = if ($Staged) {
            try { (git show ":$path") -join "`n" } catch { '' }
        }
        elseif (Test-Path -LiteralPath $path) {
            [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $path))
        }
        else { '' }

        if ([string]::IsNullOrEmpty($content)) { continue }

        $lineNumber = 0
        foreach ($line in ($content -split "`r?`n")) {
            $lineNumber++

            foreach ($label in $structural.Keys) {
                if ($line -match $structural[$label]) {
                    $sample = $Matches[0]
                    if ($sample.Length -gt 60) { $sample = $sample.Substring(0, 60) + '...' }
                    $structuralFindings.Add([pscustomobject]@{
                        File = $path; Line = $lineNumber; Indicator = $label; Sample = $sample
                    })
                }
            }

            # An onmicrosoft domain is only a finding when it names a real tenant.
            foreach ($match in [regex]::Matches($line, $onmicrosoftPattern)) {
                if ($match.Groups[1].Value -notmatch $exampleTenantPattern) {
                    $structuralFindings.Add([pscustomobject]@{
                        File = $path; Line = $lineNumber; Indicator = 'onmicrosoft domain'; Sample = $match.Value
                    })
                }
            }

            foreach ($match in [regex]::Matches($line, $guidPattern)) {
                $hash = Get-Sha256Hex -Value $match.Value
                [void]$seenGuidHashes.Add($hash)
                if (-not $baseline.ContainsKey($hash)) {
                    $newGuidFindings.Add([pscustomobject]@{
                        File = $path; Line = $lineNumber; Indicator = 'unbaselined GUID'; Sample = $match.Value
                    })
                }
            }
        }
    }

    if ($UpdateBaseline) {
        $ordered = @($seenGuidHashes | Sort-Object)
        [ordered]@{
            comment = @(
                'SHA-256 of every GUID currently considered safe to publish from tracked text files.',
                'Hashes, not values: a baseline holding literal identifiers would be the leak it prevents.',
                'Regenerate with scripts/Test-TrackedContentSafety.ps1 -UpdateBaseline and review the diff --',
                'each added entry is a GUID you are declaring safe for a public repository.'
            )
            generated = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            count     = $ordered.Count
            allowed   = $ordered
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $BaselinePath -Encoding utf8

        Write-Host ("Baseline written: {0} GUID hash(es) from {1} tracked text file(s)." -f $ordered.Count, $paths.Count) -ForegroundColor Green
        exit 0
    }

    if (-not $Quiet) {
        Write-Host ("Tracked text files scanned  : {0}" -f $paths.Count)
        Write-Host ("Baselined GUID hashes       : {0}" -f $baseline.Count)
        Write-Host ''
    }

    $failed = $false

    if ($structuralFindings.Count -gt 0) {
        $failed = $true
        Write-Host ("TENANT DATA IN {0} LOCATION(S) -- structural indicator." -f $structuralFindings.Count) -ForegroundColor Red
        $structuralFindings | Select-Object -First 40 | Format-Table -AutoSize | Out-String -Width 190 | Write-Host
        Write-Host 'Move these to workshop.settings.json (gitignored) via scripts/WorkshopSettings.ps1.' -ForegroundColor Yellow
    }

    if ($newGuidFindings.Count -gt 0) {
        $failed = $true
        Write-Host ("{0} UNBASELINED GUID(S)." -f $newGuidFindings.Count) -ForegroundColor Red
        $newGuidFindings | Select-Object -First 40 | Format-Table -AutoSize | Out-String -Width 190 | Write-Host
        Write-Host 'If these are synthetic, run -UpdateBaseline and review the diff. If any is a real' -ForegroundColor Yellow
        Write-Host 'tenant, subscription, workspace or object id, remove it instead of baselining it.' -ForegroundColor Yellow
    }

    if ($failed) { exit 1 }

    Write-Host ("CLEAN: {0} tracked text file(s), no unbaselined identifiers." -f $paths.Count) -ForegroundColor Green
    exit 0
}
finally {
    Pop-Location
}
