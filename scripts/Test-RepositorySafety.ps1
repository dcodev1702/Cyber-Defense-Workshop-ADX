<#
.SYNOPSIS
Single enforcement point that keeps live tenant data and bulk generated telemetry
out of the repository.

.DESCRIPTION
Both the local pre-commit hook (.githooks/pre-commit) and the CI workflow
(.github/workflows/telemetry-safety.yml) call this one script, so the rules stay
in parity by construction rather than by hand -- the drift between the hook and CI
was a finding in the 2026-07-26 evaluation (the hook did not check students/, and
CI did not scan the same paths the hook did).

Two rules are enforced:

  1. No raw tenant telemetry or bulk generated data may enter the repository:
     nothing under sample/, no students/*.csv (rosters carry passwords and TAP
     values), no samples/*.csv, and nothing under data/generated/.

  2. Every field profile in scope is scanned for embedded tenant data by
     Test-FieldProfileSafety.ps1. The profiles are tracked because they make the
     generated telemetry reproducible, so that scan is the last line of defence.

.PARAMETER Staged
Scan the git staged set (git diff --cached) and the staged blob *contents* rather
than the working tree. This is the pre-commit mode: it closes the "git add, then
edit the file" gap where the working tree differs from what is actually committed.

.PARAMETER Root
Repository root. Defaults to the parent of this script's directory.

.EXAMPLE
pwsh -NoProfile -File scripts/Test-RepositorySafety.ps1            # CI: whole tree

.EXAMPLE
pwsh -NoProfile -File scripts/Test-RepositorySafety.ps1 -Staged    # hook: staged only
#>
#Requires -Version 7
[CmdletBinding()]
param(
    [switch]$Staged,
    [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Push-Location $Root
try {
    # Forbidden paths, expressed once. Each entry is a regex matched against the
    # repo-relative, forward-slashed path.
    $forbiddenRules = @(
        @{ Pattern = '^sample/';           Reason = 'raw tenant telemetry (sample/ is gitignored and must never be committed)' }
        @{ Pattern = '^samples/.*\.csv$';  Reason = 'raw tenant telemetry (samples/*.csv)' }
        @{ Pattern = '^students/.*\.csv$'; Reason = 'a student roster that can contain passwords or TAP values (students/*.csv)' }
        @{ Pattern = '^data/generated/';   Reason = 'bulk generated telemetry (~900 MB, reproduced from schemas + profiles)' }
    )

    if ($Staged) {
        $paths = @(git diff --cached --name-only --diff-filter=ACM) | Where-Object { $_ }
        $scanContext = 'staged changes'
    }
    else {
        $paths = @(git ls-files) | Where-Object { $_ }
        $scanContext = 'the tracked tree'
    }

    $violations = [System.Collections.Generic.List[string]]::new()
    foreach ($path in $paths) {
        $normalized = $path -replace '\\', '/'
        foreach ($rule in $forbiddenRules) {
            if ($normalized -match $rule.Pattern) {
                $violations.Add(("{0}  --  {1}" -f $normalized, $rule.Reason))
                break
            }
        }
    }

    if ($violations.Count -gt 0) {
        Write-Host ("BLOCKED: {0} disallowed path(s) found in {1}:" -f $violations.Count, $scanContext) -ForegroundColor Red
        $violations | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        Write-Host ''
        Write-Host 'These paths hold live tenant data or bulk generated output and are gitignored.' -ForegroundColor Yellow
        Write-Host 'Unstage them (git restore --staged <path>) rather than committing them.' -ForegroundColor Yellow
        exit 1
    }

    # ---- rule 2: field-profile safety --------------------------------------
    $profileScanner = Join-Path $PSScriptRoot 'Test-FieldProfileSafety.ps1'
    $stagedProfiles = @($paths | Where-Object { ($_ -replace '\\', '/') -match '^metadata/field-profiles/.*\.profile\.json$' })

    if ($Staged) {
        # Nothing to scan unless a profile is actually being committed.
        if ($stagedProfiles.Count -eq 0) {
            Write-Host 'Repository safety: no field profiles staged; path rules clean.' -ForegroundColor Green
            exit 0
        }

        # Materialize the staged blob contents (not the working-tree files) into a
        # temp directory, then run the exact same scanner against them. This is
        # what closes the "staged content differs from working tree" gap.
        $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("repo-safety-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
        try {
            foreach ($profile in $stagedProfiles) {
                $blob = git show ":$profile"
                $target = Join-Path $tempDir ([System.IO.Path]::GetFileName($profile))
                Set-Content -LiteralPath $target -Value $blob -Encoding UTF8
            }

            & $profileScanner -ProfileDirectory $tempDir -Quiet
            $status = $LASTEXITCODE
        }
        finally {
            Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    else {
        & $profileScanner -ProfileDirectory (Join-Path $Root 'metadata' 'field-profiles')
        $status = $LASTEXITCODE
    }

    if ($status -ne 0) {
        Write-Host 'BLOCKED: field profiles failed the tenant-data scan.' -ForegroundColor Red
        exit 1
    }

    Write-Host 'Repository safety checks passed.' -ForegroundColor Green
    exit 0
}
finally {
    Pop-Location
}
