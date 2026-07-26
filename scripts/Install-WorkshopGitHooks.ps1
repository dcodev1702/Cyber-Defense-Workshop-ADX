<#
.SYNOPSIS
Points this clone at the repository's tracked Git hooks.

.DESCRIPTION
Git does not version .git\hooks, so the hooks in .githooks\ are inert until this
runs. It sets core.hooksPath, which makes the tracked pre-commit hook active for
this clone.

The pre-commit hook blocks any commit that stages raw tenant telemetry from
sample\, and runs scripts\Test-FieldProfileSafety.ps1 whenever a field profile is
staged. Field profiles are tracked because they make the generated telemetry
reproducible, so that scan is the last line of defence before tenant data reaches
a public repository.

Local hooks can be bypassed with --no-verify, so the same check also runs in CI
through .github\workflows\telemetry-safety.yml. This installer makes the failure
fast and local; the workflow makes it unavoidable.

.EXAMPLE
pwsh -NoProfile -File .\scripts\Install-WorkshopGitHooks.ps1

.EXAMPLE
pwsh -NoProfile -File .\scripts\Install-WorkshopGitHooks.ps1 -Uninstall
#>
#Requires -Version 7
[CmdletBinding()]
param(
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repositoryRoot
try {
    if (-not (Test-Path -LiteralPath (Join-Path $repositoryRoot '.git'))) {
        throw "Not a Git repository: $repositoryRoot"
    }

    if ($Uninstall) {
        git config --unset core.hooksPath 2>$null | Out-Null
        Write-Host 'Removed core.hooksPath. The repository hooks are no longer active.'
        return
    }

    $hooksPath = '.githooks'
    if (-not (Test-Path -LiteralPath (Join-Path $repositoryRoot $hooksPath))) {
        throw "Hook directory not found: $hooksPath"
    }

    git config core.hooksPath $hooksPath

    # Git for Windows runs hooks through its bundled sh, so the executable bit
    # matters only on Unix, where a fresh clone leaves the file non-executable.
    if (-not $IsWindows) {
        chmod +x (Join-Path $repositoryRoot '.githooks/pre-commit')
    }

    Write-Host ("core.hooksPath set to {0}" -f (git config --get core.hooksPath)) -ForegroundColor Green
    Write-Host ''
    Write-Host 'Active checks on every commit:'
    Write-Host '  - nothing under sample/ may be committed'
    Write-Host '  - staged field profiles must pass scripts/Test-FieldProfileSafety.ps1'
}
finally {
    Pop-Location
}
