<#
.SYNOPSIS
Converts the cloud TTP section of the local training deck to Markdown.

.DESCRIPTION
Runs MarkItDown against the ignored source presentation, retains slides 16-39,
and removes image placeholders whose binary assets are not part of the Markdown
artifact. The reviewed cyber-range mapping remains in docs/ttp-cyber-range.md.

.EXAMPLE
.\scripts\Convert-TtpDeckToMarkdown.ps1
#>
#Requires -Version 7
[CmdletBinding()]
param(
    [string]$InputPath = (Join-Path $PSScriptRoot '..' 'TTPs' 'Threat Hunting Training v3.pptx'),
    [string]$OutputPath = (Join-Path $PSScriptRoot '..' 'docs' 'ttp-slide-extract.md')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $InputPath -PathType Leaf)) {
    throw "TTP source deck not found: $InputPath"
}
if (-not (Get-Command markitdown -ErrorAction SilentlyContinue)) {
    throw "MarkItDown is required. Install it with: python -m pip install --user 'markitdown[pptx]'"
}

$temporaryPath = Join-Path ([System.IO.Path]::GetTempPath()) ('ttp-deck-' + [guid]::NewGuid().ToString('n') + '.md')
try {
    & markitdown $InputPath -o $temporaryPath
    if ($LASTEXITCODE -ne 0) {
        throw "MarkItDown failed with exit code $LASTEXITCODE."
    }

    $markdown = [System.IO.File]::ReadAllText($temporaryPath)
    $startMarker = '<!-- Slide number: 16 -->'
    $endMarker = '<!-- Slide number: 40 -->'
    $startIndex = $markdown.IndexOf($startMarker, [System.StringComparison]::Ordinal)
    $endIndex = $markdown.IndexOf($endMarker, [System.StringComparison]::Ordinal)
    if ($startIndex -lt 0 -or $endIndex -le $startIndex) {
        throw 'Could not locate the expected slide 16-39 boundary in MarkItDown output.'
    }

    $section = $markdown.Substring($startIndex, $endIndex - $startIndex)
    $section = [regex]::Replace($section, '(?m)^!\[\]\([^\r\n]+\)\r?\n?', '')
    $header = @"
# MarkItDown extract: cloud adversary TTPs

Generated from the local source deck by `scripts/Convert-TtpDeckToMarkdown.ps1`.
This artifact contains slides 16-39. See `docs/ttp-cyber-range.md` for the reviewed
catalog, selected integrations, telemetry paths, flags, and validation workflow.

"@
    $outputDirectory = Split-Path -Parent $OutputPath
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
    [System.IO.File]::WriteAllText($OutputPath, $header + $section.Trim() + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
}
finally {
    Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
}

Write-Host "Wrote $OutputPath"
Write-Host 'Slides 16-39 extracted with MarkItDown.'