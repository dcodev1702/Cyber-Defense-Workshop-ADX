<#
.SYNOPSIS
Shared progress meter for the workshop's long-running scripts.

.DESCRIPTION
Dot-sourced by the generation runner, the quality gate, and the Kustainer import so
the three report progress the same way rather than growing three slightly different
meters.

Two behaviours matter:

  * At a prompt the line is redrawn in place with a carriage return. In a redirected
    stream that would collapse the whole run into one enormous line, so a redirected
    caller gets one ordinary line per update instead.
  * Write-Progress is driven as well, which is what surfaces in the PowerShell host's
    own progress area and in editors that render it.

.NOTES
Name: WorkshopProgress.ps1
Date: 2026-07-26
Authors: dcodev1702 and GitHub Copilot
Dependencies: PowerShell 7.
Key commands: Write-Progress, Write-Host.
#>

function Write-WorkshopProgressBar {
    param(
        [Parameter(Mandatory)][string]$Activity,
        [Parameter(Mandatory)][int]$Completed,
        [Parameter(Mandatory)][int]$Total,
        [Parameter(Mandatory)][timespan]$Elapsed,
        [string]$Detail = '',
        [ValidateRange(10, 100)]
        [int]$Width = 32
    )

    if ($Total -le 0) { return }

    $fraction = [Math]::Min(1.0, $Completed / [double]$Total)

    # Extrapolated from the rate so far. Deliberately not shown before the first item
    # finishes, when there is no rate to extrapolate from and any figure would be
    # invented.
    $eta = if ($Completed -gt 0 -and $Completed -lt $Total) {
        [TimeSpan]::FromTicks([long](($Elapsed.Ticks / $Completed) * ($Total - $Completed)))
    }
    else { [TimeSpan]::Zero }

    $bar = ('=' * [int][Math]::Round($fraction * $Width)).PadRight($Width, '.')
    $suffix = if ([string]::IsNullOrWhiteSpace($Detail)) { '' } else { "   $Detail" }
    $line = "  [{0}] {1,4}/{2}  {3,4:P0}   elapsed {4:mm\:ss}   eta {5:mm\:ss}{6}" -f `
        $bar, $Completed, $Total, $fraction, $Elapsed, $eta, $suffix

    if ([Console]::IsOutputRedirected) { Write-Host $line }
    else { Write-Host ("`r" + $line + '   ') -NoNewline }

    Write-Progress -Activity $Activity `
        -Status ("{0} of {1}" -f $Completed, $Total) `
        -PercentComplete ([int][Math]::Round($fraction * 100)) `
        -SecondsRemaining ([int]$eta.TotalSeconds)
}

function Complete-WorkshopProgressBar {
    param([Parameter(Mandatory)][string]$Activity)

    # The in-place line has no newline of its own, so one is owed before anything
    # else prints.
    if (-not [Console]::IsOutputRedirected) { Write-Host '' }
    Write-Progress -Activity $Activity -Completed
}
