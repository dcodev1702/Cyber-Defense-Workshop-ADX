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

function Get-WorkshopProgressStyle {
    <#
        'Inline' redraws one line in place, 'Lines' writes one line per update.

        Auto picks Inline at a prompt and Lines when redirected, but the guess is wrong
        in a captured console: redraw looks live to a person watching and collapses to
        a single final line in a transcript, so a run whose output is being recorded
        shows no progress at all. WORKSHOP_PROGRESS_STYLE forces the choice.
    #>
    $requested = [string]$env:WORKSHOP_PROGRESS_STYLE
    if ($requested -ieq 'Lines') { return 'Lines' }
    if ($requested -ieq 'Inline') { return 'Inline' }
    if ([Console]::IsOutputRedirected) { return 'Lines' }
    return 'Inline'
}

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

    if ((Get-WorkshopProgressStyle) -eq 'Lines') {
        Write-Host $line
    }
    else {
        # Padded to the console width before the carriage return. Without this a
        # shorter line leaves the tail of a longer predecessor on screen -- a table
        # name of 12 characters following one of 30 left the last 18 behind.
        $width = try { [Console]::BufferWidth - 1 } catch { 120 }
        if ($width -lt $line.Length) { $width = $line.Length }
        Write-Host ("`r" + $line.PadRight($width)) -NoNewline
    }

    Write-Progress -Activity $Activity `
        -Status ("{0} of {1}" -f $Completed, $Total) `
        -PercentComplete ([int][Math]::Round($fraction * 100)) `
        -SecondsRemaining ([int]$eta.TotalSeconds)
}

function Complete-WorkshopProgressBar {
    param([Parameter(Mandatory)][string]$Activity)

    # The in-place line has no newline of its own, so one is owed before anything
    # else prints.
    if ((Get-WorkshopProgressStyle) -eq 'Inline') { Write-Host '' }
    Write-Progress -Activity $Activity -Completed
}
