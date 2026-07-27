<#
.SYNOPSIS
Reads deployment-specific identifiers from outside the repository.

.DESCRIPTION
Tenant GUIDs, subscription GUIDs, workspace ids and storage account names are
deployment facts, not source. They were previously written as literal defaults in
tracked scripts, Bicep and documentation, which put a live tenant into a public
repository and put it in the one place the safety gate did not look.

Resolution order, first hit wins:

  1. An environment variable, when the caller names one. Best for CI.
  2. workshop.settings.json at the repository root. Gitignored; copy
     workshop.settings.example.json and fill it in.
  3. Nothing -- the caller decides whether that is fatal.

Nothing here has a fallback value on purpose. A default that happens to be
someone's real subscription is how this class of problem starts.

.EXAMPLE
. (Join-Path $PSScriptRoot 'WorkshopSettings.ps1')
$workspaceId = Get-WorkshopSetting -Name 'logAnalyticsWorkspaceId' -EnvironmentVariable 'CDW_LOG_ANALYTICS_WORKSPACE_ID'
#>

function Get-WorkshopSettingsPath {
    [CmdletBinding()]
    param([string]$Root = (Split-Path -Parent $PSScriptRoot))

    return (Join-Path $Root 'workshop.settings.json')
}

function Get-WorkshopSetting {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$EnvironmentVariable,
        [string]$Root = (Split-Path -Parent $PSScriptRoot),

        # Throw instead of returning $null when the setting is absent. Use this at
        # the point of use, so a script that does not need the value still runs.
        [switch]$Required
    )

    if ($EnvironmentVariable) {
        $fromEnvironment = [Environment]::GetEnvironmentVariable($EnvironmentVariable)
        if (-not [string]::IsNullOrWhiteSpace($fromEnvironment)) { return $fromEnvironment.Trim() }
    }

    $settingsPath = Get-WorkshopSettingsPath -Root $Root
    if (Test-Path -LiteralPath $settingsPath) {
        $settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
        $property = $settings.PSObject.Properties[$Name]
        if ($property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            return ([string]$property.Value).Trim()
        }
    }

    if ($Required) {
        $hint = if ($EnvironmentVariable) { " Set `$env:$EnvironmentVariable, or add" } else { ' Add' }
        throw ("The '{0}' setting is not configured.{1} it to {2} (copy workshop.settings.example.json to start)." -f $Name, $hint, $settingsPath)
    }

    return $null
}
