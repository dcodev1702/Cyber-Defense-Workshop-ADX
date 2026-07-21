<#
.SYNOPSIS
Provisions the Cloudflare Tunnel and starts the local Compose runtime for Kusto.

.DESCRIPTION
Uses Terraform to create a remotely managed Cloudflare Tunnel and a Cloudflare
Access application restricted to an explicit email allow-list. Docker Compose
owns the local Kusto and cloudflared containers. The Cloudflare API token is
read only from the CLOUDFLARE_API_TOKEN process environment variable; it is
never written to the workspace or command output. The connector token is
written only to an ignored local Compose environment file. When the token does
not have Zone DNS permission, use Add-CloudflareAdxDnsRoute.ps1 after this
script.

.EXAMPLE
# The script starts the Compose Kusto service, applies the Cloudflare resources,
# and creates the ignored cloudflared.env connector-token file when required.
.\scripts\Start-CloudflareAdxTunnel.ps1 -Apply

.NOTES
Requires Docker Desktop, Terraform, and outbound connectivity to Cloudflare.
#>
[CmdletBinding()]
param(
    [string[]]$AllowedEmail = @(),
    [string]$AllowedEmailFile = (Join-Path $PSScriptRoot '..\infra\cloudflare-adx\allowed-emails.txt'),
    [string]$TerraformDirectory = (Join-Path $PSScriptRoot '..\infra\cloudflare-adx'),
    [string]$SecretConfigPath = (Join-Path $PSScriptRoot '..\.cf-config'),
    [string]$ComposeFile = (Join-Path $PSScriptRoot '..\compose.yaml'),
    [string]$CloudflaredEnvironmentFile = (Join-Path $PSScriptRoot '..\infra\cloudflare-adx\cloudflared.env'),
    [string]$ZoneName = 'tier1-cyberdefense.ai',
    [string]$CloudflaredContainerName = 'cyber-conf-wiesbaden-cloudflared',
    [switch]$Apply,
    [switch]$ManageDnsWithApi,
    [switch]$ReplaceExistingConnector,
    [switch]$MigrateLegacyContainers
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw ('Command failed with exit code {0}: {1} {2}' -f $LASTEXITCODE, $FilePath, ($Arguments -join ' '))
    }
}

function Invoke-DockerCompose {
    param(
        [Parameter(Mandatory)][string]$ProjectDirectory,
        [Parameter(Mandatory)][string]$ComposeFilePath,
        [Parameter(Mandatory)][string[]]$Arguments
    )

    $composeArguments = @(
        'compose',
        '--project-directory', $ProjectDirectory,
        '--file', $ComposeFilePath
    ) + $Arguments
    Invoke-NativeCommand -FilePath 'docker' -Arguments $composeArguments
}

function Get-ContainerComposeProject {
    param([Parameter(Mandatory)][string]$ContainerName)

    $containerId = [string](& docker ps --all --quiet --filter "name=^/$ContainerName$")
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to inspect Docker container '$ContainerName'."
    }

    $containerId = $containerId.Trim()
    if ([string]::IsNullOrWhiteSpace($containerId)) {
        return $null
    }

    $labelsJson = [string](& docker inspect $containerId --format '{{json .Config.Labels}}')
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to inspect Docker container '$ContainerName'."
    }

    $labels = $labelsJson | ConvertFrom-Json
    $composeProjectProperty = if ($null -eq $labels) {
        $null
    }
    else {
        $labels.PSObject.Properties['com.docker.compose.project']
    }
    $composeProject = if ($null -eq $composeProjectProperty) {
        ''
    }
    else {
        [string]$composeProjectProperty.Value
    }

    return [pscustomobject]@{
        Id      = $containerId
        Project = $composeProject.Trim()
    }
}

function Prepare-ComposeContainerMigration {
    param(
        [Parameter(Mandatory)][string]$ContainerName,
        [Parameter(Mandatory)][string]$ExpectedProjectName,
        [Parameter(Mandatory)][bool]$MigrateLegacyContainers
    )

    $existingContainer = Get-ContainerComposeProject -ContainerName $ContainerName
    if ($null -eq $existingContainer -or $existingContainer.Project -eq $ExpectedProjectName) {
        return $false
    }

    if (-not [string]::IsNullOrWhiteSpace($existingContainer.Project)) {
        throw "Container '$ContainerName' belongs to Docker Compose project '$($existingContainer.Project)', not '$ExpectedProjectName'."
    }

    if (-not $MigrateLegacyContainers) {
        throw "Container '$ContainerName' was created by the legacy Docker workflow. Re-run with -Apply -MigrateLegacyContainers, then rebuild the local Student snapshot if Kusto was replaced."
    }

    $isRunning = ([string](& docker inspect $existingContainer.Id --format '{{.State.Running}}')).Trim() -eq 'true'
    if ($isRunning) {
        $stopTimeoutSeconds = if ($ContainerName -eq 'cyber-conf-wiesbaden-kusto') { 120 } else { 30 }
        $stopArguments = @('stop', '--time', $stopTimeoutSeconds)
        if ($ContainerName -eq 'cyber-conf-wiesbaden-kusto') {
            $stopArguments += @('--signal', 'SIGINT')
        }
        Invoke-NativeCommand -FilePath 'docker' -Arguments ($stopArguments + $ContainerName) | Out-Host
    }

    Invoke-NativeCommand -FilePath 'docker' -Arguments @('rm', $ContainerName) | Out-Host
    return $true
}

function Write-CloudflaredEnvironmentFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$TunnelToken
    )

    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    $utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, "TUNNEL_TOKEN=$TunnelToken`n", $utf8WithoutBom)
}

function Get-CloudflareApiError {
    param([Parameter(Mandatory)]$Response)

    $messages = @($Response.errors | ForEach-Object {
        if ($_.message) { [string]$_.message } else { $_ | ConvertTo-Json -Compress }
    })
    if ($messages.Count -eq 0) {
        return 'Cloudflare did not provide an error message.'
    }

    return ($messages -join '; ')
}

function Get-CloudflareApiToken {
    param([Parameter(Mandatory)][string]$ConfigPath)

    if (-not [string]::IsNullOrWhiteSpace($env:CLOUDFLARE_API_TOKEN)) {
        return $env:CLOUDFLARE_API_TOKEN
    }

    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
        throw "Set CLOUDFLARE_API_TOKEN directly in this terminal or provide a local secret config file at '$ConfigPath'."
    }

    $configText = [System.IO.File]::ReadAllText($ConfigPath)
    $match = [regex]::Match($configText, '(?i)\bcfat_[A-Za-z0-9_-]+\b')
    if (-not $match.Success) {
        throw "The local secret configuration file '$ConfigPath' does not contain a Cloudflare API token in the expected format."
    }

    return $match.Value
}

function Get-AllowedEmailAddresses {
    param(
        [string[]]$EmailAddress,
        [string]$EmailFilePath
    )

    $candidates = New-Object System.Collections.Generic.List[string]
    foreach ($value in @($EmailAddress)) {
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            $candidates.Add($value) | Out-Null
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($EmailFilePath) -and (Test-Path -LiteralPath $EmailFilePath -PathType Leaf)) {
        foreach ($line in [System.IO.File]::ReadAllLines($EmailFilePath)) {
            $withoutComment = ($line -replace '\s*#.*$', '').Trim()
            if ([string]::IsNullOrWhiteSpace($withoutComment)) {
                continue
            }

            foreach ($value in $withoutComment -split '[,;]') {
                if (-not [string]::IsNullOrWhiteSpace($value)) {
                    $candidates.Add($value.Trim()) | Out-Null
                }
            }
        }
    }

    $allowedEmailAddresses = @(
        $candidates |
            ForEach-Object { $_.Trim().ToLowerInvariant() } |
            Where-Object { $_ -match '^[^@\s]+@[^@\s]+\.[^@\s]+$' } |
            Sort-Object -Unique
    )
    if ($allowedEmailAddresses.Count -eq 0) {
        throw "Supply -AllowedEmail or add at least one valid email address to '$EmailFilePath'."
    }

    $invalidEmailAddresses = @(
        $candidates |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -and $_ -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$' }
    )
    if ($invalidEmailAddresses.Count -gt 0) {
        throw "The Access allow-list includes invalid email address(es): $($invalidEmailAddresses -join ', ')."
    }

    return $allowedEmailAddresses
}

foreach ($commandName in @('docker', 'terraform')) {
    if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
        throw "Required command '$commandName' was not found in PATH."
    }
}

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not (Test-Path -LiteralPath $ComposeFile -PathType Leaf)) {
    throw "Docker Compose file not found: $ComposeFile"
}
if ($MigrateLegacyContainers -and -not $Apply) {
    throw '-MigrateLegacyContainers requires -Apply because it replaces containers.'
}

Invoke-NativeCommand -FilePath 'docker' -Arguments @('compose', 'version')

$cloudflareApiToken = Get-CloudflareApiToken -ConfigPath $SecretConfigPath
$allowedEmailAddresses = @(Get-AllowedEmailAddresses -EmailAddress $AllowedEmail -EmailFilePath $AllowedEmailFile)
$previousCloudflareApiToken = $env:CLOUDFLARE_API_TOKEN
$env:CLOUDFLARE_API_TOKEN = $cloudflareApiToken

try {
    if (-not (Test-Path $TerraformDirectory)) {
        throw "Terraform directory not found: $TerraformDirectory"
    }

    $legacyKustoMigrated = $false
    foreach ($containerName in @($CloudflaredContainerName, 'cyber-conf-wiesbaden-kusto')) {
        $wasMigrated = Prepare-ComposeContainerMigration `
            -ContainerName $containerName `
            -ExpectedProjectName 'cyber-conf-wiesbaden' `
            -MigrateLegacyContainers $MigrateLegacyContainers.IsPresent
        if ($containerName -eq 'cyber-conf-wiesbaden-kusto' -and $wasMigrated) {
            $legacyKustoMigrated = $true
        }
    }

    Invoke-DockerCompose `
        -ProjectDirectory $repositoryRoot `
        -ComposeFilePath $ComposeFile `
        -Arguments @('up', '--detach', '--wait', '--wait-timeout', '300', 'kusto')

    if ($legacyKustoMigrated) {
        Write-Warning 'Kusto was migrated to a new Compose container. Rebuild the mounted Student snapshot with .\scripts\Copy-StudentAdxToLocalKusto.ps1 -ForceRecreate.'
    }

    $allowListVariablesPath = Join-Path $TerraformDirectory 'allowed-emails.auto.tfvars.json'
    $allowListVariables = [ordered]@{
        allowed_emails = [string[]]$allowedEmailAddresses
    }
    $utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText(
        $allowListVariablesPath,
        ($allowListVariables | ConvertTo-Json -Depth 5),
        $utf8WithoutBom
    )

    $terraformVariables = @(
        '-var', "manage_dns_with_api=$($ManageDnsWithApi.IsPresent.ToString().ToLowerInvariant())"
    )
    if ($ManageDnsWithApi) {
        try {
            $zoneResponse = Invoke-RestMethod `
                -Method Get `
                -Uri "https://api.cloudflare.com/client/v4/zones?name=$([uri]::EscapeDataString($ZoneName))&status=active" `
                -Headers @{ Authorization = "Bearer $cloudflareApiToken" } `
                -TimeoutSec 60
        }
        catch {
            throw "Cloudflare zone lookup failed for '$ZoneName': $($_.Exception.Message)"
        }

        if (-not $zoneResponse.success) {
            throw "Cloudflare zone lookup failed for '$ZoneName': $(Get-CloudflareApiError -Response $zoneResponse)"
        }

        $zones = @($zoneResponse.result)
        if ($zones.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$zones[0].id)) {
            throw "Expected exactly one active Cloudflare zone named '$ZoneName', but received $($zones.Count)."
        }
        $terraformVariables += @('-var', "cloudflare_zone_id=$([string]$zones[0].id)")
    }

    $requestBody = @{ csl = '.show cluster' } | ConvertTo-Json -Compress
    try {
        $healthCheck = Invoke-WebRequest `
            -UseBasicParsing `
            -Method Post `
            -ContentType 'application/json' `
            -Body $requestBody `
            -Uri 'http://127.0.0.1:8080/v1/rest/mgmt' `
            -TimeoutSec 30
    }
    catch {
        throw "The local Kusto emulator is not reachable at http://127.0.0.1:8080: $($_.Exception.Message)"
    }

    if ($healthCheck.StatusCode -ne 200) {
        throw "The local Kusto emulator health check returned HTTP $($healthCheck.StatusCode)."
    }

    $previousLocation = Get-Location
    try {
        Set-Location $TerraformDirectory
        Invoke-NativeCommand -FilePath 'terraform' -Arguments @('init', '-upgrade')
        Invoke-NativeCommand -FilePath 'terraform' -Arguments @('validate')

        $planArguments = @('plan') + $terraformVariables
        if (-not $Apply) {
            Invoke-NativeCommand -FilePath 'terraform' -Arguments $planArguments
            Write-Host 'Terraform plan completed. Re-run with -Apply to create the Cloudflare resources and start the connector.'
            return
        }

        Invoke-NativeCommand -FilePath 'terraform' -Arguments (@('apply', '-auto-approve') + $terraformVariables)
        $accountId = (& terraform output -raw cloudflare_account_id).Trim()
        $tunnelId = (& terraform output -raw tunnel_id).Trim()
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($accountId) -or [string]::IsNullOrWhiteSpace($tunnelId)) {
            throw 'Terraform did not return the Cloudflare account ID and tunnel ID required to start the connector.'
        }

        if ($ReplaceExistingConnector -or -not (Test-Path -LiteralPath $CloudflaredEnvironmentFile -PathType Leaf)) {
            $tokenResponse = Invoke-RestMethod `
                -Method Get `
                -Uri "https://api.cloudflare.com/client/v4/accounts/$accountId/cfd_tunnel/$tunnelId/token" `
                -Headers @{ Authorization = "Bearer $cloudflareApiToken" } `
                -TimeoutSec 60
            if (-not $tokenResponse.success -or [string]::IsNullOrWhiteSpace([string]$tokenResponse.result)) {
                throw "Cloudflare did not return a connector token: $(Get-CloudflareApiError -Response $tokenResponse)"
            }

            Write-CloudflaredEnvironmentFile `
                -Path $CloudflaredEnvironmentFile `
                -TunnelToken ([string]$tokenResponse.result)
        }

        $cloudflaredComposeArguments = @('up', '--detach', '--wait', '--wait-timeout', '300')
        if ($ReplaceExistingConnector) {
            $cloudflaredComposeArguments += '--force-recreate'
        }
        $cloudflaredComposeArguments += 'cloudflared'
        Invoke-DockerCompose `
            -ProjectDirectory $repositoryRoot `
            -ComposeFilePath $ComposeFile `
            -Arguments $cloudflaredComposeArguments

        $publicHostname = (& terraform output -raw public_hostname).Trim()
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($publicHostname)) {
            throw 'Terraform did not return the public hostname.'
        }

        Write-Host "Cloudflare Tunnel connector is ready. Access the protected endpoint at https://$publicHostname"
    }
    finally {
        Set-Location $previousLocation
    }
}
finally {
    if ($null -eq $previousCloudflareApiToken) {
        Remove-Item Env:CLOUDFLARE_API_TOKEN -ErrorAction SilentlyContinue
    }
    else {
        $env:CLOUDFLARE_API_TOKEN = $previousCloudflareApiToken
    }
}