<#
.SYNOPSIS
Starts a local Cloudflare TCP proxy for the shared workshop Service Auth credential.

.DESCRIPTION
Forwards a local port to the read-only Kusto gateway through Cloudflare Access
using the shared workshop Service Token. The token avoids per-student Cloudflare
identity seats and should be rotated or deleted after the class.
#>
[CmdletBinding()]
param(
    [string]$CredentialFile,
    [string]$ServiceTokenId,
    [string]$ServiceTokenSecret,
    [string]$Hostname,
    [ValidateRange(1, 65535)][int]$LocalPort = 8080
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not [string]::IsNullOrWhiteSpace($CredentialFile)) {
    if (-not (Test-Path -LiteralPath $CredentialFile -PathType Leaf)) {
        throw "Credential file not found: $CredentialFile"
    }

    $credentialValues = ConvertFrom-StringData -StringData ([System.IO.File]::ReadAllText((Resolve-Path $CredentialFile)))
    if ([string]::IsNullOrWhiteSpace($ServiceTokenId)) {
        $ServiceTokenId = [string]$credentialValues.TUNNEL_SERVICE_TOKEN_ID
    }
    if ([string]::IsNullOrWhiteSpace($ServiceTokenSecret)) {
        $ServiceTokenSecret = [string]$credentialValues.TUNNEL_SERVICE_TOKEN_SECRET
    }
    if ([string]::IsNullOrWhiteSpace($Hostname)) {
        $Hostname = [string]$credentialValues.TUNNEL_SERVICE_HOSTNAME
    }
}

if ([string]::IsNullOrWhiteSpace($ServiceTokenId)) {
    $ServiceTokenId = $env:TUNNEL_SERVICE_TOKEN_ID
}
if ([string]::IsNullOrWhiteSpace($ServiceTokenSecret)) {
    $ServiceTokenSecret = $env:TUNNEL_SERVICE_TOKEN_SECRET
}
if ([string]::IsNullOrWhiteSpace($Hostname)) {
    $Hostname = if ([string]::IsNullOrWhiteSpace($env:TUNNEL_SERVICE_HOSTNAME)) {
        'adx.tier1-cyberdefense.ai'
    }
    else {
        $env:TUNNEL_SERVICE_HOSTNAME
    }
}

if ([string]::IsNullOrWhiteSpace($ServiceTokenId) -or [string]::IsNullOrWhiteSpace($ServiceTokenSecret)) {
    throw 'Supply -CredentialFile, -ServiceTokenId and -ServiceTokenSecret, or set TUNNEL_SERVICE_TOKEN_ID and TUNNEL_SERVICE_TOKEN_SECRET.'
}

if (-not (Get-Command cloudflared -ErrorAction SilentlyContinue)) {
    throw 'cloudflared was not found in PATH. Install it with: winget install --id Cloudflare.cloudflared --exact'
}

& cloudflared access tcp `
    --hostname $Hostname `
    --url "127.0.0.1:$LocalPort" `
    --service-token-id $ServiceTokenId `
    --service-token-secret $ServiceTokenSecret

if ($LASTEXITCODE -ne 0) {
    throw "cloudflared access tcp exited with code $LASTEXITCODE."
}