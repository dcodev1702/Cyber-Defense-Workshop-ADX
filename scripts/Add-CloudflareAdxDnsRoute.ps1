<#
.SYNOPSIS
Creates the public ADX CNAME through a browser-authenticated Cloudflared session.

.DESCRIPTION
Uses cloudflared tunnel login credentials rather than a Cloudflare API token.
This is the fallback when the Terraform API token does not have Zone DNS rights.

.EXAMPLE
.\scripts\Add-CloudflareAdxDnsRoute.ps1

.NOTES
Run cloudflared tunnel login first if %USERPROFILE%\.cloudflared\cert.pem is absent.
#>
[CmdletBinding()]
param(
    [string]$TerraformDirectory = (Join-Path $PSScriptRoot '..\infra\cloudflare-adx')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-CloudflaredExecutable {
    $command = Get-Command cloudflared -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $wingetPath = Join-Path ${env:ProgramFiles(x86)} 'cloudflared\cloudflared.exe'
    if (Test-Path -LiteralPath $wingetPath -PathType Leaf) {
        return $wingetPath
    }

    throw 'cloudflared was not found. Install Cloudflare.cloudflared and retry.'
}

$cloudflaredExecutable = Get-CloudflaredExecutable
$credentialsPath = Join-Path $env:USERPROFILE '.cloudflared\cert.pem'
if (-not (Test-Path $credentialsPath -PathType Leaf)) {
    throw "Cloudflare browser credentials are missing. Run 'cloudflared tunnel login', complete browser authorization for $credentialsPath, then retry."
}

if (-not (Test-Path $TerraformDirectory)) {
    throw "Terraform directory not found: $TerraformDirectory"
}

$previousLocation = Get-Location
try {
    Set-Location $TerraformDirectory
    $tunnelId = (& terraform output -raw tunnel_id).Trim()
    $publicHostname = (& terraform output -raw public_hostname).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($tunnelId) -or [string]::IsNullOrWhiteSpace($publicHostname)) {
        throw 'Terraform did not return the tunnel ID and public hostname required for DNS routing.'
    }

    & $cloudflaredExecutable tunnel route dns $tunnelId $publicHostname
    if ($LASTEXITCODE -ne 0) {
        throw "cloudflared failed to create the DNS route for $publicHostname."
    }
}
finally {
    Set-Location $previousLocation
}