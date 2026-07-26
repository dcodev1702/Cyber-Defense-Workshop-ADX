<#
.SYNOPSIS
Proves the Cloudflare connector cannot bypass the read-only Kusto gateway.

.DESCRIPTION
Smoke test for the network boundary the workshop depends on. It does not read
the firewall and report what it says; it sends packets and reports what
actually happened, because a rule that references a stale bridge name still
looks correct in `iptables -S` and blocks nothing.

Live mode (the default) runs against the workshop stack and asserts:

  1. `kusto` does not resolve from the edge network.
  2. Kustainer is unreachable from the edge network by name.
  3. Kustainer is unreachable from the edge network by raw IP -- the bypass a
     tunnel ingress rule could use. Docker isolates bridges from each other,
     but publishing 8080 inserts an accept above that isolation which is not
     restricted by source bridge, so the split alone does not close this.
  4. Kustainer IS reachable from the backend network, so the gateway still
     works.
  5. The gateway is reachable from the edge network, so students still get in.
  6. The published 127.0.0.1:8080 still answers, so the instructor and the
     import scripts are unaffected.

Self-test mode builds two throwaway networks and a listener that publishes a
port -- the condition that makes a container reachable across networks in the
first place -- applies the same rule through Set-WorkshopNetworkIsolation.ps1,
and asserts reachable-then-blocked-then-reachable before removing everything.
It needs no workshop stack, so CI can run it.

.EXAMPLE
.\scripts\Test-WorkshopNetworkIsolation.ps1

.EXAMPLE
.\scripts\Test-WorkshopNetworkIsolation.ps1 -SelfTest

.NOTES
Exit code 0 when every assertion holds, 1 otherwise.
#>
[CmdletBinding()]
param(
    [string]$EdgeContainer = 'cyber-conf-wiesbaden-cloudflared',
    [string]$BackendContainer = 'cyber-conf-wiesbaden-kusto',
    [string]$GatewayContainer = 'cyber-conf-wiesbaden-kusto-readonly-gateway',
    [int]$BackendPort = 8080,
    [int]$GatewayPort = 8081,
    [string]$PublishedUri = 'http://127.0.0.1:8080/v1/rest/ping',
    [string]$HelperImage = 'alpine:3.21',
    [string]$ListenerImage = 'nginx:alpine',
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Failures = 0

function Assert-Condition {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Condition,
        [string]$Detail = ''
    )

    if ($Condition) {
        Write-Host ('  PASS  {0}{1}' -f $Name.PadRight(52), $Detail) -ForegroundColor Green
    }
    else {
        Write-Host ('  FAIL  {0}{1}' -f $Name.PadRight(52), $Detail) -ForegroundColor Red
        $script:Failures++
    }
}

function Test-TcpFromNetwork {
    <#
        A container attached to one network is the only honest way to ask what a
        container on that network can reach. Returns $true when the port is open.
    #>
    param(
        [Parameter(Mandatory)][string]$Network,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][int]$Port,
        [int]$TimeoutSeconds = 5
    )

    & docker run --rm --network $Network $HelperImage `
        timeout $TimeoutSeconds nc -z $Target $Port 2>&1 | Out-Null
    return $LASTEXITCODE -eq 0
}

function Test-NameResolves {
    param([Parameter(Mandatory)][string]$Network, [Parameter(Mandatory)][string]$Name)

    & docker run --rm --network $Network $HelperImage `
        sh -c "getent hosts $Name" 2>&1 | Out-Null
    return $LASTEXITCODE -eq 0
}

function Get-ContainerNetworkAddress {
    param([Parameter(Mandatory)][string]$ContainerName, [Parameter(Mandatory)][string]$NetworkName)

    $ip = (& docker inspect $ContainerName --format ('{{(index .NetworkSettings.Networks "' + $NetworkName + '").IPAddress}}') 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "Could not read the address of '$ContainerName' on '$NetworkName'." }
    return ([string]$ip).Trim()
}

function Get-SoleNetwork {
    param([Parameter(Mandatory)][string]$ContainerName, [string[]]$Excluding = @())

    $raw = (& docker inspect $ContainerName --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Container '$ContainerName' was not found. Start the stack with 'docker compose up --detach --wait'."
    }
    $networks = @(([string]$raw).Trim() -split '\s+' | Where-Object { $_ -and $_ -notin $Excluding })
    if ($networks.Count -eq 0) { throw "Container '$ContainerName' is not on a network of its own." }
    return $networks[0]
}

# ================================ self-test =====================================

if ($SelfTest) {
    Write-Host 'Self-test: proving the rule blocks cross-network traffic' -ForegroundColor Cyan
    Write-Host ''

    $suffix = [guid]::NewGuid().ToString('N').Substring(0, 8)
    $edgeNet = "cdw-selftest-edge-$suffix"
    $backendNet = "cdw-selftest-backend-$suffix"
    $listener = "cdw-selftest-listener-$suffix"
    $isolationScript = Join-Path $PSScriptRoot 'Set-WorkshopNetworkIsolation.ps1'
    # A real server, not a `nc -l` loop: busybox nc serves one connection and
    # exits, so the loop leaves gaps that read as "blocked" and made this test
    # fail against a mitigation that was working correctly.
    #
    # The published port is the whole point. Docker does isolate bridges from
    # each other (`! -i br-X -o br-X -j DROP` in the DOCKER chain), but
    # publishing a port inserts an ACCEPT above those drops that is not
    # restricted by source bridge, so every container on every other network
    # can reach the published container port. That is exactly why Kustainer,
    # which publishes 8080, was reachable from the edge network. Without a
    # published port here the listener would already be unreachable and the
    # test would prove nothing.
    $listenerPort = 80

    try {
        & docker network create $edgeNet | Out-Null
        & docker network create $backendNet | Out-Null
        & docker run -d --name $listener --network $backendNet -p '127.0.0.1::80' $ListenerImage | Out-Null

        $listenerIp = ''
        $deadline = (Get-Date).AddSeconds(60)
        while ((Get-Date) -lt $deadline) {
            $listenerIp = Get-ContainerNetworkAddress -ContainerName $listener -NetworkName $backendNet
            if ($listenerIp -and (Test-TcpFromNetwork -Network $backendNet -Target $listenerIp -Port $listenerPort)) { break }
            Start-Sleep -Seconds 2
        }
        if (-not (Test-TcpFromNetwork -Network $backendNet -Target $listenerIp -Port $listenerPort)) {
            throw 'The self-test listener never became reachable from its own network.'
        }

        Write-Host ("  listener on {0} at {1}:{2}" -f $backendNet, $listenerIp, $listenerPort)
        Write-Host ''

        Assert-Condition -Name 'reachable across networks before the rule' `
            -Condition (Test-TcpFromNetwork -Network $edgeNet -Target $listenerIp -Port $listenerPort) `
            -Detail '(a published port punches through bridge isolation)'

        & pwsh -NoProfile -File $isolationScript -EdgeNetwork $edgeNet -BackendNetwork $backendNet | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Set-WorkshopNetworkIsolation.ps1 failed to apply the rule.' }

        Assert-Condition -Name 'blocked across networks after the rule' `
            -Condition (-not (Test-TcpFromNetwork -Network $edgeNet -Target $listenerIp -Port $listenerPort)) `
            -Detail '(the mitigation works)'

        Assert-Condition -Name 'still reachable from its own network' `
            -Condition (Test-TcpFromNetwork -Network $backendNet -Target $listenerIp -Port $listenerPort) `
            -Detail '(the rule is not over-broad)'

        & pwsh -NoProfile -File $isolationScript -EdgeNetwork $edgeNet -BackendNetwork $backendNet -Remove | Out-Null

        Assert-Condition -Name 'reachable again after -Remove' `
            -Condition (Test-TcpFromNetwork -Network $edgeNet -Target $listenerIp -Port $listenerPort) `
            -Detail '(removal is clean)'
    }
    finally {
        & docker rm -f $listener 2>&1 | Out-Null
        & docker network rm $edgeNet 2>&1 | Out-Null
        & docker network rm $backendNet 2>&1 | Out-Null
    }

    Write-Host ''
    if ($script:Failures -gt 0) {
        Write-Host ("Self-test FAILED: {0} assertion(s)." -f $script:Failures) -ForegroundColor Red
        exit 1
    }
    Write-Host 'Self-test passed.' -ForegroundColor Green
    exit 0
}

# ================================ live stack ====================================

Write-Host 'Workshop network boundary' -ForegroundColor Cyan

$edgeNetwork = Get-SoleNetwork -ContainerName $EdgeContainer
$backendNetwork = Get-SoleNetwork -ContainerName $BackendContainer
$backendIp = Get-ContainerNetworkAddress -ContainerName $BackendContainer -NetworkName $backendNetwork

if ($edgeNetwork -eq $backendNetwork) {
    Write-Host ''
    Write-Host ("  FAIL  {0} and {1} share the network {2}." -f $EdgeContainer, $BackendContainer, $edgeNetwork) -ForegroundColor Red
    Write-Host '        The connector is directly attached to Kustainer; no firewall rule can fix that.'
    exit 1
}

Write-Host ("  edge    : {0}" -f $edgeNetwork)
Write-Host ("  backend : {0}  ({1} at {2})" -f $backendNetwork, $BackendContainer, $backendIp)
Write-Host ''

# --- the boundary must hold -----------------------------------------------------

Assert-Condition -Name 'kusto does not resolve from the edge network' `
    -Condition (-not (Test-NameResolves -Network $edgeNetwork -Name 'kusto'))

Assert-Condition -Name 'kusto unreachable from edge by name' `
    -Condition (-not (Test-TcpFromNetwork -Network $edgeNetwork -Target 'kusto' -Port $BackendPort))

Assert-Condition -Name 'kusto unreachable from edge by raw IP' `
    -Condition (-not (Test-TcpFromNetwork -Network $edgeNetwork -Target $backendIp -Port $BackendPort)) `
    -Detail ("({0}:{1})" -f $backendIp, $BackendPort)

# --- and the workshop must still work -------------------------------------------

Assert-Condition -Name 'kusto reachable from the backend network' `
    -Condition (Test-TcpFromNetwork -Network $backendNetwork -Target $backendIp -Port $BackendPort) `
    -Detail '(gateway path intact)'

$gatewayEdgeIp = Get-ContainerNetworkAddress -ContainerName $GatewayContainer -NetworkName $edgeNetwork
Assert-Condition -Name 'gateway reachable from the edge network' `
    -Condition (Test-TcpFromNetwork -Network $edgeNetwork -Target $gatewayEdgeIp -Port $GatewayPort) `
    -Detail '(student path intact)'

$publishedOk = $false
try {
    $response = Invoke-WebRequest -Uri $PublishedUri -TimeoutSec 15 -SkipHttpErrorCheck
    $publishedOk = ($response.StatusCode -eq 200)
}
catch { $publishedOk = $false }

Assert-Condition -Name 'published 127.0.0.1:8080 still answers' `
    -Condition $publishedOk `
    -Detail '(instructor and import scripts intact)'

Write-Host ''
if ($script:Failures -gt 0) {
    Write-Host ("Network boundary FAILED: {0} assertion(s)." -f $script:Failures) -ForegroundColor Red
    Write-Host 'If the raw-IP check failed, apply the rule: .\scripts\Set-WorkshopNetworkIsolation.ps1'
    exit 1
}

Write-Host 'Network boundary holds: the connector can only reach Kustainer through the gateway.' -ForegroundColor Green
exit 0
