<#
.SYNOPSIS
Blocks the Docker network path that lets the Cloudflare connector bypass the read-only Kusto gateway.

.DESCRIPTION
Compose puts `cloudflared` on the edge network and Kustainer on the backend
network so the read-only gateway is the only route between them. On Docker 29
that separation is weaker than it looks: the old DOCKER-ISOLATION-STAGE chains
are gone and DOCKER-FORWARD accepts traffic from every bridge unconditionally,
so while the name `kusto` does not resolve from the edge network, the backend
IP is still reachable. A tunnel ingress rule pointed at `tcp://<backend-ip>:8080`
therefore reaches the engine with no allowlist, no database restriction, and no
rate limit in front of it.

This script inserts one rule into the DOCKER-USER chain -- which Docker
evaluates before its own accept rules and never rewrites -- dropping packets
that arrive on the edge bridge and leave on the backend bridge. It does not
affect the connector reaching the gateway (edge to edge), the gateway reaching
Kustainer (backend to backend), or the published 127.0.0.1:8080.

Bridge interface names are derived from the live Docker network IDs at run time,
because they change whenever a network is recreated.

Nothing here is hard-coded to a bridge name or a network name. The edge and
backend networks are read from the running containers, so the rule follows the
actual topology rather than a naming convention. Docker names a bridge after the
network ID, so recreating a network -- any `docker compose down` -- produces a
new bridge name and silently strips the protection while leaving a dead rule
behind that still looks like protection in `iptables -S`. This script removes
rules of its own shape whose interfaces no longer exist before applying the
current pair, so re-running it after any topology change is always correct.

The rule lives in the host firewall, not in the repository, so it does not
survive a Docker engine restart. Re-run this script after one, and use -Status
to check. Test-WorkshopNetworkIsolation.ps1 proves whether it is in force.

.EXAMPLE
.\scripts\Set-WorkshopNetworkIsolation.ps1
Applies the rule if it is not already present, clearing stale rules first.

.EXAMPLE
.\scripts\Set-WorkshopNetworkIsolation.ps1 -Status
Reports whether the rule is currently in force without changing anything.

.EXAMPLE
.\scripts\Set-WorkshopNetworkIsolation.ps1 -Remove
Removes the rule.

.EXAMPLE
.\scripts\Set-WorkshopNetworkIsolation.ps1 -EdgeNetwork my-edge -BackendNetwork my-backend
Uses explicit networks instead of deriving them from the running containers.

.NOTES
Requires Docker. On Docker Desktop the firewall lives inside the Linux VM, so
the rule is applied through a short-lived privileged helper container; on a
Linux host running as root, iptables is called directly.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$EdgeContainer = 'cyber-conf-wiesbaden-cloudflared',
    [string]$BackendContainer = 'cyber-conf-wiesbaden-kusto',
    [string]$EdgeNetwork,
    [string]$BackendNetwork,
    [string]$HelperImage = 'alpine:3.21',
    [switch]$Remove,
    [switch]$Status
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ContainerNetworks {
    param([Parameter(Mandatory)][string]$ContainerName)

    $raw = (& docker inspect $ContainerName --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Container '$ContainerName' was not found. Start the stack with 'docker compose up --detach', or pass -EdgeNetwork and -BackendNetwork explicitly."
    }

    return @(([string]$raw).Trim() -split '\s+' | Where-Object { $_ })
}

function Get-DockerBridgeInterface {
    <#
        Docker names a user-defined bridge br-<first 12 characters of the network
        ID>. Resolving it at run time matters: the name changes every time the
        network is recreated, so a hard-coded br- name silently stops matching
        and the rule protects nothing.
    #>
    param([Parameter(Mandatory)][string]$NetworkName)

    $networkId = (& docker network inspect $NetworkName --format '{{.Id}}' 2>&1)
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($networkId)) {
        throw "Docker network '$NetworkName' was not found. Start the stack with 'docker compose up --detach' first."
    }

    return 'br-' + ([string]$networkId).Trim().Substring(0, 12)
}

function Invoke-HostShell {
    <#
        Returns the exit code rather than throwing, because iptables -C uses a
        non-zero exit to mean "rule absent", which is a normal answer.
    #>
    param([Parameter(Mandatory)][string]$Command)

    $useDirect = $false
    if ($IsLinux) {
        $uid = (& id -u 2>$null)
        $useDirect = ($LASTEXITCODE -eq 0 -and "$uid".Trim() -eq '0')
    }

    if ($useDirect) {
        $output = & sh -c $Command 2>&1
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = ($output -join [Environment]::NewLine) }
    }

    # Docker Desktop keeps the firewall inside its Linux VM, so enter the init
    # process's namespaces from a throwaway privileged container.
    $output = & docker run --rm --privileged --pid=host --network=host $HelperImage `
        nsenter -t 1 -m -u -n -i sh -c $Command 2>&1
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = ($output -join [Environment]::NewLine) }
}

function Invoke-HostIptables {
    param([Parameter(Mandatory)][string]$Arguments)
    return Invoke-HostShell -Command ("iptables $Arguments")
}

function Test-IsolationRule {
    param([Parameter(Mandatory)][string]$In, [Parameter(Mandatory)][string]$Out)
    return (Invoke-HostIptables -Arguments "-C DOCKER-USER -i $In -o $Out -j DROP").ExitCode -eq 0
}

function Get-HostInterfaces {
    $result = Invoke-HostShell -Command 'ls /sys/class/net'
    if ($result.ExitCode -ne 0) {
        throw ("Could not list host network interfaces.`n{0}" -f $result.Output)
    }
    return @($result.Output -split '\s+' | Where-Object { $_ })
}

function Get-ExistingIsolationRules {
    <#
        Only rules of this script's exact shape are considered -- a DROP between
        two Docker bridges. Anything else in DOCKER-USER belongs to somebody
        else and is never touched.
    #>
    $result = Invoke-HostIptables -Arguments '-S DOCKER-USER'
    if ($result.ExitCode -ne 0) {
        throw ("The DOCKER-USER chain is not reachable, so the rule cannot be managed.`n{0}" -f $result.Output)
    }

    $rules = @()
    foreach ($line in ($result.Output -split '\r?\n')) {
        $match = [regex]::Match($line.Trim(), '^-A DOCKER-USER -i (?<in>br-[0-9a-f]{12}) -o (?<out>br-[0-9a-f]{12}) -j DROP$')
        if ($match.Success) {
            $rules += [pscustomobject]@{ In = $match.Groups['in'].Value; Out = $match.Groups['out'].Value }
        }
    }
    return $rules
}

# ---- resolve the topology ------------------------------------------------------

# Deriving the networks from the containers means the rule follows the actual
# topology. Renaming the Compose project, or the networks, changes nothing here.
if ([string]::IsNullOrWhiteSpace($EdgeNetwork) -or [string]::IsNullOrWhiteSpace($BackendNetwork)) {
    $edgeContainerNetworks = Get-ContainerNetworks -ContainerName $EdgeContainer
    $backendContainerNetworks = Get-ContainerNetworks -ContainerName $BackendContainer

    $shared = @($edgeContainerNetworks | Where-Object { $_ -in $backendContainerNetworks })
    if ($shared.Count -gt 0) {
        throw ("'{0}' and '{1}' share the network(s) {2}. They are directly connected, so no firewall rule between bridges can isolate them; fix the Compose topology first." -f $EdgeContainer, $BackendContainer, ($shared -join ', '))
    }

    if ([string]::IsNullOrWhiteSpace($EdgeNetwork)) {
        $EdgeNetwork = @($edgeContainerNetworks | Where-Object { $_ -notin $backendContainerNetworks })[0]
    }
    if ([string]::IsNullOrWhiteSpace($BackendNetwork)) {
        $BackendNetwork = @($backendContainerNetworks | Where-Object { $_ -notin $edgeContainerNetworks })[0]
    }
}

if ([string]::IsNullOrWhiteSpace($EdgeNetwork) -or [string]::IsNullOrWhiteSpace($BackendNetwork)) {
    throw 'Could not determine the edge and backend networks. Pass -EdgeNetwork and -BackendNetwork explicitly.'
}

$edgeBridge = Get-DockerBridgeInterface -NetworkName $EdgeNetwork
$backendBridge = Get-DockerBridgeInterface -NetworkName $BackendNetwork

Write-Host ('Edge     : {0,-34} {1}' -f $EdgeNetwork, $edgeBridge)
Write-Host ('Backend  : {0,-34} {1}' -f $BackendNetwork, $backendBridge)

# Fail loudly rather than installing a rule that drops everything: if both
# networks resolved to the same bridge, the lookup is wrong.
if ($edgeBridge -eq $backendBridge) {
    throw "The edge and backend networks resolved to the same bridge ($edgeBridge). Refusing to install a rule that would block the gateway from Kustainer."
}

$present = Test-IsolationRule -In $edgeBridge -Out $backendBridge

if ($Status) {
    $interfaces = Get-HostInterfaces
    $stale = @(Get-ExistingIsolationRules | Where-Object {
            -not ($_.In -eq $edgeBridge -and $_.Out -eq $backendBridge) -and
            (($_.In -notin $interfaces) -or ($_.Out -notin $interfaces))
        })

    if ($present) {
        Write-Host 'Rule     : IN FORCE' -ForegroundColor Green
    }
    else {
        Write-Host 'Rule     : NOT PRESENT' -ForegroundColor Yellow
        Write-Host ''
        Write-Host 'The Cloudflare connector can reach Kustainer directly by IP, bypassing the'
        Write-Host 'read-only gateway. Apply it with: .\scripts\Set-WorkshopNetworkIsolation.ps1'
    }

    foreach ($rule in $stale) {
        Write-Host ('Stale    : {0} -> {1} references an interface that no longer exists' -f $rule.In, $rule.Out) -ForegroundColor Yellow
    }
    if ($stale.Count -gt 0) {
        Write-Host 'Re-run without -Status to clear stale rules and reapply.' -ForegroundColor Yellow
    }

    Write-Host ''
    Write-Host 'Prove it actually blocks with: .\scripts\Test-WorkshopNetworkIsolation.ps1'
    exit $(if ($present) { 0 } else { 1 })
}

if ($Remove) {
    if (-not $present) {
        Write-Host 'Rule     : not present, nothing to remove.'
        exit 0
    }

    if ($PSCmdlet.ShouldProcess("$edgeBridge -> $backendBridge", 'Remove DOCKER-USER DROP rule')) {
        # Loop: a repeated -I on earlier runs could have stacked duplicates.
        while (Test-IsolationRule -In $edgeBridge -Out $backendBridge) {
            $result = Invoke-HostIptables -Arguments "-D DOCKER-USER -i $edgeBridge -o $backendBridge -j DROP"
            if ($result.ExitCode -ne 0) {
                throw ("Failed to remove the isolation rule.`n{0}" -f $result.Output)
            }
        }
        Write-Host 'Rule     : removed.' -ForegroundColor Yellow
        Write-Host 'The connector can now reach Kustainer directly by IP again.'
    }
    exit 0
}

# A recreated network leaves a rule pointing at a bridge that no longer exists.
# It still looks like protection in `iptables -S` and provides none, so clear
# those before adding the current pair.
$interfaces = Get-HostInterfaces
foreach ($rule in Get-ExistingIsolationRules) {
    $isCurrent = ($rule.In -eq $edgeBridge -and $rule.Out -eq $backendBridge)
    $isDead = ($rule.In -notin $interfaces) -or ($rule.Out -notin $interfaces)

    if (-not $isCurrent -and $isDead -and $PSCmdlet.ShouldProcess("$($rule.In) -> $($rule.Out)", 'Remove stale DOCKER-USER DROP rule')) {
        $result = Invoke-HostIptables -Arguments "-D DOCKER-USER -i $($rule.In) -o $($rule.Out) -j DROP"
        if ($result.ExitCode -eq 0) {
            Write-Host ('Stale    : removed {0} -> {1} (interface no longer exists)' -f $rule.In, $rule.Out) -ForegroundColor Yellow
        }
    }
}

if ($present) {
    Write-Host 'Rule     : already in force, nothing to do.' -ForegroundColor Green
}
elseif ($PSCmdlet.ShouldProcess("$edgeBridge -> $backendBridge", 'Insert DOCKER-USER DROP rule')) {
    $result = Invoke-HostIptables -Arguments "-I DOCKER-USER -i $edgeBridge -o $backendBridge -j DROP"
    if ($result.ExitCode -ne 0) {
        throw ("Failed to apply the isolation rule.`n{0}" -f $result.Output)
    }

    if (-not (Test-IsolationRule -In $edgeBridge -Out $backendBridge)) {
        throw 'The isolation rule was applied but is not readable back from DOCKER-USER.'
    }

    Write-Host 'Rule     : applied.' -ForegroundColor Green
}

Write-Host ''
Write-Host ('  iptables -I DOCKER-USER -i {0} -o {1} -j DROP' -f $edgeBridge, $backendBridge)
Write-Host ''
Write-Host 'Re-run after a Docker engine restart or any `docker compose down`, then prove'
Write-Host 'it is working with: .\scripts\Test-WorkshopNetworkIsolation.ps1'
