<#
.SYNOPSIS
Shared helper module for ADX workshop provisioning and ingestion scripts.

.DESCRIPTION
Provides common functions for acquiring ADX tokens, formatting Kusto identifiers
and string literals, invoking ADX management commands, parsing ADX response rows,
checking Azure resource permissions, and ensuring the ADX cluster is running
before table or ingestion operations.

.EXAMPLE
Import-Module .\scripts\AdxWorkshop.Common.psm1 -Force

.NOTES
Name: AdxWorkshop.Common.psm1
Date: 2026-05-01
Authors: dcodev1702 and GitHub Copilot CLI w/ ChatGPT 5.5 xhigh
Dependencies: Az.Accounts/Az.Kusto or Azure CLI for authentication and cluster state, ADX REST API access.
Key commands: Get-AzAccessToken, Invoke-AzRestMethod, Get-AzKustoCluster, Start-AzKustoCluster, Invoke-RestMethod.
#>
Set-StrictMode -Version Latest

function ConvertTo-WorkshopPlainTextToken {
    param([Parameter(Mandatory)]$Token)

    if ($Token -is [System.Security.SecureString]) {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Token)
        try {
            return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }

    return [string]$Token
}

function Get-WorkshopObjectPropertyValue {
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)][string[]]$Name
    )

    foreach ($propertyName in $Name) {
        $property = $InputObject.PSObject.Properties[$propertyName]
        if ($property) {
            return $property.Value
        }
    }

    return $null
}

# Token cache. A fresh token was acquired on every management call, so a batched
# ingest (Import-SyntheticTelemetry sends 500 rows at a time) triggered dozens of
# token acquisitions for one table. Cache the plaintext token with its real
# expiry and reuse it until it is close to expiring; -Force bypasses the cache.
$script:WorkshopAdxToken = $null
$script:WorkshopAdxTokenExpiresOn = [datetimeoffset]::MinValue

function Get-WorkshopAdxAccessToken {
    [CmdletBinding()]
    param(
        [switch]$Force
    )

    if (-not $Force -and
        -not [string]::IsNullOrWhiteSpace($script:WorkshopAdxToken) -and
        $script:WorkshopAdxTokenExpiresOn -gt [datetimeoffset]::UtcNow.AddMinutes(5)) {
        return $script:WorkshopAdxToken
    }

    if (Get-Command Get-AzAccessToken -ErrorAction SilentlyContinue) {
        try {
            $tokenResult = Get-AzAccessToken -ResourceUrl 'https://kusto.kusto.windows.net' -ErrorAction Stop
            $script:WorkshopAdxToken = ConvertTo-WorkshopPlainTextToken -Token $tokenResult.Token
            $expiresOn = Get-WorkshopObjectPropertyValue -InputObject $tokenResult -Name @('ExpiresOn', 'expiresOn')
            $script:WorkshopAdxTokenExpiresOn = if ($expiresOn) { [datetimeoffset]$expiresOn } else { [datetimeoffset]::UtcNow.AddMinutes(50) }
            return $script:WorkshopAdxToken
        }
        catch {
            Write-Verbose "Get-AzAccessToken failed: $($_.Exception.Message)"
        }
    }

    if (Get-Command az -ErrorAction SilentlyContinue) {
        # Read the token and its expiry together, and check the CLI exit code:
        # az writes diagnostics to stdout on some failures, and returning that as
        # a bearer token produces a confusing 401 far downstream instead of a
        # clear "run az login" here.
        $tokenJson = az account get-access-token --resource https://kusto.kusto.windows.net --output json 2>$null
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($tokenJson)) {
            try {
                $parsed = $tokenJson | ConvertFrom-Json
            }
            catch {
                $parsed = $null
            }

            if ($parsed -and -not [string]::IsNullOrWhiteSpace($parsed.accessToken)) {
                $script:WorkshopAdxToken = [string]$parsed.accessToken
                $script:WorkshopAdxTokenExpiresOn =
                    if ($parsed.PSObject.Properties['expires_on']) { [datetimeoffset]::FromUnixTimeSeconds([int64]$parsed.expires_on) }
                    elseif ($parsed.PSObject.Properties['expiresOn']) { [datetimeoffset]([datetime]$parsed.expiresOn) }
                    else { [datetimeoffset]::UtcNow.AddMinutes(50) }
                return $script:WorkshopAdxToken
            }
        }
    }

    throw 'Could not obtain an Azure Data Explorer token. Run Connect-AzAccount or az login, then retry.'
}

function Test-WorkshopAzureResourceActionAllowed {
    param(
        [Parameter(Mandatory)][string]$ResourceId,
        [Parameter(Mandatory)][string]$Action
    )

    $permissions = $null
    $permissionsPath = "$ResourceId/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
    if (Get-Command Invoke-AzRestMethod -ErrorAction SilentlyContinue) {
        $permissionsResponse = Invoke-AzRestMethod -Method GET -Path $permissionsPath -ErrorAction Stop
        $permissions = ($permissionsResponse.Content | ConvertFrom-Json).value
    }
    elseif (Get-Command az -ErrorAction SilentlyContinue) {
        $permissionsResponse = & az rest --method get --url "https://management.azure.com$permissionsPath" --output json 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Could not read effective permissions for '$ResourceId': $permissionsResponse"
        }
        $permissions = ($permissionsResponse | ConvertFrom-Json).value
    }
    else {
        throw 'Az.Accounts/Az.Resources or Azure CLI is required to validate ADX cluster start permissions.'
    }

    foreach ($permission in @($permissions)) {
        $actionAllowed = $false
        foreach ($allowedAction in @($permission.actions)) {
            if ($Action -like [string]$allowedAction) {
                $actionAllowed = $true
                break
            }
        }
        if (-not $actionAllowed) {
            continue
        }

        $actionDenied = $false
        foreach ($deniedAction in @($permission.notActions)) {
            if ($Action -like [string]$deniedAction) {
                $actionDenied = $true
                break
            }
        }
        if (-not $actionDenied) {
            return $true
        }
    }

    return $false
}

function Get-WorkshopAdxClusterResource {
    param(
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$ClusterName,
        [string]$SubscriptionId,
        [string]$SubscriptionName
    )

    if ((Get-Command Get-AzContext -ErrorAction SilentlyContinue) -and (Get-Command Get-AzKustoCluster -ErrorAction SilentlyContinue)) {
        if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
            Connect-AzAccount | Out-Null
        }
        if (-not [string]::IsNullOrWhiteSpace($SubscriptionId)) {
            Set-AzContext -Subscription $SubscriptionId | Out-Null
        }
        elseif (-not [string]::IsNullOrWhiteSpace($SubscriptionName)) {
            Set-AzContext -Subscription $SubscriptionName | Out-Null
        }

        $scope = @{
            ResourceGroupName = $ResourceGroupName
        }
        $contextSubscriptionId = (Get-AzContext).Subscription.Id
        if (-not [string]::IsNullOrWhiteSpace($contextSubscriptionId)) {
            $scope['SubscriptionId'] = $contextSubscriptionId
        }

        return Get-AzKustoCluster @scope -Name $ClusterName
    }

    if (Get-Command az -ErrorAction SilentlyContinue) {
        $azArgs = @('kusto', 'cluster', 'show', '--resource-group', $ResourceGroupName, '--name', $ClusterName, '--output', 'json')
        if (-not [string]::IsNullOrWhiteSpace($SubscriptionId)) {
            $azArgs += @('--subscription', $SubscriptionId)
        }
        elseif (-not [string]::IsNullOrWhiteSpace($SubscriptionName)) {
            $azArgs += @('--subscription', $SubscriptionName)
        }

        $azOutput = & az @azArgs 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Could not read ADX cluster state with Azure CLI: $azOutput"
        }
        return ($azOutput | ConvertFrom-Json)
    }

    throw 'Az.Accounts/Az.Kusto or Azure CLI is required to verify the ADX cluster state before import.'
}

function Start-WorkshopAdxClusterResource {
    param(
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$ClusterName,
        [string]$SubscriptionId
    )

    if (-not (Get-Command Start-AzKustoCluster -ErrorAction SilentlyContinue)) {
        throw 'Az.Kusto Start-AzKustoCluster is required to start a stopped ADX cluster automatically.'
    }

    $scope = @{
        ResourceGroupName = $ResourceGroupName
        Name = $ClusterName
    }
    if (-not [string]::IsNullOrWhiteSpace($SubscriptionId)) {
        $scope['SubscriptionId'] = $SubscriptionId
    }

    Start-AzKustoCluster @scope | Out-Null
}

function Assert-WorkshopAdxClusterRunning {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$ClusterName,
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [string]$ClusterUri,
        [int]$StartTimeoutMinutes = 30,
        [int]$StartPollSeconds = 30
    )

    $cluster = Get-WorkshopAdxClusterResource -ResourceGroupName $ResourceGroupName -ClusterName $ClusterName -SubscriptionId $SubscriptionId -SubscriptionName $SubscriptionName
    if (-not $cluster) {
        throw "ADX cluster '$ClusterName' was not found in resource group '$ResourceGroupName'."
    }

    $state = [string](Get-WorkshopObjectPropertyValue -InputObject $cluster -Name @('State', 'state'))
    $provisioningState = [string](Get-WorkshopObjectPropertyValue -InputObject $cluster -Name @('ProvisioningState', 'provisioningState'))
    $reportedUri = [string](Get-WorkshopObjectPropertyValue -InputObject $cluster -Name @('Uri', 'uri'))
    $resourceId = [string](Get-WorkshopObjectPropertyValue -InputObject $cluster -Name @('Id', 'id'))
    if ($state -eq 'Stopped') {
        if ([string]::IsNullOrWhiteSpace($resourceId)) {
            throw "Could not determine the Azure resource ID for ADX cluster '$ClusterName'; cannot validate start permissions."
        }

        $startAction = 'Microsoft.Kusto/clusters/start/action'
        if (-not (Test-WorkshopAzureResourceActionAllowed -ResourceId $resourceId -Action $startAction)) {
            throw "The current Azure identity does not have '$startAction' on ADX cluster '$ClusterName'. Assign a role such as Contributor or another role containing that action, then retry."
        }

        Write-Host "ADX cluster $ClusterName is stopped. Current identity has '$startAction'; starting cluster."
        Start-WorkshopAdxClusterResource -ResourceGroupName $ResourceGroupName -ClusterName $ClusterName -SubscriptionId $SubscriptionId
        $state = 'Starting'
    }

    if ($state -ne 'Running') {
        if ($state -notin @('Starting', 'Stopped')) {
            throw "ADX cluster '$ClusterName' is not in a startable/running state. Current state: '$state'; provisioning state: '$provisioningState'."
        }

        $deadline = (Get-Date).AddMinutes($StartTimeoutMinutes)
        do {
            Start-Sleep -Seconds $StartPollSeconds
            $cluster = Get-WorkshopAdxClusterResource -ResourceGroupName $ResourceGroupName -ClusterName $ClusterName -SubscriptionId $SubscriptionId -SubscriptionName $SubscriptionName
            $state = [string](Get-WorkshopObjectPropertyValue -InputObject $cluster -Name @('State', 'state'))
            $provisioningState = [string](Get-WorkshopObjectPropertyValue -InputObject $cluster -Name @('ProvisioningState', 'provisioningState'))
            Write-Host "ADX cluster $ClusterName state: $state; provisioning state: $provisioningState"
        } while ($state -ne 'Running' -and (Get-Date) -lt $deadline)

        if ($state -ne 'Running') {
            throw "Timed out waiting for ADX cluster '$ClusterName' to reach Running state. Current state: '$state'; provisioning state: '$provisioningState'."
        }

        $reportedUri = [string](Get-WorkshopObjectPropertyValue -InputObject $cluster -Name @('Uri', 'uri'))
    }
    if (-not [string]::IsNullOrWhiteSpace($ClusterUri) -and -not [string]::IsNullOrWhiteSpace($reportedUri) -and $ClusterUri.TrimEnd('/') -ne $reportedUri.TrimEnd('/')) {
        Write-Warning "Configured ClusterUri '$ClusterUri' does not match Azure cluster URI '$reportedUri'."
    }

    Write-Host "ADX cluster check passed: $ClusterName is Running."
    return $cluster
}

function ConvertTo-WorkshopKustoIdentifier {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)

    return "['$($Name.Replace("'", "''"))']"
}

function ConvertTo-WorkshopKustoStringLiteral {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Value = '')

    return "'$($Value.Replace("'", "''"))'"
}

function Invoke-WorkshopAdxManagementCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ClusterUri,
        [Parameter(Mandatory)][string]$DatabaseName,
        [Parameter(Mandatory)][string]$Command,
        [int]$ServerTimeoutSeconds = 600,

        # Head-room for TLS, token refresh and response transfer on top of the
        # server's own budget. The client must always outlast the server, never
        # the other way round.
        [int]$ClientTimeoutMarginSeconds = 60,

        # Opt in ONLY for commands that are safe to run twice. Off by default
        # because this helper also drives `.ingest inline` and `.export async`,
        # where a retry after the server already committed duplicates data.
        [switch]$Idempotent,

        [int]$MaximumRetryCount = 3
    )

    $token = Get-WorkshopAdxAccessToken
    $uri = "$($ClusterUri.TrimEnd('/'))/v1/rest/mgmt"
    $body = @{
        db = $DatabaseName
        csl = $Command
        properties = @{
            Options = @{
                servertimeout = [TimeSpan]::FromSeconds($ServerTimeoutSeconds).ToString()
            }
        }
    } | ConvertTo-Json -Depth 10

    $headers = @{
        Authorization = "Bearer $token"
        'Content-Type' = 'application/json'
    }

    # servertimeout is only a server-side hint and does not bound the HTTP client,
    # so the client needs its own limit or a hung connection hangs the whole run.
    #
    # It was a flat 300s while callers ask for up to 1800s, so the client gave up
    # while ADX was still working: a batch between the two aborts here, the server
    # finishes anyway, and the operator reruns it -- into whatever the first run
    # already committed.
    $clientTimeoutSeconds = $ServerTimeoutSeconds + $ClientTimeoutMarginSeconds

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            return Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body -ErrorAction Stop `
                -TimeoutSec $clientTimeoutSeconds
        }
        catch {
            # -MaximumRetryCount used to do this, but it retries on any 4xx/5xx.
            # A 5xx from a load balancer AFTER an `.ingest inline` committed means
            # the rows are already in; replaying it silently duplicates the batch
            # and Initialize-Workshop still reports success. Retry only what is
            # safe to replay, and only what genuinely means "not processed".
            $response = $_.Exception.Response
            $status = if ($response -and $response.StatusCode) { [int]$response.StatusCode } else { 0 }

            $retryable = $Idempotent -and ($status -eq 429 -or $status -eq 503) -and $attempt -le $MaximumRetryCount
            if (-not $retryable) { throw }

            # Honour Retry-After when ADX sends one; it knows its own throttle window.
            $delaySeconds = 5 * $attempt
            try {
                $retryAfter = $response.Headers.RetryAfter
                if ($retryAfter) {
                    if ($retryAfter.Delta) { $delaySeconds = [int]$retryAfter.Delta.TotalSeconds }
                    elseif ($retryAfter.Date) { $delaySeconds = [Math]::Max(1, [int](($retryAfter.Date - [DateTimeOffset]::UtcNow).TotalSeconds)) }
                }
            }
            catch { }

            Write-Verbose ("ADX returned {0}; retrying idempotent command in {1}s (attempt {2}/{3})." -f $status, $delaySeconds, $attempt, $MaximumRetryCount)
            Start-Sleep -Seconds $delaySeconds
        }
    }
}

function ConvertFrom-WorkshopAdxResponseRows {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Response)

    if (-not $Response.Tables -or $Response.Tables.Count -eq 0) {
        return @()
    }

    $primary = $Response.Tables[0]
    if (-not $primary.Rows) {
        return @()
    }

    $rows = foreach ($row in $primary.Rows) {
        $object = [ordered]@{}
        for ($i = 0; $i -lt $primary.Columns.Count; $i++) {
            $column = $primary.Columns[$i]
            $name = if ($column.ColumnName) { $column.ColumnName } else { $column.Name }
            $object[$name] = $row[$i]
        }
        [pscustomobject]$object
    }

    return @($rows)
}

Export-ModuleMember -Function @(
    'ConvertTo-WorkshopKustoIdentifier',
    'ConvertTo-WorkshopKustoStringLiteral',
    'ConvertFrom-WorkshopAdxResponseRows',
    'Get-WorkshopAdxAccessToken',
    'Assert-WorkshopAdxClusterRunning',
    'Invoke-WorkshopAdxManagementCommand'
)
