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

function Get-WorkshopAdxAccessToken {
    [CmdletBinding()]
    param()

    if (Get-Command Get-AzAccessToken -ErrorAction SilentlyContinue) {
        try {
            $tokenResult = Get-AzAccessToken -ResourceUrl 'https://kusto.kusto.windows.net' -ErrorAction Stop
            return ConvertTo-WorkshopPlainTextToken -Token $tokenResult.Token
        }
        catch {
            Write-Verbose "Get-AzAccessToken failed: $($_.Exception.Message)"
        }
    }

    if (Get-Command az -ErrorAction SilentlyContinue) {
        $token = az account get-access-token --resource https://kusto.kusto.windows.net --query accessToken -o tsv 2>$null
        if (-not [string]::IsNullOrWhiteSpace($token)) {
            return $token.Trim()
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
        [int]$ServerTimeoutSeconds = 600
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

    Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body -ErrorAction Stop
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
