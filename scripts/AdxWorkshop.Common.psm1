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

function Assert-WorkshopAdxClusterRunning {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$ClusterName,
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [string]$ClusterUri
    )

    $cluster = $null
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
        $cluster = Get-AzKustoCluster @scope -Name $ClusterName
    }
    elseif (Get-Command az -ErrorAction SilentlyContinue) {
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
        $cluster = $azOutput | ConvertFrom-Json
    }
    else {
        throw 'Az.Accounts/Az.Kusto or Azure CLI is required to verify the ADX cluster state before import.'
    }

    if (-not $cluster) {
        throw "ADX cluster '$ClusterName' was not found in resource group '$ResourceGroupName'."
    }

    $state = [string](Get-WorkshopObjectPropertyValue -InputObject $cluster -Name @('State', 'state'))
    $provisioningState = [string](Get-WorkshopObjectPropertyValue -InputObject $cluster -Name @('ProvisioningState', 'provisioningState'))
    $reportedUri = [string](Get-WorkshopObjectPropertyValue -InputObject $cluster -Name @('Uri', 'uri'))
    if ($state -ne 'Running') {
        throw "ADX cluster '$ClusterName' in resource group '$ResourceGroupName' is not running. Current state: '$state'; provisioning state: '$provisioningState'. Start it before import with Start-AzKustoCluster or the Azure portal, then retry."
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
