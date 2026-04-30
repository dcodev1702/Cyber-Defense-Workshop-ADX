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
    $uri = "$($ClusterUri.TrimEnd('/'))/v2/rest/mgmt"
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

    Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body
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
    'Invoke-WorkshopAdxManagementCommand'
)
