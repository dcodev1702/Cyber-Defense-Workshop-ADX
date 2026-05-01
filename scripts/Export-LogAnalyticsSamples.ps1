[CmdletBinding()]
param(
    [string]$SubscriptionName = 'Security',
    [string]$SubscriptionId,
    [string]$WorkspaceName = 'DIBSecCom',
    [string]$ResourceGroupName = 'sentinel',
    [string]$SchemaDirectory = (Join-Path $PSScriptRoot '..\schemas'),
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\sample'),
    [int]$LookbackDays = 7,
    [int]$MaxRowsPerTable = 5000,
    [ValidateSet('All', 'Linux')]
    [string]$SampleProfile = 'All',
    [string[]]$TableName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Get-Command Get-AzContext -ErrorAction SilentlyContinue)) {
    throw 'Az.Accounts is required. Install-Module Az.Accounts and run Connect-AzAccount.'
}
if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
    Connect-AzAccount | Out-Null
}
if (-not [string]::IsNullOrWhiteSpace($SubscriptionId)) {
    Set-AzContext -Subscription $SubscriptionId | Out-Null
}
elseif (-not [string]::IsNullOrWhiteSpace($SubscriptionName)) {
    $subscription = @(Get-AzSubscription -SubscriptionName $SubscriptionName)
    if ($subscription.Count -ne 1) {
        throw "Expected exactly one subscription named '$SubscriptionName'; found $($subscription.Count)."
    }
    Set-AzContext -Subscription $subscription[0].Id | Out-Null
}
if (-not (Get-Command Get-AzOperationalInsightsWorkspace -ErrorAction SilentlyContinue)) {
    throw 'Az.OperationalInsights is required. Install-Module Az.OperationalInsights and retry.'
}
if (-not (Get-Command Invoke-AzOperationalInsightsQuery -ErrorAction SilentlyContinue)) {
    throw 'Invoke-AzOperationalInsightsQuery is required. Update Az.OperationalInsights and retry.'
}
if (-not (Test-Path $SchemaDirectory)) {
    throw "Schema directory not found: $SchemaDirectory"
}

if ($SampleProfile -eq 'Linux' -and (Split-Path -Path $OutputDirectory -Leaf) -ne 'linux') {
    $OutputDirectory = Join-Path $OutputDirectory 'linux'
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName
$schemaByTable = @{}
Get-ChildItem -Path $SchemaDirectory -Filter '*.schema.json' |
    ForEach-Object {
        $schema = Get-Content -Path $_.FullName -Raw | ConvertFrom-Json
        $schemaByTable[[string]$schema.tableName] = $schema
    }
$schemaTables = $schemaByTable.Keys | Sort-Object -Unique

if ($TableName) {
    $schemaTables = $schemaTables | Where-Object { $TableName -contains $_ }
}

function New-LogAnalyticsSampleQuery {
    param(
        [Parameter(Mandatory)][string]$Table,
        [Parameter(Mandatory)]$Schema
    )

    if ($SampleProfile -ne 'Linux') {
        return @"
$Table
| where TimeGenerated >= ago($($LookbackDays)d)
| take $MaxRowsPerTable
"@
    }

    $columns = @($Schema.columns.name)
    if ($Table -eq 'DeviceInfo') {
        return @"
$Table
| where TimeGenerated >= ago($($LookbackDays)d)
| where OSPlatform has_any ("Linux", "Ubuntu") or OSDistribution has "Ubuntu"
| take $MaxRowsPerTable
"@
    }

    if ($Table -notlike 'Device*' -and $Table -notin @('AlertEvidence', 'AlertInfo')) {
        return $null
    }

    if ($columns -contains 'DeviceId') {
        return @"
let LinuxDevices = materialize(
    DeviceInfo
    | where TimeGenerated >= ago($($LookbackDays)d)
    | where OSPlatform has_any ("Linux", "Ubuntu") or OSDistribution has "Ubuntu"
    | summarize by DeviceId
);
$Table
| where TimeGenerated >= ago($($LookbackDays)d)
| join kind=inner LinuxDevices on DeviceId
| take $MaxRowsPerTable
"@
    }

    if ($columns -contains 'DeviceName') {
        return @"
let LinuxDevices = materialize(
    DeviceInfo
    | where TimeGenerated >= ago($($LookbackDays)d)
    | where OSPlatform has_any ("Linux", "Ubuntu") or OSDistribution has "Ubuntu"
    | summarize by DeviceName
);
$Table
| where TimeGenerated >= ago($($LookbackDays)d)
| join kind=inner LinuxDevices on DeviceName
| take $MaxRowsPerTable
"@
    }

    return $null
}

$summary = foreach ($table in $schemaTables) {
    $csvPath = Join-Path $OutputDirectory "$table.csv"
    $query = New-LogAnalyticsSampleQuery -Table $table -Schema $schemaByTable[$table]
    if ([string]::IsNullOrWhiteSpace($query)) {
        Write-Host "Skipping $table because it does not expose Linux device fields for $SampleProfile sampling"
        [pscustomobject]@{
            TableName = $table
            Status = 'Skipped'
            RowCount = 0
            Path = ''
        }
        continue
    }

    try {
        Write-Host "Exporting $table from $WorkspaceName ($SampleProfile profile)"
        $result = Invoke-AzOperationalInsightsQuery -Workspace $workspace -Query $query -Timespan ([TimeSpan]::FromDays($LookbackDays)) -Wait 180
        $rows = @($result.Results)
        if ($rows.Count -eq 0) {
            if (Test-Path $csvPath) {
                Remove-Item -Path $csvPath -Force
            }
            Write-Host "No rows found for $table"
            [pscustomobject]@{
                TableName = $table
                Status = 'NoRows'
                RowCount = 0
                Path = ''
            }
            continue
        }

        $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Wrote $($rows.Count) rows to $csvPath"
        [pscustomobject]@{
            TableName = $table
            Status = 'Exported'
            RowCount = $rows.Count
            Path = $csvPath
        }
    }
    catch {
        Write-Warning "Skipping $table`: $($_.Exception.Message)"
        [pscustomobject]@{
            TableName = $table
            Status = 'Skipped'
            RowCount = 0
            Path = ''
        }
    }
}

$summaryPath = Join-Path $OutputDirectory '_export-summary.csv'
$summary | Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8
$summary | Sort-Object Status, TableName | Format-Table -AutoSize
Write-Host "Export summary: $summaryPath"
