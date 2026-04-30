[CmdletBinding()]
param(
    [string]$SubscriptionId = '192ad012-896e-4f14-8525-c37a2a9640f9',
    [string]$WorkspaceName = 'DIBSecCom',
    [string]$ResourceGroupName = 'sentinel',
    [string]$SchemaDirectory = (Join-Path $PSScriptRoot '..\schemas'),
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\sample'),
    [int]$LookbackDays = 7,
    [int]$MaxRowsPerTable = 5000,
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
if (-not (Get-Command Get-AzOperationalInsightsWorkspace -ErrorAction SilentlyContinue)) {
    throw 'Az.OperationalInsights is required. Install-Module Az.OperationalInsights and retry.'
}
if (-not (Get-Command Invoke-AzOperationalInsightsQuery -ErrorAction SilentlyContinue)) {
    throw 'Invoke-AzOperationalInsightsQuery is required. Update Az.OperationalInsights and retry.'
}
if (-not (Test-Path $SchemaDirectory)) {
    throw "Schema directory not found: $SchemaDirectory"
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName
$schemaTables = Get-ChildItem -Path $SchemaDirectory -Filter '*.schema.json' |
    ForEach-Object {
        $schema = Get-Content -Path $_.FullName -Raw | ConvertFrom-Json
        [string]$schema.tableName
    } |
    Sort-Object -Unique

if ($TableName) {
    $schemaTables = $schemaTables | Where-Object { $TableName -contains $_ }
}

$summary = foreach ($table in $schemaTables) {
    $csvPath = Join-Path $OutputDirectory "$table.csv"
    $query = @"
$table
| where TimeGenerated >= ago($($LookbackDays)d)
| take $MaxRowsPerTable
"@

    try {
        Write-Host "Exporting $table from $WorkspaceName"
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
