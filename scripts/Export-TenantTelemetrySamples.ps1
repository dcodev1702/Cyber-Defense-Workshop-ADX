<#
.SYNOPSIS
Exports real tenant telemetry samples from Log Analytics and Microsoft Defender XDR advanced hunting.

.DESCRIPTION
Pulls up to a fixed number of rows per table from the two authoritative telemetry
surfaces used by this workshop and writes them as newline-delimited JSON (NDJSON)
under a dated folder inside the sample directory.

Routing is data driven. Each table is resolved to a preferred source using
metadata\tables.manifest.json. Tables categorized as AzureMonitor are pulled from
the Log Analytics workspace; every other table is pulled from Microsoft Defender XDR
advanced hunting. When the preferred source returns nothing, the alternate source is
tried automatically, so a table that exists on both surfaces is always captured.

Alongside every NDJSON file the script writes a field profile that records, for each
column, the observed type, null and empty rate, distinct cardinality, the most common
values with their frequencies, numeric ranges, and string length ranges. The synthetic
telemetry generator consumes those profiles so generated rows use real observed value
distributions instead of empty schema defaults.

The output folder uses the repository date-time group convention, yyyyMMddTHHmmssZ,
matching the ADX backup folders under data\backups. Every datetime value in an
exported row is normalized to ISO-8601 round-trip UTC so the files match the machine
format already present in the sample CSVs rather than the Defender portal display
format.

Log Analytics access uses the Az context token for https://api.loganalytics.io.
Defender advanced hunting access uses Microsoft Graph with the ThreatHunting.Read.All
delegated scope, acquired through interactive browser sign-in. Device code
authentication is never used.

LookbackDays applies the Log Analytics query timespan. Microsoft Defender XDR advanced
hunting retains 30 days regardless of this value, so Defender-sourced tables are
naturally capped at 30 days even when a longer window is requested.

.EXAMPLE
.\scripts\Export-TenantTelemetrySamples.ps1

.EXAMPLE
.\scripts\Export-TenantTelemetrySamples.ps1 -MaxRowsPerTable 1000 -LookbackDays 90

.EXAMPLE
.\scripts\Export-TenantTelemetrySamples.ps1 -TableName AgentsInfo, IntuneDevices -Source DefenderXdr

.EXAMPLE
.\scripts\Export-TenantTelemetrySamples.ps1 -ProfileOnly

.NOTES
Name: Export-TenantTelemetrySamples.ps1
Date: 2026-07-24
Authors: dcodev1702 and GitHub Copilot
Dependencies: PowerShell 7, Az.Accounts, Az.OperationalInsights, Microsoft.Graph.Authentication, Log Analytics reader on the workspace, ThreatHunting.Read.All in Microsoft Defender XDR.
Key commands: Get-AzAccessToken, Invoke-RestMethod, Connect-MgGraph, Invoke-MgGraphRequest, ConvertTo-Json.
#>
[CmdletBinding()]
param(
    [string]$SubscriptionName = 'Security',
    [string]$SubscriptionId,
    [string]$WorkspaceName = 'DIBSecCom',
    [string]$ResourceGroupName = 'sentinel',
    [string]$WorkspaceId,
    [string]$ManifestPath = (Join-Path $PSScriptRoot '..' 'metadata' 'tables.manifest.json'),
    [string]$SchemaDirectory = (Join-Path $PSScriptRoot '..' 'schemas'),
    [string]$OutputRoot = (Join-Path $PSScriptRoot '..' 'sample'),
    [Alias('DateStamp')]
    [string]$Dtg = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'),
    [ValidateRange(1, 100000)]
    [int]$MaxRowsPerTable = 1000,
    [ValidateRange(1, 90)]
    [int]$LookbackDays = 90,
    [ValidateSet('All', 'LogAnalytics', 'DefenderXdr')]
    [string]$Source = 'All',
    [string[]]$TableName,
    [ValidateRange(1, 500)]
    [int]$TopValuesPerColumn = 40,
    [switch]$ProfileOnly,
    [switch]$SkipExisting
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "PowerShell 7 or later is required. Detected $($PSVersionTable.PSVersion). Run this script from pwsh."
}

# Tables added after the original 48-table manifest. StorageBlobInfo does not exist on
# either surface; the Azure Storage blob diagnostic table StorageBlobLogs is the real
# equivalent and is present in both Log Analytics and Defender XDR advanced hunting.
#
# Tier 2 additions cover the cloud control plane, threat intelligence, Sentinel
# analytics, DNS resolution, and Office workload activity. ThreatIntelIndicators is the
# current threat intelligence table; the legacy ThreatIntelligenceIndicator table is
# empty in this tenant and is deliberately not exported.
$script:AdditionalTables = @(
    [pscustomobject]@{ Name = 'AgentsInfo'; PreferredSource = 'DefenderXdr' }
    [pscustomobject]@{ Name = 'StorageBlobLogs'; PreferredSource = 'DefenderXdr' }
    [pscustomobject]@{ Name = 'IntuneDevices'; PreferredSource = 'DefenderXdr' }
    [pscustomobject]@{ Name = 'ThreatIntelIndicators'; PreferredSource = 'LogAnalytics' }
    [pscustomobject]@{ Name = 'SecurityAlert'; PreferredSource = 'LogAnalytics' }
    [pscustomobject]@{ Name = 'AzureActivity'; PreferredSource = 'LogAnalytics' }
    [pscustomobject]@{ Name = 'ASimDnsActivityLogs'; PreferredSource = 'LogAnalytics' }
    [pscustomobject]@{ Name = 'OfficeActivity'; PreferredSource = 'LogAnalytics' }
    [pscustomobject]@{ Name = 'CloudAuditEvents'; PreferredSource = 'DefenderXdr' }
    # Tier 3 attack path, UEBA, and identity risk surfaces.
    [pscustomobject]@{ Name = 'ExposureGraphNodes'; PreferredSource = 'DefenderXdr' }
    [pscustomobject]@{ Name = 'ExposureGraphEdges'; PreferredSource = 'DefenderXdr' }
    [pscustomobject]@{ Name = 'CloudStorageAggregatedEvents'; PreferredSource = 'DefenderXdr' }
    [pscustomobject]@{ Name = 'BehaviorAnalytics'; PreferredSource = 'LogAnalytics' }
    [pscustomobject]@{ Name = 'UserPeerAnalytics'; PreferredSource = 'LogAnalytics' }
    [pscustomobject]@{ Name = 'IntuneDeviceComplianceOrg'; PreferredSource = 'LogAnalytics' }
    [pscustomobject]@{ Name = 'MicrosoftServicePrincipalSignInLogs'; PreferredSource = 'LogAnalytics' }
    [pscustomobject]@{ Name = 'AADGraphActivityLogs'; PreferredSource = 'LogAnalytics' }
    # Tier 4 depth and coverage surfaces.
    [pscustomobject]@{ Name = 'AADRiskyUsers'; PreferredSource = 'LogAnalytics' }
    [pscustomobject]@{ Name = 'SentinelHealth'; PreferredSource = 'LogAnalytics' }
    [pscustomobject]@{ Name = 'AzureDiagnostics'; PreferredSource = 'LogAnalytics' }
    [pscustomobject]@{ Name = 'Heartbeat'; PreferredSource = 'LogAnalytics' }
)

# Repo schema names that historically did not match the live table name. The live name
# is queried; the repo name is used for the output file.
$script:LiveTableNameOverride = @{}

function Write-Stage {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function ConvertTo-WorkshopIso8601 {
    <#
        Normalizes any value that is, or looks like, a datetime into ISO-8601
        round-trip UTC. This matches the machine format already present in the sample
        CSVs (2026-04-28T22:17:09.851769Z) instead of the Defender portal display
        format (May 1, 2026 4:51:34 PM).
    #>
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [datetime]) {
        return $Value.ToUniversalTime().ToString('o')
    }
    if ($Value -is [datetimeoffset]) {
        return $Value.UtcDateTime.ToString('o')
    }

    if ($Value -is [string]) {
        $text = [string]$Value
        if ($text -match '^\s*$' -or $text.Length -gt 64) {
            return $Value
        }

        # Only attempt conversion on strings that plausibly encode a date.
        $looksLikeDate = $text -match '^\d{4}-\d{2}-\d{2}[T ]' -or
            $text -match '^[A-Z][a-z]{2,8} \d{1,2}, \d{4}' -or
            $text -match '^\d{1,2}/\d{1,2}/\d{4}'
        if (-not $looksLikeDate) {
            return $Value
        }

        $parsed = [datetime]::MinValue
        $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
        if ([datetime]::TryParse($text, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
            return $parsed.ToString('o')
        }
        return $Value
    }

    return $Value
}

function ConvertTo-WorkshopNormalizedRow {
    param([Parameter(Mandatory)][object]$Row)

    $normalized = [ordered]@{}
    foreach ($property in $Row.PSObject.Properties) {
        $normalized[$property.Name] = ConvertTo-WorkshopIso8601 -Value $property.Value
    }
    return [pscustomobject]$normalized
}

function Get-WorkshopTableCatalog {
    $manifest = @(Get-Content -Path $ManifestPath -Raw | ConvertFrom-Json)
    $catalog = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($entry in $manifest) {
        $categories = @($entry.categories)
        $preferred = if ($categories -contains 'AzureMonitor') { 'LogAnalytics' } else { 'DefenderXdr' }
        $catalog.Add([pscustomobject]@{
                Name            = [string]$entry.name
                PreferredSource = $preferred
                SourceProduct   = [string]$entry.sourceProduct
                Origin          = 'manifest'
            })
    }

    foreach ($extra in $script:AdditionalTables) {
        if ($catalog.Name -notcontains $extra.Name) {
            $catalog.Add([pscustomobject]@{
                    Name            = $extra.Name
                    PreferredSource = $extra.PreferredSource
                    SourceProduct   = 'Microsoft Defender XDR / Azure Monitor'
                    Origin          = 'added'
                })
        }
    }

    return $catalog | Sort-Object Name
}

function Connect-WorkshopAzureContext {
    if (-not (Get-Command Get-AzContext -ErrorAction SilentlyContinue)) {
        throw 'Az.Accounts is required. Install-Module Az.Accounts and retry.'
    }
    if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
        Connect-AzAccount | Out-Null
    }
    if (-not [string]::IsNullOrWhiteSpace($SubscriptionId)) {
        Set-AzContext -Subscription $SubscriptionId | Out-Null
    }
    elseif (-not [string]::IsNullOrWhiteSpace($SubscriptionName)) {
        $subscription = @(Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction SilentlyContinue)
        if ($subscription.Count -eq 1) {
            Set-AzContext -Subscription $subscription[0].Id | Out-Null
        }
    }
}

function Resolve-WorkshopWorkspaceId {
    if (-not [string]::IsNullOrWhiteSpace($WorkspaceId)) {
        return $WorkspaceId
    }
    $workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName
    return [string]$workspace.CustomerId
}

function Get-WorkshopLogAnalyticsToken {
    $token = Get-AzAccessToken -ResourceUrl 'https://api.loganalytics.io' -AsSecureString
    return [System.Net.NetworkCredential]::new('', $token.Token).Password
}

function Invoke-WorkshopLogAnalyticsQuery {
    param(
        [Parameter(Mandatory)][string]$Query,
        [Parameter(Mandatory)][string]$CustomerId,
        [Parameter(Mandatory)][string]$AccessToken
    )

    $uri = "https://api.loganalytics.io/v1/workspaces/$CustomerId/query"
    $body = @{ query = $Query; timespan = "P$($LookbackDays)D" } | ConvertTo-Json -Depth 4
    $headers = @{ Authorization = "Bearer $AccessToken"; 'Content-Type' = 'application/json' }
    $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body -TimeoutSec 300

    $table = @($response.tables)[0]
    if ($null -eq $table) {
        return @()
    }

    $columnNames = @($table.columns.name)
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($row in @($table.rows)) {
        $record = [ordered]@{}
        for ($i = 0; $i -lt $columnNames.Count; $i++) {
            $record[$columnNames[$i]] = $row[$i]
        }
        $rows.Add([pscustomobject]$record)
    }
    return $rows.ToArray()
}

function Connect-WorkshopDefenderGraph {
    if (-not (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue)) {
        throw 'Microsoft.Graph.Authentication is required. Install-Module Microsoft.Graph.Authentication and retry.'
    }

    $context = Get-MgContext -ErrorAction SilentlyContinue
    if ($null -ne $context -and @($context.Scopes) -contains 'ThreatHunting.Read.All') {
        return
    }

    Write-Stage 'Signing in to Microsoft Graph for Defender advanced hunting (browser)'
    Connect-MgGraph -Scopes 'ThreatHunting.Read.All' -NoWelcome
}

function Invoke-WorkshopDefenderQuery {
    param(
        [Parameter(Mandatory)][string]$Query,
        [int]$MaxAttempts = 5
    )

    # Advanced hunting through Microsoft Graph allows 15 calls per minute and returns
    # HTTP 429 with a Retry-After header past that. Honor it instead of failing over to
    # the wrong source.
    $response = $null
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $response = Invoke-MgGraphRequest -Method POST `
                -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' `
                -Body (@{ Query = $Query } | ConvertTo-Json -Depth 4) `
                -ContentType 'application/json' `
                -OutputType PSObject
            break
        }
        catch {
            $status = 0
            if ($_.Exception.PSObject.Properties['Response'] -and $null -ne $_.Exception.Response) {
                $status = [int]$_.Exception.Response.StatusCode
            }
            $isThrottled = $status -eq 429 -or $_.Exception.Message -match 'TooManyRequests|throttl'
            if (-not $isThrottled -or $attempt -eq $MaxAttempts) {
                throw
            }

            $retryAfter = 20 * $attempt
            Write-Host "    throttled by advanced hunting; waiting $retryAfter second(s)" -ForegroundColor DarkYellow
            Start-Sleep -Seconds $retryAfter
        }
    }

    $results = @($response.results)
    if ($results.Count -eq 0) {
        return @()
    }

    # Graph emits companion "<Column>@odata.type" annotations. Drop them so the
    # exported record shape matches the advanced hunting schema exactly.
    $columnNames = @($response.schema.name)
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($result in $results) {
        $record = [ordered]@{}
        foreach ($columnName in $columnNames) {
            $property = $result.PSObject.Properties[$columnName]
            $record[$columnName] = if ($property) { $property.Value } else { $null }
        }
        $rows.Add([pscustomobject]$record)
    }
    return $rows.ToArray()
}

function Get-WorkshopColumnProfile {
    param(
        [Parameter(Mandatory)][string]$ColumnName,
        [AllowNull()][AllowEmptyCollection()][object[]]$Values = @()
    )

    if ($null -eq $Values) { $Values = @() }
    $total = $Values.Count
    $nullCount = 0
    $emptyCount = 0
    $observedTypes = [System.Collections.Generic.HashSet[string]]::new()
    $frequency = [System.Collections.Generic.Dictionary[string, int]]::new()
    $numeric = [System.Collections.Generic.List[double]]::new()
    $minLength = [int]::MaxValue
    $maxLength = 0

    foreach ($value in $Values) {
        if ($null -eq $value) {
            $nullCount++
            continue
        }

        [void]$observedTypes.Add($value.GetType().Name)

        $text = if ($value -is [string]) {
            $value
        }
        elseif ($value -is [bool] -or $value -is [int] -or $value -is [long] -or $value -is [double] -or $value -is [decimal] -or $value -is [datetime]) {
            [string]$value
        }
        else {
            ConvertTo-Json -InputObject $value -Compress -Depth 12
        }

        if ([string]::IsNullOrWhiteSpace($text)) {
            $emptyCount++
        }

        $minLength = [Math]::Min($minLength, $text.Length)
        $maxLength = [Math]::Max($maxLength, $text.Length)

        $parsed = 0.0
        if ($value -isnot [bool] -and $value -isnot [datetime] -and [double]::TryParse($text, [ref]$parsed)) {
            $numeric.Add($parsed)
        }

        # Long payloads blow up the profile without improving generation fidelity.
        $key = if ($text.Length -gt 200) { $text.Substring(0, 200) + '...' } else { $text }
        if ($frequency.ContainsKey($key)) {
            $frequency[$key]++
        }
        else {
            $frequency[$key] = 1
        }
    }

    $topValues = @(
        $frequency.GetEnumerator() |
            Sort-Object -Property Value -Descending |
            Select-Object -First $TopValuesPerColumn |
            ForEach-Object { [ordered]@{ value = $_.Key; count = $_.Value } }
    )

    $columnProfile = [ordered]@{
        name          = $ColumnName
        observedTypes = @($observedTypes | Sort-Object)
        rowCount      = $total
        nullCount     = $nullCount
        emptyCount    = $emptyCount
        nullRate      = if ($total -gt 0) { [Math]::Round(($nullCount + $emptyCount) / $total, 4) } else { 1 }
        distinctCount = $frequency.Count
        minLength     = if ($minLength -eq [int]::MaxValue) { 0 } else { $minLength }
        maxLength     = $maxLength
        topValues     = $topValues
    }

    if ($numeric.Count -gt 0) {
        $sorted = @($numeric | Sort-Object)
        $columnProfile['numericMin'] = $sorted[0]
        $columnProfile['numericMax'] = $sorted[$sorted.Count - 1]
        $columnProfile['numericMedian'] = $sorted[[int]([Math]::Floor($sorted.Count / 2))]
    }

    return $columnProfile
}

function New-WorkshopTableProfile {
    param(
        [Parameter(Mandatory)][string]$Table,
        [Parameter(Mandatory)][string]$LiveTable,
        [Parameter(Mandatory)][string]$ResolvedSource,
        [AllowNull()][AllowEmptyCollection()][object[]]$Rows = @()
    )

    if ($null -eq $Rows) { $Rows = @() }

    $columnNames = [System.Collections.Generic.List[string]]::new()
    foreach ($row in $Rows) {
        foreach ($property in $row.PSObject.Properties) {
            if (-not $columnNames.Contains($property.Name)) {
                $columnNames.Add($property.Name)
            }
        }
    }

    $columns = foreach ($columnName in $columnNames) {
        $values = [System.Collections.Generic.List[object]]::new()
        foreach ($row in $Rows) {
            $property = $row.PSObject.Properties[$columnName]
            $values.Add($(if ($null -eq $property) { $null } else { $property.Value }))
        }
        Get-WorkshopColumnProfile -ColumnName $columnName -Values $values.ToArray()
    }

    return [ordered]@{
        tableName     = $Table
        liveTableName = $LiveTable
        source        = $ResolvedSource
        capturedUtc   = (Get-Date).ToUniversalTime().ToString('o')
        lookbackDays  = $LookbackDays
        rowCount      = $Rows.Count
        columnCount   = $columnNames.Count
        columns       = @($columns)
    }
}

function Write-WorkshopNdjson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows
    )

    $encoding = [System.Text.UTF8Encoding]::new($false)
    $writer = [System.IO.StreamWriter]::new($Path, $false, $encoding)
    try {
        foreach ($row in $Rows) {
            $writer.WriteLine(($row | ConvertTo-Json -Compress -Depth 24))
        }
    }
    finally {
        $writer.Dispose()
    }
}

$catalog = Get-WorkshopTableCatalog
if ($TableName) {
    $catalog = @($catalog | Where-Object { $TableName -contains $_.Name })
}
if ($Source -ne 'All') {
    $catalog = @($catalog | Where-Object { $_.PreferredSource -eq $Source })
}
if ($catalog.Count -eq 0) {
    throw 'No tables selected. Check -TableName and -Source.'
}

$outputDirectory = Join-Path $OutputRoot $Dtg
$profileDirectory = Join-Path $outputDirectory '_field-profiles'
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $profileDirectory -Force | Out-Null

Write-Stage "Exporting $($catalog.Count) table(s) to $outputDirectory"

$needsLogAnalytics = @($catalog | Where-Object { $_.PreferredSource -eq 'LogAnalytics' }).Count -gt 0 -or $Source -eq 'All'
$needsDefender = @($catalog | Where-Object { $_.PreferredSource -eq 'DefenderXdr' }).Count -gt 0 -or $Source -eq 'All'

$customerId = $null
$logAnalyticsToken = $null
if ($needsLogAnalytics) {
    Connect-WorkshopAzureContext
    $customerId = Resolve-WorkshopWorkspaceId
    $logAnalyticsToken = Get-WorkshopLogAnalyticsToken
    Write-Stage "Log Analytics workspace $WorkspaceName ($customerId)"
}
if ($needsDefender) {
    Connect-WorkshopDefenderGraph
}

$summary = [System.Collections.Generic.List[pscustomobject]]::new()

foreach ($table in $catalog) {
    $liveTable = if ($script:LiveTableNameOverride.ContainsKey($table.Name)) { $script:LiveTableNameOverride[$table.Name] } else { $table.Name }
    $ndjsonPath = Join-Path $outputDirectory "$($table.Name).json"
    $profilePath = Join-Path $profileDirectory "$($table.Name).profile.json"

    if ($SkipExisting -and (Test-Path $ndjsonPath)) {
        Write-Host "  $($table.Name): skipped (already exported)"
        continue
    }

    $query = "$liveTable`n| take $MaxRowsPerTable"
    $fallbackSource = if ($table.PreferredSource -eq 'LogAnalytics') { 'DefenderXdr' } else { 'LogAnalytics' }
    $order = @($table.PreferredSource, $fallbackSource)
    if ($Source -ne 'All') {
        $order = @($Source)
    }

    $rows = @()
    $resolvedSource = 'None'
    $lastError = ''

    foreach ($candidate in $order) {
        try {
            if ($candidate -eq 'LogAnalytics') {
                if ($null -eq $customerId) {
                    Connect-WorkshopAzureContext
                    $customerId = Resolve-WorkshopWorkspaceId
                    $logAnalyticsToken = Get-WorkshopLogAnalyticsToken
                }
                $rows = @(Invoke-WorkshopLogAnalyticsQuery -Query $query -CustomerId $customerId -AccessToken $logAnalyticsToken)
            }
            else {
                Connect-WorkshopDefenderGraph
                $rows = @(Invoke-WorkshopDefenderQuery -Query $query)
            }
        }
        catch {
            $lastError = $_.Exception.Message
            $rows = @()
        }

        if ($rows.Count -gt 0) {
            $resolvedSource = $candidate
            break
        }
    }

    if ($rows.Count -eq 0) {
        Write-Host "  $($table.Name): no rows on any source. $lastError" -ForegroundColor DarkYellow
        $summary.Add([pscustomobject]@{
                TableName = $table.Name
                LiveTable = $liveTable
                Source    = 'None'
                RowCount  = 0
                Status    = if ($lastError) { 'Error' } else { 'NoRows' }
                Detail    = $lastError
            })
        continue
    }

    $rows = @(foreach ($row in $rows) { ConvertTo-WorkshopNormalizedRow -Row $row })

    try {
        if (-not $ProfileOnly) {
            Write-WorkshopNdjson -Path $ndjsonPath -Rows $rows
        }

        $tableProfile = New-WorkshopTableProfile -Table $table.Name -LiveTable $liveTable -ResolvedSource $resolvedSource -Rows $rows
        $tableProfile | ConvertTo-Json -Depth 12 | Set-Content -Path $profilePath -Encoding utf8
    }
    catch {
        Write-Host "  $($table.Name): profiling failed. $($_.Exception.Message)" -ForegroundColor Red
        $summary.Add([pscustomobject]@{
                TableName = $table.Name
                LiveTable = $liveTable
                Source    = $resolvedSource
                RowCount  = $rows.Count
                Status    = 'ProfileError'
                Detail    = $_.Exception.Message
            })
        continue
    }

    Write-Host "  $($table.Name): $($rows.Count) row(s), $($tableProfile.columnCount) column(s) from $resolvedSource"
    $summary.Add([pscustomobject]@{
            TableName = $table.Name
            LiveTable = $liveTable
            Source    = $resolvedSource
            RowCount  = $rows.Count
            Status    = 'Exported'
            Detail    = "$($tableProfile.columnCount) columns"
        })
}

$summaryPath = Join-Path $outputDirectory '_export-summary.json'
[ordered]@{
    capturedUtc     = (Get-Date).ToUniversalTime().ToString('o')
    dtg             = $Dtg
    workspaceName   = $WorkspaceName
    workspaceId     = $customerId
    lookbackDays    = $LookbackDays
    maxRowsPerTable = $MaxRowsPerTable
    tableCount      = $summary.Count
    exportedCount   = @($summary | Where-Object { $_.Status -eq 'Exported' }).Count
    tables          = @($summary)
} | ConvertTo-Json -Depth 8 | Set-Content -Path $summaryPath -Encoding utf8

Write-Stage "Export summary written to $summaryPath"
$summary | Sort-Object Status, TableName | Format-Table -AutoSize
