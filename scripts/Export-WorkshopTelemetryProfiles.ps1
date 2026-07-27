<#
.SYNOPSIS
Builds per-column field profiles for workshop tables from real telemetry.

.DESCRIPTION
Produces metadata\field-profiles\<Table>.profile.json describing the SHAPE of
each column in real data: fill rate, cardinality, weighted value vocabulary,
detected format pattern, and numeric/length bounds. The synthetic data
generator consumes these profiles so generated rows match production.

Rows are gathered from up to three sources and merged:

  1. sample\  - curated real telemetry already on disk. Often the richest
                source (AgentsInfo has 22k rows here) and the only source for
                tables that no longer emit.
  2. Log Analytics, workspace DIBSecCom.
  3. Defender XDR advanced hunting, for tables absent from Log Analytics.
     Requires ThreatHunting.Read.All.

Telemetry age is irrelevant. A profile describes structure and the kind of
values a column holds, not recency, so a table that stopped emitting months ago
still yields a fully usable profile.

Existing files in sample\ are never overwritten unless -RefreshSamples is
passed; the curated captures on disk are treated as authoritative.

.EXAMPLE
pwsh -NoProfile -File .\scripts\Export-WorkshopTelemetryProfiles.ps1 -TableName AgentsInfo

.EXAMPLE
pwsh -NoProfile -File .\scripts\Export-WorkshopTelemetryProfiles.ps1 -LocalOnly

.NOTES
Requires PowerShell 7. Live sourcing needs Azure CLI signed in to the Security
subscription and Microsoft.Graph.Authentication for the XDR path.
#>
#Requires -Version 7
[CmdletBinding()]
param(
    [string[]]$TableName,
    [int]$RowLimit = 5000,
    [int]$MaxProfileRows = 20000,
    [int]$LookbackDays = 90,
    [int]$TopValueCount = 30,
    [int]$SampleRowCap = 2000,
    [string]$WorkspaceId = '7e9298ab-22e6-4a82-a53e-c5ed7faee977',
    [string]$ManifestPath = (Join-Path $PSScriptRoot '..' 'metadata' 'tables.manifest.json'),
    [string]$SampleDirectory = (Join-Path $PSScriptRoot '..' 'sample'),
    [string]$ProfileDirectory = (Join-Path $PSScriptRoot '..' 'metadata' 'field-profiles'),
    [switch]$LocalOnly,
    [switch]$RefreshSamples,
    [switch]$SkipExistingProfiles
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Sample files whose name does not derive from the table name.
$SampleAlias = @{
    'AADUserRiskEvents' = 'AADRiskUserEvents.csv'
    'DeviceFileEvents'  = 'New query (7).csv'
    'DeviceLogonEvents' = 'New query (8).csv'
}

# Columns that carry identity, host, or location data from the live tenant. Their
# shape is profiled, but their values are never captured into a vocabulary: this
# repo is public, and the generator supplies its own synthetic user, device, and
# network universe for these fields anyway.
$SensitiveColumnPattern = '(?i)(account|user|upn|email|mail|sender|recipient|subject|principal|owner|displayname|' +
                          'ip4|ip6|ipaddress|address|host|machine|devicename|deviceid|sid|objectid|' +
                          'tenant|domain|url|uri|path|filename|folder|location|city|country|latitude|longitude|' +
                          'phone|serial|asset|organization|company)'

# Free-text columns whose contents are tenant-authored rather than a product
# vocabulary. Categorical fields such as Title, Category, Severity, and
# ActionType are deliberately excluded here because their real distribution is
# exactly the signal the generator needs.
$FreeTextColumnPattern = '(?i)(instruction|description|commandline|content|message|body|script|rawagentinfo|prompt)'

# ---------------------------------------------------------------- helpers ----

function Get-LocalSamplePath {
    param([Parameter(Mandatory)][string]$Table)

    if ($SampleAlias.ContainsKey($Table)) {
        $aliased = Join-Path $SampleDirectory $SampleAlias[$Table]
        if (Test-Path -LiteralPath $aliased) { return $aliased }
    }

    # Prefer the largest matching capture; "-RealTelemetry" exports are usually
    # richer than the older short exports.
    $candidates = @(
        "$Table-RealTelemetry.csv"
        "$Table-Real.csv"
        "$Table.csv"
    ) | ForEach-Object { Join-Path $SampleDirectory $_ } | Where-Object { Test-Path -LiteralPath $_ }

    if (-not $candidates) { return $null }
    return @($candidates | Sort-Object { (Get-Item -LiteralPath $_).Length } -Descending)[0]
}

function Get-LogAnalyticsToken {
    $token = az account get-access-token --resource 'https://api.loganalytics.io' --query accessToken -o tsv 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($token)) { return $null }
    return $token.Trim()
}

function Invoke-LogAnalyticsQuery {
    param(
        [Parameter(Mandatory)][string]$Query,
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][int]$Days
    )

    $uri = "https://api.loganalytics.io/v1/workspaces/$WorkspaceId/query"
    $body = @{ query = $Query; timespan = "P$($Days)D" } | ConvertTo-Json -Depth 5
    $headers = @{ Authorization = "Bearer $Token"; 'Content-Type' = 'application/json' }

    $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body -ErrorAction Stop
    $table = @($response.tables)[0]
    if (-not $table) { return @() }

    $columns = @($table.columns.name)
    $records = foreach ($row in $table.rows) {
        $record = [ordered]@{}
        for ($i = 0; $i -lt $columns.Count; $i++) { $record[$columns[$i]] = $row[$i] }
        [pscustomobject]$record
    }
    return @($records)
}

function Invoke-XdrHuntingQuery {
    param([Parameter(Mandatory)][string]$Query)

    if (-not (Get-MgContext)) { Connect-MgGraph -Scopes 'ThreatHunting.Read.All' -NoWelcome }

    $body = @{ Query = $Query } | ConvertTo-Json -Compress
    $response = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' -Body $body
    $results = @($response.results)
    if ($results.Count -eq 0) { return @() }

    return @($results | ForEach-Object {
        $record = [ordered]@{}
        foreach ($key in $_.Keys) { $record[$key] = $_[$key] }
        [pscustomobject]$record
    })
}

function Get-ValuePattern {
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Values)

    if ($Values.Count -eq 0) { return $null }
    $probe = @($Values | Select-Object -First 60)
    $threshold = [Math]::Ceiling($probe.Count * 0.8)

    # Datetimes are checked first and by parsing rather than by regex. Sources
    # render them differently ("07/24/2026 08:10:07" from CSV vs
    # "Jul 25, 2026 4:10:03 AM" from Graph), and a low-cardinality timestamp
    # column would otherwise be captured as a literal vocabulary and replay
    # stale dates into generated data.
    $parsed = 0
    foreach ($value in $probe) {
        $dt = [datetime]::MinValue
        if ([datetime]::TryParse($value, [cultureinfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$dt)) {
            $parsed++
        }
    }
    if ($parsed -ge $threshold) { return 'datetime' }

    $tests = [ordered]@{
        guid    = '^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$'
        sha256  = '^[0-9a-fA-F]{64}$'
        sha1    = '^[0-9a-fA-F]{40}$'
        md5     = '^[0-9a-fA-F]{32}$'
        sid     = '^S-\d-\d+(-\d+)+$'
        ipv4    = '^\d{1,3}(\.\d{1,3}){3}$'
        upn     = '^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$'
        url     = '^https?://'
        winpath = '^[a-zA-Z]:\\'
        posix   = '^/(etc|usr|var|opt|tmp|home|u01)/'
        json    = '^\s*[\{\[]'
    }

    foreach ($name in $tests.Keys) {
        $hits = @($probe | Where-Object { $_ -match $tests[$name] }).Count
        if ($hits -ge $threshold) { return $name }
    }
    return $null
}

function Get-RowSetColumns {
    <#
        Rows are ragged: Graph returns a per-row dictionary, so a property may be
        absent on some rows entirely. Take the union across a probe of rows and
        drop OData annotations, which are transport artifacts rather than schema.

        Returns both the normalised column set and a map back to the actual
        property name, because Azure portal CSV exports rename datetime columns
        to "TimeGenerated [UTC]" and would otherwise create a phantom column.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows)

    $map = [ordered]@{}
    foreach ($row in @($Rows | Select-Object -First 200)) {
        foreach ($property in $row.PSObject.Properties.Name) {
            if ($property -like '*@odata*') { continue }
            $normalized = ($property -replace '\s*\[UTC\]$', '').Trim()
            if (-not $map.Contains($normalized)) { $map[$normalized] = $property }
        }
    }

    return [pscustomobject]@{
        Columns = @($map.Keys)
        Map     = $map
    }
}

function Test-SensitiveContent {
    <#
        Content-based safety net for value vocabularies. Column-name matching alone
        misses fields such as SourceAgentId, which in real data carries Azure
        resource IDs embedding a live subscription GUID. Any vocabulary containing a
        GUID, a resource path, a UPN, an address, or a credential is suppressed
        regardless of the column name.

        Kept deliberately in step with scripts\Test-FieldProfileSafety.ps1.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Values,
        [string]$ColumnName = ''
    )

    $indicators = @(
        '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'  # any embedded GUID
        '(?i)/subscriptions/'
        '(?i)/resourcegroups/'
        '(?i)/tenants/'
        '(?i)\.onmicrosoft\.com'
        '(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}'                                     # any embedded UPN
        '(?i)(bearer\s+[a-z0-9._-]{8,}|eyJ[a-zA-Z0-9._-]{10,})'                         # bearer token or JWT
        '\b[0-9a-fA-F]{32,}\b'                                                          # long hex, hashes and keys
    )

    # Version strings such as 4.83.1.0 are shaped like an address, so the IPv4 test
    # is skipped for version columns rather than discarding a useful vocabulary.
    if ($ColumnName -notmatch '(?i)version') {
        $indicators += '\b\d{1,3}(\.\d{1,3}){3}\b'
    }

    foreach ($value in $Values) {
        foreach ($indicator in $indicators) {
            if ($value -match $indicator) { return $true }
        }
    }
    return $false
}

function ConvertTo-ProfileValueText {
    <#
        Renders a cell the way the column actually holds it.

        `[string]` on a nested object or array yields "System.Collections.Hashtable"
        or "System.Object[]" -- the name of a CLR type, not a value -- and Export-Csv
        does exactly the same when it writes the sample cache. Every dynamic column
        that went through that cache was therefore replaced by a type name, and the
        next run read it back and recorded it as the column's entire vocabulary.

        Complex values become compact JSON, which is what the column holds, what the
        generator emits, and what survives a CSV round trip. Scalars keep their
        existing rendering so no profile changes shape for no reason.
    #>
    param($Value)

    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [ValueType]) { return [string]$Value }

    $json = ConvertTo-Json -InputObject $Value -Compress -Depth 12
    # An empty bag or array is an unpopulated cell, not the literal text "[]".
    if ($json -in @('[]', '{}', 'null')) { return '' }
    return $json
}

function New-ColumnProfile {
    <#
        Values are gathered only from row sets that actually declare the column,
        so a column present in one source is not penalised by rows from another
        source that never had it.
    #>
    param(
        [Parameter(Mandatory)][string]$Column,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$RowSets
    )

    $values = [System.Collections.Generic.List[object]]::new()
    $considered = 0

    foreach ($set in $RowSets) {
        if ($set.Columns -notcontains $Column) { continue }
        $actual = $set.Map[$Column]
        $considered += $set.Rows.Count
        foreach ($row in $set.Rows) {
            # Property may be absent on an individual row; StrictMode makes
            # direct access throw, so resolve through the property bag.
            $property = $row.PSObject.Properties[$actual]
            if ($property) { $values.Add($property.Value) }
        }
    }

    # Rendered in a loop rather than a pipeline: emitting an array to the pipeline
    # unrolls it, which would scatter one dynamic cell across several vocabulary
    # entries and inflate the fill count.
    $present = [System.Collections.Generic.List[object]]::new()
    $strings = [System.Collections.Generic.List[string]]::new()
    foreach ($value in $values) {
        if ($null -eq $value) { continue }
        $text = ConvertTo-ProfileValueText -Value $value
        if ($text -match '^\s*$') { continue }
        $present.Add($value)
        $strings.Add($text)
    }
    $denominator = [Math]::Max($considered, 1)

    $result = [ordered]@{
        fillRate      = [Math]::Round($present.Count / $denominator, 4)
        distinctCount = 0
        topValues     = @()
        pattern       = $null
    }

    if ($present.Count -eq 0) {
        # Empty in production too. Recorded explicitly so the generator leaves
        # the column blank by design rather than by oversight.
        $result.alwaysEmpty = $true
        return $result
    }

    $groups = @($strings | Group-Object | Sort-Object Count -Descending)
    $result.distinctCount = $groups.Count
    $result.pattern = Get-ValuePattern -Values @($strings)

    # Carry an explicit vocabulary only for low-cardinality categorical columns.
    # High cardinality values are regenerated from their pattern instead, and
    # identity, host, or tenant-authored free text is never captured verbatim.
    $isSensitive = $Column -match $SensitiveColumnPattern
    $isFreeText = $Column -match $FreeTextColumnPattern
    if ($isSensitive) { $result.sensitive = $true }
    if ($isFreeText) { $result.freeText = $true }

    # A 'json' pattern alone is not a reason to drop the vocabulary. The pattern
    # tests exist to stop high-cardinality structured identifiers -- guids, hashes,
    # paths, timestamps -- being replayed literally, but a dynamic column holding a
    # small set of category tuples is a real enumeration, and the vocabulary is the
    # only thing that makes such a column checkable at all. The cardinality bound
    # below still keeps genuine property bags out.
    $patternBlocksVocabulary = $result.pattern -and $result.pattern -ne 'json'

    if ($groups.Count -le 200 -and -not $patternBlocksVocabulary -and -not $isSensitive -and -not $isFreeText) {
        $candidate = @(
            $groups | Select-Object -First $TopValueCount | ForEach-Object {
                [ordered]@{ value = $_.Name; weight = [Math]::Round($_.Count / $present.Count, 5) }
            }
        )

        if (Test-SensitiveContent -Values @($candidate | ForEach-Object { [string]$_.value }) -ColumnName $Column) {
            $result.sensitive = $true
        }
        else {
            $result.topValues = $candidate
        }
    }

    $lengths = @($strings | ForEach-Object { $_.Length })
    $lengthStats = $lengths | Measure-Object -Minimum -Maximum
    $result.minLength = $lengthStats.Minimum
    $result.maxLength = $lengthStats.Maximum

    $numeric = @($present | Where-Object { $_ -is [int] -or $_ -is [long] -or $_ -is [double] -or $_ -is [decimal] })
    if ($numeric.Count -gt 0 -and $numeric.Count -eq $present.Count) {
        $stats = $numeric | Measure-Object -Minimum -Maximum -Average
        $result.numericMin = $stats.Minimum
        $result.numericMax = $stats.Maximum
        $result.numericAvg = [Math]::Round($stats.Average, 3)
    }

    return $result
}

# ------------------------------------------------------------------ main ----

if (-not (Test-Path $ManifestPath)) { throw "Manifest not found: $ManifestPath" }
$tables = @((Get-Content -Raw $ManifestPath | ConvertFrom-Json) | ForEach-Object { $_.name })

if ($TableName) {
    # pwsh -File passes arguments as literal strings, so "A,B,C" arrives as one
    # element. Split it back out so -File and -Command behave identically.
    $requested = @($TableName | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $unknown = @($requested | Where-Object { $tables -notcontains $_ })
    if ($unknown) { throw ("Not in manifest: {0}" -f ($unknown -join ', ')) }
    $tables = @($tables | Where-Object { $requested -contains $_ })
}
if (-not $tables) { throw 'No tables selected.' }

New-Item -ItemType Directory -Path $SampleDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $ProfileDirectory -Force | Out-Null

$laToken = $null
if (-not $LocalOnly) {
    $laToken = Get-LogAnalyticsToken
    if (-not $laToken) { Write-Warning 'No Log Analytics token; using local samples and XDR only.' }
}

$summary = [System.Collections.Generic.List[object]]::new()
$index = 0

foreach ($table in $tables) {
    $index++
    $profilePath = Join-Path $ProfileDirectory "$table.profile.json"
    if ($SkipExistingProfiles -and (Test-Path $profilePath)) {
        Write-Host ("[{0,2}/{1}] {2,-44} skipped (profile exists)" -f $index, $tables.Count, $table)
        continue
    }

    $rowSets = [System.Collections.Generic.List[object]]::new()
    $sources = [System.Collections.Generic.List[string]]::new()
    $note = $null

    # ---- source 1: curated local sample -------------------------------------
    $localPath = Get-LocalSamplePath -Table $table
    if ($localPath) {
        try {
            $localRows = @(Import-Csv -LiteralPath $localPath | Select-Object -First $MaxProfileRows)
            if ($localRows.Count -gt 0) {
                $shape = Get-RowSetColumns -Rows $localRows
                $rowSets.Add([pscustomobject]@{
                    Rows    = $localRows
                    Columns = $shape.Columns
                    Map     = $shape.Map
                })
                $sources.Add('sample:' + (Split-Path $localPath -Leaf))
            }
        }
        catch { $note = "sample read failed: $($_.Exception.Message)" }
    }

    # ---- source 2/3: live telemetry -----------------------------------------
    if (-not $LocalOnly) {
        $query = "$table | take $RowLimit"
        $liveRows = @()

        if ($laToken) {
            # Age does not matter; widen until the table yields rows so tables
            # that stopped emitting still profile correctly.
            foreach ($days in @($LookbackDays, 365, 730)) {
                try {
                    $liveRows = @(Invoke-LogAnalyticsQuery -Query $query -Token $laToken -Days $days)
                    if ($liveRows.Count -gt 0) { $sources.Add("LogAnalytics(P${days}D)"); break }
                }
                catch { $note = $_.Exception.Message; break }
            }
        }

        if ($liveRows.Count -eq 0) {
            try {
                $liveRows = @(Invoke-XdrHuntingQuery -Query $query)
                if ($liveRows.Count -gt 0) { $sources.Add('XDR'); $note = $null }
            }
            catch { if (-not $note) { $note = $_.Exception.Message } }
        }

        if ($liveRows.Count -gt 0) {
            $shape = Get-RowSetColumns -Rows $liveRows
            $rowSets.Add([pscustomobject]@{
                Rows    = $liveRows
                Columns = $shape.Columns
                Map     = $shape.Map
            })

            # Only write a sample when none exists; curated captures on disk are
            # authoritative and must not be silently truncated.
            if ($RefreshSamples -or -not $localPath) {
                $samplePath = Join-Path $SampleDirectory "$table-RealTelemetry.csv"
                # Flatten dynamic columns to JSON first. Export-Csv calls ToString()
                # on anything it does not recognise, so writing the rows straight out
                # would cache the type name and lose the value permanently.
                @($liveRows | Select-Object -First $SampleRowCap | ForEach-Object {
                    $flat = [ordered]@{}
                    foreach ($cell in $_.PSObject.Properties) {
                        $flat[$cell.Name] = ConvertTo-ProfileValueText -Value $cell.Value
                    }
                    [pscustomobject]$flat
                }) | Export-Csv -LiteralPath $samplePath -NoTypeInformation -Encoding utf8NoBOM
            }
        }
    }

    if ($rowSets.Count -eq 0) {
        Write-Host ("[{0,2}/{1}] {2,-44} NO DATA" -f $index, $tables.Count, $table) -ForegroundColor Yellow
        $summary.Add([pscustomobject]@{ Table = $table; Rows = 0; Columns = 0; EmptyInProd = 0; Sources = 'none'; Note = $note })
        continue
    }

    $allColumns = @($rowSets | ForEach-Object { $_.Columns } | Select-Object -Unique)
    $totalRows = ($rowSets | ForEach-Object { $_.Rows.Count } | Measure-Object -Sum).Sum

    $columnProfiles = [ordered]@{}
    foreach ($column in $allColumns) {
        $columnProfiles[$column] = New-ColumnProfile -Column $column -RowSets @($rowSets)
    }

    $emptyInProd = @($allColumns | Where-Object { $columnProfiles[$_].Contains('alwaysEmpty') })

    ([ordered]@{
        tableName    = $table
        sources      = @($sources)
        sampledRows  = $totalRows
        columnCount  = $allColumns.Count
        emptyInProd  = @($emptyInProd)
        generatedUtc = (Get-Date).ToUniversalTime().ToString('o')
        columns      = $columnProfiles
    } | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $profilePath -Encoding utf8NoBOM

    Write-Host ("[{0,2}/{1}] {2,-44} {3,6} rows {4,3} cols {5,3} empty-in-prod   {6}" -f `
        $index, $tables.Count, $table, $totalRows, $allColumns.Count, $emptyInProd.Count, ($sources -join ' + '))

    $summary.Add([pscustomobject]@{
        Table       = $table
        Rows        = $totalRows
        Columns     = $allColumns.Count
        EmptyInProd = $emptyInProd.Count
        Sources     = ($sources -join ' + ')
        Note        = $note
    })
}

Write-Host ''
$withData = @($summary | Where-Object { $_.Rows -gt 0 })
Write-Host ("Profiled {0} of {1} table(s)." -f $withData.Count, $summary.Count) -ForegroundColor Cyan

$noData = @($summary | Where-Object { $_.Rows -eq 0 })
if ($noData.Count -gt 0) {
    Write-Host ("No data for {0}:" -f $noData.Count) -ForegroundColor Yellow
    $noData | ForEach-Object { Write-Host ("  {0,-44} {1}" -f $_.Table, $_.Note) }
}
Write-Host ("Profiles written to {0}" -f (Resolve-Path $ProfileDirectory))
