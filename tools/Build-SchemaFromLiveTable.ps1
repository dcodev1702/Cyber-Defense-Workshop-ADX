<#
.SYNOPSIS
Generates repository table schema JSON from a live Microsoft Defender XDR or Log Analytics table.

.DESCRIPTION
Complements tools\Build-SchemasFromMicrosoftLearn.ps1 for tables that are not yet
documented on Microsoft Learn, or whose published documentation lags the live schema.

Runs "<Table> | getschema" against the requested surface and writes a schema file that
matches the shape produced by the Microsoft Learn builder, including the ADX JSON
ingestion mapping name. When a field profile produced by
scripts\Export-TenantTelemetrySamples.ps1 is available, the most common observed value
for each column is recorded in the column description so the synthetic generator and
schema reviewers can see real value shapes at a glance.

Defender advanced hunting access uses Microsoft Graph with the ThreatHunting.Read.All
delegated scope through interactive browser sign-in. Device code authentication is
never used.

.EXAMPLE
.\tools\Build-SchemaFromLiveTable.ps1 -TableName AgentsInfo, StorageBlobLogs, IntuneDevices

.EXAMPLE
.\tools\Build-SchemaFromLiveTable.ps1 -TableName SigninLogs -Source LogAnalytics -Force

.NOTES
Name: Build-SchemaFromLiveTable.ps1
Date: 2026-07-24
Authors: dcodev1702 and GitHub Copilot
Dependencies: PowerShell 7, Microsoft.Graph.Authentication, Az.Accounts, Az.OperationalInsights.
Key commands: Connect-MgGraph, Invoke-MgGraphRequest, Get-AzAccessToken, Invoke-RestMethod.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$TableName,
    [ValidateSet('DefenderXdr', 'LogAnalytics')]
    [string]$Source = 'DefenderXdr',
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..' 'schemas'),
    [string]$ManifestPath = (Join-Path $PSScriptRoot '..' 'metadata' 'tables.manifest.json'),
    [string]$FieldProfileDirectory,
    [string]$WorkspaceName = 'DIBSecCom',
    [string]$ResourceGroupName = 'sentinel',
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# One definition of "this looks like live tenant data", shared with the field
# profile gate. Without it this script embeds observed values into every schema
# description, which is how tenant identifiers reached 17 files under schemas/.
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts' 'WorkshopSensitiveContent.ps1')

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "PowerShell 7 or later is required. Detected $($PSVersionTable.PSVersion)."
}

# Curated metadata for the tables this repository adds beyond the Microsoft Learn set.
$script:TableMetadata = @{
    AgentsInfo      = [ordered]@{
        categories    = @('Agent', 'AI', 'DefenderXDR')
        sourceProduct = 'Microsoft Defender XDR'
        sourceUrl     = 'https://learn.microsoft.com/defender-xdr/advanced-hunting-agentsinfo-table'
        summary       = 'Inventory of AI agents discovered in the tenant, including owner, platform, and risk posture.'
    }
    StorageBlobLogs = [ordered]@{
        categories    = @('AzureStorage', 'CloudResource', 'AzureMonitor', 'DefenderXDR')
        sourceProduct = 'Azure Storage'
        sourceUrl     = 'https://learn.microsoft.com/azure/azure-monitor/reference/tables/storagebloblogs'
        summary       = 'Azure Storage blob service diagnostic operations used to hunt cloud data access and exfiltration.'
    }
    IntuneDevices   = [ordered]@{
        categories    = @('Intune', 'DeviceManagement', 'DefenderXDR')
        sourceProduct = 'Microsoft Intune'
        sourceUrl     = 'https://learn.microsoft.com/defender-xdr/advanced-hunting-intunedevices-table'
        summary       = 'Microsoft Intune managed device inventory, enrollment state, ownership, and compliance posture.'
    }
    ThreatIntelIndicators = [ordered]@{
        categories    = @('ThreatIntelligence', 'AzureMonitor', 'Sentinel')
        sourceProduct = 'Microsoft Sentinel'
        sourceUrl     = 'https://learn.microsoft.com/azure/azure-monitor/reference/tables/threatintelindicators'
        summary       = 'Current Microsoft Sentinel threat intelligence indicators in STIX 2.1 shape, used to join indicators to observed telemetry.'
    }
    SecurityAlert   = [ordered]@{
        categories    = @('Alert', 'AzureMonitor', 'Sentinel')
        sourceProduct = 'Microsoft Sentinel'
        sourceUrl     = 'https://learn.microsoft.com/azure/azure-monitor/reference/tables/securityalert'
        summary       = 'Microsoft Sentinel analytics rule and connected product alerts that pair with the SecurityIncident queue.'
    }
    AzureActivity   = [ordered]@{
        categories    = @('CloudResource', 'ControlPlane', 'AzureMonitor')
        sourceProduct = 'Azure Activity Log'
        sourceUrl     = 'https://learn.microsoft.com/azure/azure-monitor/reference/tables/azureactivity'
        summary       = 'Azure Resource Manager control plane operations used to hunt cloud pivots that follow identity compromise.'
    }
    ASimDnsActivityLogs = [ordered]@{
        categories    = @('Network', 'Dns', 'AzureMonitor', 'Asim')
        sourceProduct = 'Microsoft Sentinel ASIM'
        sourceUrl     = 'https://learn.microsoft.com/azure/azure-monitor/reference/tables/asimdnsactivitylogs'
        summary       = 'Normalized ASIM DNS activity used to hunt command and control resolution and to teach schema normalization.'
    }
    OfficeActivity  = [ordered]@{
        categories    = @('Office365', 'CloudApp', 'AzureMonitor')
        sourceProduct = 'Microsoft 365'
        sourceUrl     = 'https://learn.microsoft.com/azure/azure-monitor/reference/tables/officeactivity'
        summary       = 'Exchange, SharePoint, and Teams workload operations that corroborate mailbox and file collection activity.'
    }
    CloudAuditEvents = [ordered]@{
        categories    = @('CloudResource', 'ControlPlane', 'DefenderXDR')
        sourceProduct = 'Microsoft Defender XDR'
        sourceUrl     = 'https://learn.microsoft.com/defender-xdr/advanced-hunting-cloudauditevents-table'
        summary       = 'Multicloud control plane audit events across Azure, AWS, and GCP surfaced through Defender for Cloud.'
    }
    ExposureGraphNodes = [ordered]@{
        categories    = @('ExposureManagement', 'AttackPath', 'DefenderXDR')
        sourceProduct = 'Microsoft Security Exposure Management'
        sourceUrl     = 'https://learn.microsoft.com/defender-xdr/advanced-hunting-exposuregraphnodes-table'
        summary       = 'Assets in the enterprise exposure graph, used with ExposureGraphEdges for attack path analysis.'
    }
    ExposureGraphEdges = [ordered]@{
        categories    = @('ExposureManagement', 'AttackPath', 'DefenderXDR')
        sourceProduct = 'Microsoft Security Exposure Management'
        sourceUrl     = 'https://learn.microsoft.com/defender-xdr/advanced-hunting-exposuregraphedges-table'
        summary       = 'Relationships between exposure graph nodes that describe how an attacker can traverse the estate.'
    }
    CloudStorageAggregatedEvents = [ordered]@{
        categories    = @('CloudResource', 'AzureStorage', 'DefenderXDR')
        sourceProduct = 'Microsoft Defender for Cloud'
        sourceUrl     = 'https://learn.microsoft.com/defender-xdr/advanced-hunting-cloudstorageaggregatedevents-table'
        summary       = 'Aggregated cloud storage object operations used to detect bulk collection and exfiltration.'
    }
    BehaviorAnalytics = [ordered]@{
        categories    = @('Ueba', 'Identity', 'AzureMonitor', 'Sentinel')
        sourceProduct = 'Microsoft Sentinel UEBA'
        sourceUrl     = 'https://learn.microsoft.com/azure/azure-monitor/reference/tables/behavioranalytics'
        summary       = 'User and entity behavior analytics scoring that ranks activity against learned baselines.'
    }
    UserPeerAnalytics = [ordered]@{
        categories    = @('Ueba', 'Identity', 'AzureMonitor', 'Sentinel')
        sourceProduct = 'Microsoft Sentinel UEBA'
        sourceUrl     = 'https://learn.microsoft.com/azure/azure-monitor/reference/tables/userpeeranalytics'
        summary       = 'Peer group ranking for each user, used to judge whether an action is unusual for their cohort.'
    }
    IntuneDeviceComplianceOrg = [ordered]@{
        categories    = @('Intune', 'DeviceManagement', 'AzureMonitor')
        sourceProduct = 'Microsoft Intune'
        sourceUrl     = 'https://learn.microsoft.com/azure/azure-monitor/reference/tables/intunedevicecomplianceorg'
        summary       = 'Organization-wide Intune device compliance state, used to explain conditional access outcomes.'
    }
    MicrosoftServicePrincipalSignInLogs = [ordered]@{
        categories    = @('Identity', 'ServicePrincipal', 'AzureMonitor', 'EntraID')
        sourceProduct = 'Microsoft Entra ID'
        sourceUrl     = 'https://learn.microsoft.com/azure/azure-monitor/reference/tables/microsoftserviceprincipalsigninlogs'
        summary       = 'Service principal sign-in activity, the current table for app-only authentication hunting.'
    }
    AADGraphActivityLogs = [ordered]@{
        categories    = @('Identity', 'Graph', 'AzureMonitor', 'EntraID')
        sourceProduct = 'Microsoft Entra ID'
        sourceUrl     = 'https://learn.microsoft.com/azure/azure-monitor/reference/tables/aadgraphactivitylogs'
        summary       = 'Legacy Azure AD Graph API request telemetry, still abused for directory enumeration.'
    }
    AADRiskyUsers = [ordered]@{
        categories    = @('Identity', 'IdentityProtection', 'AzureMonitor', 'EntraID')
        sourceProduct = 'Microsoft Entra ID Protection'
        sourceUrl     = 'https://learn.microsoft.com/azure/azure-monitor/reference/tables/aadriskyusers'
        summary       = 'Current risk state per user, giving risk a timeline rather than a single detection event.'
    }
    SentinelHealth = [ordered]@{
        categories    = @('Operations', 'AzureMonitor', 'Sentinel')
        sourceProduct = 'Microsoft Sentinel'
        sourceUrl     = 'https://learn.microsoft.com/azure/azure-monitor/reference/tables/sentinelhealth'
        summary       = 'Sentinel connector and analytics rule health, used to teach detection blind spots.'
    }
    AzureDiagnostics = [ordered]@{
        categories    = @('CloudResource', 'Diagnostics', 'AzureMonitor')
        sourceProduct = 'Azure Monitor'
        sourceUrl     = 'https://learn.microsoft.com/azure/azure-monitor/reference/tables/azurediagnostics'
        summary       = 'Multi-resource Azure diagnostic logs covering Key Vault, network security groups, and more.'
    }
    Heartbeat = [ordered]@{
        categories    = @('Operations', 'AzureMonitor')
        sourceProduct = 'Azure Monitor Agent'
        sourceUrl     = 'https://learn.microsoft.com/azure/azure-monitor/reference/tables/heartbeat'
        summary       = 'Agent check-in records used to find monitoring coverage gaps across the fleet.'
    }
    AADRiskyServicePrincipals = [ordered]@{
        categories    = @('Identity', 'ServicePrincipal', 'IdentityProtection', 'EntraID')
        sourceProduct = 'Microsoft Entra ID Protection'
        sourceUrl     = 'https://learn.microsoft.com/azure/azure-monitor/reference/tables/aadriskyserviceprincipals'
        summary       = 'Risk state for service principals, directly on scenario for the compromised OAuth application.'
    }
    AADServicePrincipalRiskEvents = [ordered]@{
        categories    = @('Identity', 'ServicePrincipal', 'IdentityProtection', 'EntraID')
        sourceProduct = 'Microsoft Entra ID Protection'
        sourceUrl     = 'https://learn.microsoft.com/azure/azure-monitor/reference/tables/aadserviceprincipalriskevents'
        summary       = 'Individual risk detections raised against service principals.'
    }
}

function ConvertTo-WorkshopColumnType {
    param([Parameter(Mandatory)][string]$KustoType)

    switch -Regex ($KustoType.ToLowerInvariant()) {
        '^system\.string$|^string$' { 'string'; break }
        '^system\.datetime$|^datetime$' { 'datetime'; break }
        '^system\.boolean$|^bool$|^boolean$' { 'bool'; break }
        '^system\.int32$|^int$' { 'int'; break }
        '^system\.int64$|^long$' { 'long'; break }
        '^system\.double$|^real$|^double$' { 'real'; break }
        '^system\.decimal$|^decimal$' { 'decimal'; break }
        '^system\.guid$|^guid$' { 'guid'; break }
        '^system\.object$|^dynamic$' { 'dynamic'; break }
        '^system\.sbyte$' { 'bool'; break }
        default { 'string' }
    }
}

function Get-WorkshopLiveSchema {
    param([Parameter(Mandatory)][string]$Table)

    $query = "$Table`n| getschema`n| project ColumnName, ColumnType, ColumnOrdinal`n| order by ColumnOrdinal asc"

    if ($Source -eq 'DefenderXdr') {
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if ($null -eq $context -or @($context.Scopes) -notcontains 'ThreatHunting.Read.All') {
            Connect-MgGraph -Scopes 'ThreatHunting.Read.All' -NoWelcome
        }
        $response = Invoke-MgGraphRequest -Method POST `
            -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' `
            -Body (@{ Query = $query } | ConvertTo-Json -Depth 4) `
            -ContentType 'application/json' `
            -OutputType PSObject
        return @($response.results | ForEach-Object {
                [pscustomobject]@{ ColumnName = [string]$_.ColumnName; ColumnType = [string]$_.ColumnType }
            })
    }

    if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
        Connect-AzAccount | Out-Null
    }
    $workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName
    $secureToken = Get-AzAccessToken -ResourceUrl 'https://api.loganalytics.io' -AsSecureString
    $accessToken = [System.Net.NetworkCredential]::new('', $secureToken.Token).Password
    $response = Invoke-RestMethod -Method Post `
        -Uri "https://api.loganalytics.io/v1/workspaces/$($workspace.CustomerId)/query" `
        -Headers @{ Authorization = "Bearer $accessToken"; 'Content-Type' = 'application/json' } `
        -Body (@{ query = $query } | ConvertTo-Json -Depth 4) `
        -TimeoutSec 180

    $table0 = @($response.tables)[0]
    $names = @($table0.columns.name)
    $nameIndex = $names.IndexOf('ColumnName')
    $typeIndex = $names.IndexOf('ColumnType')
    return @($table0.rows | ForEach-Object {
            [pscustomobject]@{ ColumnName = [string]$_[$nameIndex]; ColumnType = [string]$_[$typeIndex] }
        })
}

function Get-WorkshopFieldProfile {
    param([Parameter(Mandatory)][string]$Table)

    if ([string]::IsNullOrWhiteSpace($FieldProfileDirectory)) {
        $sampleRoot = Join-Path $PSScriptRoot '..' 'sample'
        if (-not (Test-Path $sampleRoot)) { return $null }
        $latest = Get-ChildItem -Path $sampleRoot -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^\d{8}T\d{6}Z$' } |
            Sort-Object Name -Descending |
            Select-Object -First 1
        if ($null -eq $latest) { return $null }
        $FieldProfileDirectory = Join-Path $latest.FullName '_field-profiles'
    }

    $path = Join-Path $FieldProfileDirectory "$Table.profile.json"
    if (-not (Test-Path $path)) { return $null }
    return Get-Content -Path $path -Raw | ConvertFrom-Json
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$manifest = [System.Collections.Generic.List[object]]::new()
if (Test-Path $ManifestPath) {
    foreach ($entry in @(Get-Content -Path $ManifestPath -Raw | ConvertFrom-Json)) {
        $manifest.Add($entry)
    }
}
$manifestChanged = $false

foreach ($table in $TableName) {
    $schemaPath = Join-Path $OutputDirectory "$table.schema.json"
    if ((Test-Path $schemaPath) -and -not $Force) {
        Write-Host "$table : schema already exists. Use -Force to regenerate." -ForegroundColor DarkYellow
        continue
    }

    Write-Host "Reading live schema for $table from $Source"
    $liveColumns = @(Get-WorkshopLiveSchema -Table $table)
    if ($liveColumns.Count -eq 0) {
        Write-Host "$table : no schema returned. Skipping." -ForegroundColor Red
        continue
    }

    $fieldProfile = Get-WorkshopFieldProfile -Table $table
    $profileByColumn = @{}
    if ($null -ne $fieldProfile) {
        foreach ($column in @($fieldProfile.columns)) {
            $profileByColumn[[string]$column.name] = $column
        }
    }

    $metadata = if ($script:TableMetadata.ContainsKey($table)) {
        $script:TableMetadata[$table]
    }
    elseif ($Source -eq 'LogAnalytics') {
        # Azure Monitor tables must carry the AzureMonitor category so
        # Export-TenantTelemetrySamples.ps1 routes them to Log Analytics.
        [ordered]@{
            categories    = @('AzureMonitor')
            sourceProduct = 'Azure Monitor'
            sourceUrl     = "https://learn.microsoft.com/azure/azure-monitor/reference/tables/$($table.ToLowerInvariant())"
            summary       = "Live schema captured from the $table table in Log Analytics."
        }
    }
    else {
        [ordered]@{
            categories    = @('DefenderXDR')
            sourceProduct = 'Microsoft Defender XDR'
            sourceUrl     = "https://learn.microsoft.com/defender-xdr/advanced-hunting-$($table.ToLowerInvariant())-table"
            summary       = "Live schema captured from the $table table."
        }
    }

    $columns = foreach ($liveColumn in $liveColumns) {
        $description = "Column captured from the live $table schema."
        $observed = $profileByColumn[$liveColumn.ColumnName]
        if ($null -ne $observed) {
            # Set-StrictMode Latest turns out-of-bounds indexing into a terminating
            # error, so the count must be checked before indexing topValues.
            $topValues = @($observed.topValues)
            $sample = if ($topValues.Count -gt 0) { [string]$topValues[0].value } else { '' }

            # The sample is a real value out of live tenant telemetry, and this line
            # is how the tenant GUID, the Security subscription and the DIBSecCom
            # workspace id reached 17 tracked files under schemas/. The cardinality is
            # the useful part of the description; the literal value is not worth the
            # exposure, so anything matching a tenant-data indicator is dropped.
            $indicator = Test-WorkshopSensitiveContent -Value $sample
            if ($indicator) {
                Write-Verbose ("Suppressed {0}.{1} sample ({2}) from the schema description." -f $table, $liveColumn.ColumnName, $indicator)
                $sample = ''
            }

            if (-not [string]::IsNullOrWhiteSpace($sample)) {
                if ($sample.Length -gt 80) { $sample = $sample.Substring(0, 80) + '...' }
                $description = "Live $table column. Distinct values observed: $($observed.distinctCount). Most common: $sample"
            }
            else {
                $description = "Live $table column. Distinct values observed: $($observed.distinctCount)."
            }
        }

        [ordered]@{
            name        = [string]$liveColumn.ColumnName
            type        = ConvertTo-WorkshopColumnType -KustoType $liveColumn.ColumnType
            sourceType  = [string]$liveColumn.ColumnType
            description = $description
        }
    }

    [ordered]@{
        tableName     = $table
        categories    = @($metadata.categories)
        sourceProduct = [string]$metadata.sourceProduct
        sourceUrl     = [string]$metadata.sourceUrl
        schemaSource  = "Live $Source getschema"
        summary       = [string]$metadata.summary
        columns       = @($columns)
        adx           = [ordered]@{ mappingName = "$($table)_JsonMapping" }
    } | ConvertTo-Json -Depth 8 | Set-Content -Path $schemaPath -Encoding utf8

    Write-Host "  wrote $schemaPath ($($columns.Count) columns)"

    if (-not ($manifest | Where-Object { [string]$_.name -eq $table })) {
        $manifest.Add([pscustomobject][ordered]@{
                name          = $table
                categories    = @($metadata.categories)
                sourceProduct = [string]$metadata.sourceProduct
                sourceUrl     = [string]$metadata.sourceUrl
            })
        $manifestChanged = $true
        Write-Host "  added $table to the table manifest"
    }
}

if ($manifestChanged) {
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -Path $ManifestPath -Encoding utf8
    Write-Host "Updated $ManifestPath"
}
