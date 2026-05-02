<#
.SYNOPSIS
Creates the importable Azure Data Explorer dashboard for the cyber defense workshop.

.DESCRIPTION
Builds a schema-version 20 ADX dashboard JSON file and a companion KQL query pack.
The dashboard uses Microsoft Defender XDR-style workshop tables to surface SOC-style
threat protection, identity defense, sign-in, alert, network, Graph API, device
posture, and scenario investigation signals.

.EXAMPLE
.\scripts\New-WorkshopDashboard.ps1 `
  -ClusterUri 'https://dibsecadx.eastus2.kusto.windows.net' `
  -DatabaseName 'cyber-defend-q0xxzc'

.NOTES
Name: New-WorkshopDashboard.ps1
Date: 2026-05-02
Authors: dcodev1702 and GitHub Copilot CLI w/ ChatGPT 5.5
Dependencies: Azure Data Explorer web UI dashboard import; generated workshop ADX tables.
Key commands: ConvertTo-Json, Set-Content, deterministic dashboard IDs.
#>
[CmdletBinding()]
param(
    [string]$ClusterUri = 'https://dibsecadx.eastus2.kusto.windows.net',
    [string]$DatabaseName = 'cyber-defend-q0xxzc',
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\dashboards\cyber-defense-workshop-dashboard.json'),
    [string]$KqlPath = (Join-Path $PSScriptRoot '..\dashboards\cyber-defense-workshop-dashboard.kql')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-WorkshopGuid {
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

function New-BaseAxis {
    param([string]$Label = '')

    [ordered]@{
        id = '-1'
        columns = @()
        label = $Label
        yAxisMinimumValue = $null
        yAxisMaximumValue = $null
        yAxisScale = 'linear'
        horizontalLines = @()
    }
}

function New-ChartOptions {
    param([string]$YAxisLabel = '')

    [ordered]@{
        hideTileTitle = $false
        hideLegend = $false
        xColumn = [ordered]@{ type = 'infer' }
        yColumns = [ordered]@{ type = 'infer' }
        seriesColumns = [ordered]@{ type = 'infer' }
        xColumnTitle = ''
        yColumnTitle = ''
        xAxisScale = 'linear'
        yAxisScale = 'linear'
        crossFilter = $null
        crossFilterDisabled = $false
        multipleYAxes = [ordered]@{
            base = New-BaseAxis -Label $YAxisLabel
            additional = @()
        }
    }
}

function New-CardOptions {
    [ordered]@{
        hideTileTitle = $false
        multiStat__textSize = 'large'
        multiStat__displayOrientation = 'horizontal'
        multiStat__valueColumn = [ordered]@{ type = 'infer' }
    }
}

function New-TableOptions {
    [ordered]@{
        hideTileTitle = $false
        table__enableRenderLinks = $false
    }
}

function New-PieOptions {
    [ordered]@{
        hideTileTitle = $false
        hideLegend = $false
        pie__kind = 'donut'
        pie__label = @('name', 'percentage')
        pie__tooltip = @('name', 'value', 'percentage')
        pie__orderBy = 'size'
        xColumn = [ordered]@{ type = 'infer' }
        yColumn = [ordered]@{ type = 'infer' }
    }
}

function New-Tile {
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Query,
        [Parameter(Mandatory)][string]$PageId,
        [Parameter(Mandatory)][string]$DataSourceId,
        [Parameter(Mandatory)][string]$VisualType,
        [Parameter(Mandatory)][int]$X,
        [Parameter(Mandatory)][int]$Y,
        [Parameter(Mandatory)][int]$Width,
        [Parameter(Mandatory)][int]$Height,
        [Parameter(Mandatory)]$VisualOptions,
        [string[]]$UsedParamVariables = @('_startTime', '_endTime')
    )

    [ordered]@{
        id = New-WorkshopGuid "tile|$PageId|$Title"
        title = $Title
        query = $Query.Trim()
        dataSourceId = $DataSourceId
        visualType = $VisualType
        pageId = $PageId
        layout = [ordered]@{
            x = $X
            y = $Y
            width = $Width
            height = $Height
        }
        visualOptions = $VisualOptions
        usedParamVariables = @($UsedParamVariables)
    }
}

$outputDirectory = Split-Path -Path $OutputPath -Parent
$kqlDirectory = Split-Path -Path $KqlPath -Parent
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $kqlDirectory -Force | Out-Null

$dataSourceId = New-WorkshopGuid 'cyber-defense-workshop-dashboard|datasource'
$overviewPageId = New-WorkshopGuid 'cyber-defense-workshop-dashboard|overview'
$identityPageId = New-WorkshopGuid 'cyber-defense-workshop-dashboard|identity'
$networkPageId = New-WorkshopGuid 'cyber-defense-workshop-dashboard|network'
$timelinePageId = New-WorkshopGuid 'cyber-defense-workshop-dashboard|timeline'
$inventoryPageId = New-WorkshopGuid 'cyber-defense-workshop-dashboard|inventory'

$tiles = [System.Collections.Generic.List[object]]::new()

$totalAlertsCardQuery = @'
AlertInfo
| where Timestamp between (['_startTime'] .. ['_endTime'])
| summarize ['Total alerts']=count()
| render card
'@

$highAlertsCardQuery = @'
AlertInfo
| where Timestamp between (['_startTime'] .. ['_endTime'])
| summarize ['High alerts']=countif(Severity in~ ('High', 'Critical'))
| render card
'@

$securityIncidentsCardQuery = @'
SecurityIncident
| where TimeGenerated between (['_startTime'] .. ['_endTime'])
| summarize ['Security incidents']=count()
| render card
'@

$topSecurityIncidentsQuery = @'
SecurityIncident
| where TimeGenerated between (['_startTime'] .. ['_endTime'])
| summarize arg_max(TimeGenerated, *) by IncidentName
| extend AlertCount=coalesce(array_length(AlertIds), 0)
| project ['#']=IncidentNumber, ['Security incident name']=Title, Severity, Status, AlertCount, ProviderIncidentId, LastActivityTime, TimeGenerated
| top 20 by TimeGenerated desc
'@

$failedLoginsCardQuery = @'
let FailedLogons = union isfuzzy=true
(SigninLogs | where TimeGenerated between (['_startTime'] .. ['_endTime']) | where not(tostring(ResultType) == '0' or ResultType =~ 'Success') | project Timestamp=TimeGenerated),
(AADNonInteractiveUserSignInLogs | where TimeGenerated between (['_startTime'] .. ['_endTime']) | where not(tostring(ResultType) == '0' or ResultType =~ 'Success') | project Timestamp=TimeGenerated),
(AADServicePrincipalSignInLogs | where TimeGenerated between (['_startTime'] .. ['_endTime']) | where not(tostring(ResultType) == '0' or ResultType =~ 'Success') | project Timestamp=TimeGenerated),
(AADManagedIdentitySignInLogs | where TimeGenerated between (['_startTime'] .. ['_endTime']) | where not(tostring(ResultType) == '0' or ResultType =~ 'Success') | project Timestamp=TimeGenerated),
(DeviceLogonEvents | where Timestamp between (['_startTime'] .. ['_endTime']) | where ActionType has 'Failed' | project Timestamp),
(IdentityLogonEvents | where Timestamp between (['_startTime'] .. ['_endTime']) | where ActionType has 'Failed' | project Timestamp);
FailedLogons
| summarize ['Failed logins']=count()
| render card
'@

$successfulLoginsCardQuery = @'
let SuccessfulLogons = union isfuzzy=true
(SigninLogs | where TimeGenerated between (['_startTime'] .. ['_endTime']) | where tostring(ResultType) == '0' or ResultType =~ 'Success' | project Timestamp=TimeGenerated),
(AADNonInteractiveUserSignInLogs | where TimeGenerated between (['_startTime'] .. ['_endTime']) | where tostring(ResultType) == '0' or ResultType =~ 'Success' | project Timestamp=TimeGenerated),
(AADServicePrincipalSignInLogs | where TimeGenerated between (['_startTime'] .. ['_endTime']) | where tostring(ResultType) == '0' or ResultType =~ 'Success' | project Timestamp=TimeGenerated),
(AADManagedIdentitySignInLogs | where TimeGenerated between (['_startTime'] .. ['_endTime']) | where tostring(ResultType) == '0' or ResultType =~ 'Success' | project Timestamp=TimeGenerated),
(DeviceLogonEvents | where Timestamp between (['_startTime'] .. ['_endTime']) | where ActionType !has 'Failed' | project Timestamp),
(IdentityLogonEvents | where Timestamp between (['_startTime'] .. ['_endTime']) | where ActionType !has 'Failed' | project Timestamp);
SuccessfulLogons
| summarize ['Successful logins']=count()
| render card
'@

$usersCardQuery = @'
IdentityAccountInfo
| where TimeGenerated between (['_startTime'] .. ['_endTime'])
| summarize arg_max(TimeGenerated, *) by AccountId
| summarize Users=countif(Type =~ 'User')
| render card
'@

$serviceAccountsCardQuery = @'
IdentityAccountInfo
| where TimeGenerated between (['_startTime'] .. ['_endTime'])
| summarize arg_max(TimeGenerated, *) by AccountId
| summarize ['Service accounts']=countif(Type =~ 'ServiceAccount')
| render card
'@

$oauthGraphSuspiciousActivityCardQuery = @'
GraphApiAuditEvents
| where TimeGenerated between (['_startTime'] .. ['_endTime'])
| extend StatusCode=toint(ResponseStatusCode)
| where StatusCode >= 400 or RequestMethod in~ ('POST', 'PATCH', 'DELETE')
| summarize ['OAuth/Graph suspicious activity']=count()
| render card
'@

$publicEgressCardQuery = @'
DeviceNetworkEvents
| where TimeGenerated between (['_startTime'] .. ['_endTime'])
| where RemoteIPType == 'Public'
| summarize ['Public egress']=count()
| render card
'@

$deviceOsCategoryQuery = @'
DeviceInfo
| where TimeGenerated between (['_startTime'] .. ['_endTime'])
| summarize arg_max(TimeGenerated, *) by DeviceId
| summarize Devices=count() by OSFamily=case(OSPlatform has 'Windows', 'Windows', OSPlatform =~ 'Linux' or OSDistribution =~ 'Ubuntu', 'Linux', OSPlatform =~ 'Android', 'Android/IoT', 'Other'), DeviceCategory, DeviceType
| order by Devices desc
| render barchart with (title='Devices by OS family, category, and type')
'@

$machineGroupPostureQuery = @'
DeviceInfo
| where TimeGenerated between (['_startTime'] .. ['_endTime'])
| summarize arg_max(TimeGenerated, *) by DeviceId
| summarize Devices=count(), Onboarded=countif(OnboardingStatus == 'Onboarded'), Unsupported=countif(OnboardingStatus == 'Unsupported'), HealthySensors=countif(SensorHealthState == 'Active') by MachineGroup
| order by Devices desc
| render columnchart with (title='Device posture by machine group')
'@

$deviceInventoryQuery = @'
DeviceInfo
| where TimeGenerated between (['_startTime'] .. ['_endTime'])
| summarize arg_max(TimeGenerated, *) by DeviceId
| project DeviceName, OSPlatform, OSDistribution, OSBuild, DeviceCategory, DeviceType, MachineGroup, OnboardingStatus, SensorHealthState, ExposureLevel, PublicIP
| order by MachineGroup asc, DeviceName asc
| take 100
'@

$identitySummaryQuery = @'
IdentityAccountInfo
| where TimeGenerated between (['_startTime'] .. ['_endTime'])
| summarize arg_max(TimeGenerated, *) by AccountId
| summarize Accounts=count(), Enabled=countif(AccountStatus =~ 'Enabled'), Disabled=countif(AccountStatus =~ 'Disabled'), PrimaryAccounts=countif(IsPrimary) by Type, SourceProvider
| order by Accounts desc
| render columnchart with (title='Users and service accounts by provider')
'@

$privilegedIdentitiesQuery = @'
IdentityAccountInfo
| where TimeGenerated between (['_startTime'] .. ['_endTime'])
| extend RoleCount = coalesce(array_length(AssignedRoles), 0), GroupCount = coalesce(array_length(GroupMembership), 0)
| where RoleCount > 0 or CriticalityLevel >= 8 or DefenderRiskLevel >= 5
| project DisplayName, AccountUpn, Type, AccountStatus, SourceProvider, RoleCount, GroupCount, AssignedRoles, GroupMembership, CriticalityLevel, DefenderRiskLevel
| order by RoleCount desc, CriticalityLevel desc, DefenderRiskLevel desc
| take 25
'@

$loginOutcomesQuery = @'
let Logons = union isfuzzy=true
(SigninLogs | where TimeGenerated between (['_startTime'] .. ['_endTime']) | project Timestamp=TimeGenerated, Source='Interactive Entra', Result=iff(tostring(ResultType) == '0' or ResultType =~ 'Success', 'Success', 'Failure')),
(AADNonInteractiveUserSignInLogs | where TimeGenerated between (['_startTime'] .. ['_endTime']) | project Timestamp=TimeGenerated, Source='Non-interactive Entra', Result=iff(tostring(ResultType) == '0' or ResultType =~ 'Success', 'Success', 'Failure')),
(AADServicePrincipalSignInLogs | where TimeGenerated between (['_startTime'] .. ['_endTime']) | project Timestamp=TimeGenerated, Source='Service principal', Result=iff(tostring(ResultType) == '0' or ResultType =~ 'Success', 'Success', 'Failure')),
(AADManagedIdentitySignInLogs | where TimeGenerated between (['_startTime'] .. ['_endTime']) | project Timestamp=TimeGenerated, Source='Managed identity', Result=iff(tostring(ResultType) == '0' or ResultType =~ 'Success', 'Success', 'Failure')),
(DeviceLogonEvents | where Timestamp between (['_startTime'] .. ['_endTime']) | project Timestamp, Source='Endpoint logon', Result=iff(ActionType has 'Failed', 'Failure', 'Success')),
(IdentityLogonEvents | where Timestamp between (['_startTime'] .. ['_endTime']) | project Timestamp, Source='Identity logon', Result=iff(ActionType has 'Failed', 'Failure', 'Success'));
Logons
| summarize Logons=count() by bin(Timestamp, 6h), Result
| order by Timestamp asc
| render timechart with (title='Successful and failed logons over time')
'@

$failedLoginSourcesQuery = @'
let Failed = union isfuzzy=true
(SigninLogs | where TimeGenerated between (['_startTime'] .. ['_endTime']) | where not(tostring(ResultType) == '0' or ResultType =~ 'Success') | project Timestamp=TimeGenerated, Source='Interactive Entra', Principal=UserPrincipalName, Application=AppDisplayName, IPAddress, Failure=ResultDescription),
(AADNonInteractiveUserSignInLogs | where TimeGenerated between (['_startTime'] .. ['_endTime']) | where not(tostring(ResultType) == '0' or ResultType =~ 'Success') | project Timestamp=TimeGenerated, Source='Non-interactive Entra', Principal=UserPrincipalName, Application=AppDisplayName, IPAddress, Failure=ResultDescription),
(DeviceLogonEvents | where Timestamp between (['_startTime'] .. ['_endTime']) | where ActionType has 'Failed' | project Timestamp, Source='Endpoint logon', Principal=strcat(AccountDomain, '\\', AccountName), Application=LogonType, IPAddress=RemoteIP, Failure=FailureReason),
(IdentityLogonEvents | where Timestamp between (['_startTime'] .. ['_endTime']) | where ActionType has 'Failed' | project Timestamp, Source='Identity logon', Principal=coalesce(AccountUpn, strcat(AccountDomain, '\\', AccountName)), Application=LogonType, IPAddress, Failure=FailureReason);
Failed
| summarize FailedLogins=count(), Principals=dcount(Principal), Applications=dcount(Application) by Source
| order by FailedLogins desc
| render barchart with (title='Failed logins by source')
'@

$topFailedPrincipalsQuery = @'
let Failed = union isfuzzy=true
(SigninLogs | where TimeGenerated between (['_startTime'] .. ['_endTime']) | where not(tostring(ResultType) == '0' or ResultType =~ 'Success') | project Principal=UserPrincipalName, IPAddress, Failure=ResultDescription),
(AADNonInteractiveUserSignInLogs | where TimeGenerated between (['_startTime'] .. ['_endTime']) | where not(tostring(ResultType) == '0' or ResultType =~ 'Success') | project Principal=UserPrincipalName, IPAddress, Failure=ResultDescription),
(DeviceLogonEvents | where Timestamp between (['_startTime'] .. ['_endTime']) | where ActionType has 'Failed' | project Principal=strcat(AccountDomain, '\\', AccountName), IPAddress=RemoteIP, Failure=FailureReason),
(IdentityLogonEvents | where Timestamp between (['_startTime'] .. ['_endTime']) | where ActionType has 'Failed' | project Principal=coalesce(AccountUpn, strcat(AccountDomain, '\\', AccountName)), IPAddress, Failure=FailureReason);
Failed
| summarize FailedLogins=count(), SourceIPs=dcount(IPAddress), Failures=make_set(Failure, 5) by Principal
| top 20 by FailedLogins desc
'@

$alertSeverityQuery = @'
AlertInfo
| where Timestamp between (['_startTime'] .. ['_endTime'])
| summarize Alerts=count() by Severity, Category
| order by Alerts desc
| render columnchart with (title='Alerts by severity and category')
'@

$mitreAlertQuery = @'
AlertInfo
| where Timestamp between (['_startTime'] .. ['_endTime'])
| summarize Alerts=count(), Titles=make_set(Title, 5) by AttackTechniques, Severity
| order by Alerts desc
'@

$topNetworkDestinationsQuery = @'
DeviceNetworkEvents
| where TimeGenerated between (['_startTime'] .. ['_endTime'])
| extend Destination=iff(isempty(RemoteUrl), RemoteIP, RemoteUrl)
| summarize Connections=count(), Devices=dcount(DeviceId), Ports=make_set(RemotePort, 8), Processes=make_set(InitiatingProcessFileName, 8) by Destination, RemoteIP, RemoteIPType, Protocol
| top 25 by Connections desc
'@

$networkByProcessQuery = @'
DeviceNetworkEvents
| where TimeGenerated between (['_startTime'] .. ['_endTime'])
| summarize Connections=count(), Destinations=dcount(iff(isempty(RemoteUrl), RemoteIP, RemoteUrl)), PublicConnections=countif(RemoteIPType == 'Public') by InitiatingProcessFileName, Protocol
| top 20 by Connections desc
| render barchart with (title='Network connections by process')
'@

$publicEgressQuery = @'
DeviceNetworkEvents
| where TimeGenerated between (['_startTime'] .. ['_endTime'])
| where RemoteIPType == 'Public'
| extend Destination=iff(isempty(RemoteUrl), RemoteIP, RemoteUrl)
| summarize Connections=count(), Devices=dcount(DeviceId), Processes=make_set(InitiatingProcessFileName, 8) by Destination, RemoteIP, RemotePort, Protocol
| top 25 by Connections desc
'@

$graphApiRequestsQuery = @'
let AppLookup = union isfuzzy=true
(SigninLogs | project ApplicationId=tostring(ApplicationId), ApplicationName=AppDisplayName),
(EntraIdSpnSignInEvents | project ApplicationId=tostring(ApplicationId), ApplicationName=Application),
(AADManagedIdentitySignInLogs | project ApplicationId=tostring(AppId), ApplicationName=ServicePrincipalName)
| where isnotempty(ApplicationId) and isnotempty(ApplicationName)
| summarize ApplicationName=any(ApplicationName) by ApplicationId;
GraphApiAuditEvents
| where TimeGenerated between (['_startTime'] .. ['_endTime'])
| extend Api=strcat(RequestMethod, ' ', tostring(split(RequestUri, '?')[0])), AppId=tostring(ApplicationId), StatusCode=toint(ResponseStatusCode)
| lookup kind=leftouter AppLookup on ApplicationId
| extend ApplicationName=coalesce(ApplicationName, 'Unknown / synthetic Graph client')
| summarize Requests=count(), Failures=countif(StatusCode >= 400), Principals=dcount(AccountObjectId), ClientIPs=dcount(IpAddress) by Api, ApplicationName, AppId, TargetWorkload
| top 25 by Requests desc
'@

$graphStatusQuery = @'
GraphApiAuditEvents
| where TimeGenerated between (['_startTime'] .. ['_endTime'])
| extend StatusClass=strcat(substring(ResponseStatusCode, 0, 1), 'xx')
| summarize Requests=count() by RequestMethod, StatusClass
| order by Requests desc
| render columnchart with (title='Graph API status by method')
'@

$managedIdentityQuery = @'
AADManagedIdentitySignInLogs
| where TimeGenerated between (['_startTime'] .. ['_endTime'])
| summarize SignIns=count(), Failures=countif(not(ResultType =~ 'Success' or tostring(ResultType) == '0')), Resources=make_set(ResourceDisplayName, 8), SourceIPs=make_set(IPAddress, 8) by ServicePrincipalName, ServicePrincipalId
| top 20 by SignIns desc
'@

$scenarioTimelineQuery = @'
let AlertSignals = AlertInfo | where Timestamp between (['_startTime'] .. ['_endTime']) | project Timestamp, Signal='Alert', Entity=Title, Detail=strcat(Severity, ' | ', AttackTechniques);
let NetworkSignals = DeviceNetworkEvents | where TimeGenerated between (['_startTime'] .. ['_endTime']) | where RemoteIPType == 'Public' | extend Destination=iff(isempty(RemoteUrl), RemoteIP, RemoteUrl) | project Timestamp=TimeGenerated, Signal='Public network connection', Entity=DeviceName, Detail=strcat(InitiatingProcessFileName, ' -> ', Destination, ':', tostring(RemotePort));
let GraphSignals = GraphApiAuditEvents | where TimeGenerated between (['_startTime'] .. ['_endTime']) | where toint(ResponseStatusCode) >= 400 or RequestMethod in ('POST','PATCH','DELETE') | project Timestamp=TimeGenerated, Signal='Graph API activity', Entity=ApplicationId, Detail=strcat(RequestMethod, ' ', RequestUri, ' -> ', ResponseStatusCode);
union AlertSignals, NetworkSignals, GraphSignals
| top 50 by Timestamp desc
'@

$tiles.Add((New-Tile -Title 'Total alerts' -Query $totalAlertsCardQuery -PageId $overviewPageId -DataSourceId $dataSourceId -VisualType 'card' -X 0 -Y 0 -Width 3 -Height 3 -VisualOptions (New-CardOptions))) | Out-Null
$tiles.Add((New-Tile -Title 'High alerts' -Query $highAlertsCardQuery -PageId $overviewPageId -DataSourceId $dataSourceId -VisualType 'card' -X 3 -Y 0 -Width 3 -Height 3 -VisualOptions (New-CardOptions))) | Out-Null
$tiles.Add((New-Tile -Title 'Failed logins' -Query $failedLoginsCardQuery -PageId $overviewPageId -DataSourceId $dataSourceId -VisualType 'card' -X 6 -Y 0 -Width 3 -Height 3 -VisualOptions (New-CardOptions))) | Out-Null
$tiles.Add((New-Tile -Title 'Successful logins' -Query $successfulLoginsCardQuery -PageId $overviewPageId -DataSourceId $dataSourceId -VisualType 'card' -X 9 -Y 0 -Width 3 -Height 3 -VisualOptions (New-CardOptions))) | Out-Null
$tiles.Add((New-Tile -Title 'Users' -Query $usersCardQuery -PageId $overviewPageId -DataSourceId $dataSourceId -VisualType 'card' -X 0 -Y 3 -Width 3 -Height 3 -VisualOptions (New-CardOptions))) | Out-Null
$tiles.Add((New-Tile -Title 'Service accounts' -Query $serviceAccountsCardQuery -PageId $overviewPageId -DataSourceId $dataSourceId -VisualType 'card' -X 3 -Y 3 -Width 3 -Height 3 -VisualOptions (New-CardOptions))) | Out-Null
$tiles.Add((New-Tile -Title 'OAuth/Graph suspicious activity' -Query $oauthGraphSuspiciousActivityCardQuery -PageId $overviewPageId -DataSourceId $dataSourceId -VisualType 'card' -X 6 -Y 3 -Width 3 -Height 3 -VisualOptions (New-CardOptions))) | Out-Null
$tiles.Add((New-Tile -Title 'Public egress' -Query $publicEgressCardQuery -PageId $overviewPageId -DataSourceId $dataSourceId -VisualType 'card' -X 9 -Y 3 -Width 3 -Height 3 -VisualOptions (New-CardOptions))) | Out-Null
$tiles.Add((New-Tile -Title 'Alerts by severity and category' -Query $alertSeverityQuery -PageId $overviewPageId -DataSourceId $dataSourceId -VisualType 'column' -X 0 -Y 6 -Width 6 -Height 5 -VisualOptions (New-ChartOptions -YAxisLabel 'Alerts'))) | Out-Null
$tiles.Add((New-Tile -Title 'Login outcomes over time' -Query $loginOutcomesQuery -PageId $overviewPageId -DataSourceId $dataSourceId -VisualType 'line' -X 6 -Y 6 -Width 6 -Height 5 -VisualOptions (New-ChartOptions -YAxisLabel 'Logons'))) | Out-Null
$tiles.Add((New-Tile -Title 'Failed logins by source' -Query $failedLoginSourcesQuery -PageId $overviewPageId -DataSourceId $dataSourceId -VisualType 'bar' -X 0 -Y 11 -Width 4 -Height 5 -VisualOptions (New-ChartOptions -YAxisLabel 'Failed logins'))) | Out-Null
$tiles.Add((New-Tile -Title 'Top failed principals' -Query $topFailedPrincipalsQuery -PageId $overviewPageId -DataSourceId $dataSourceId -VisualType 'table' -X 4 -Y 11 -Width 4 -Height 5 -VisualOptions (New-TableOptions))) | Out-Null
$tiles.Add((New-Tile -Title 'MITRE ATT&CK alert techniques' -Query $mitreAlertQuery -PageId $overviewPageId -DataSourceId $dataSourceId -VisualType 'table' -X 8 -Y 11 -Width 4 -Height 5 -VisualOptions (New-TableOptions))) | Out-Null
$tiles.Add((New-Tile -Title 'Public egress destinations' -Query $publicEgressQuery -PageId $overviewPageId -DataSourceId $dataSourceId -VisualType 'table' -X 0 -Y 16 -Width 6 -Height 6 -VisualOptions (New-TableOptions))) | Out-Null
$tiles.Add((New-Tile -Title 'Graph API requests by API / application / AppId' -Query $graphApiRequestsQuery -PageId $overviewPageId -DataSourceId $dataSourceId -VisualType 'table' -X 6 -Y 16 -Width 6 -Height 6 -VisualOptions (New-TableOptions))) | Out-Null
$tiles.Add((New-Tile -Title 'Scenario signal timeline' -Query $scenarioTimelineQuery -PageId $overviewPageId -DataSourceId $dataSourceId -VisualType 'table' -X 0 -Y 22 -Width 12 -Height 7 -VisualOptions (New-TableOptions))) | Out-Null

$tiles.Add((New-Tile -Title 'Users and service accounts' -Query $identitySummaryQuery -PageId $identityPageId -DataSourceId $dataSourceId -VisualType 'column' -X 0 -Y 0 -Width 6 -Height 6 -VisualOptions (New-ChartOptions -YAxisLabel 'Accounts'))) | Out-Null
$tiles.Add((New-Tile -Title 'Login outcomes over time' -Query $loginOutcomesQuery -PageId $identityPageId -DataSourceId $dataSourceId -VisualType 'line' -X 6 -Y 0 -Width 6 -Height 6 -VisualOptions (New-ChartOptions -YAxisLabel 'Logons'))) | Out-Null
$tiles.Add((New-Tile -Title 'Failed logins by source' -Query $failedLoginSourcesQuery -PageId $identityPageId -DataSourceId $dataSourceId -VisualType 'bar' -X 0 -Y 6 -Width 6 -Height 5 -VisualOptions (New-ChartOptions -YAxisLabel 'Failed logins'))) | Out-Null
$tiles.Add((New-Tile -Title 'Top failed principals' -Query $topFailedPrincipalsQuery -PageId $identityPageId -DataSourceId $dataSourceId -VisualType 'table' -X 6 -Y 6 -Width 6 -Height 5 -VisualOptions (New-TableOptions))) | Out-Null
$tiles.Add((New-Tile -Title 'Privileged / high-risk identities' -Query $privilegedIdentitiesQuery -PageId $identityPageId -DataSourceId $dataSourceId -VisualType 'table' -X 0 -Y 11 -Width 12 -Height 7 -VisualOptions (New-TableOptions))) | Out-Null

$tiles.Add((New-Tile -Title 'Top network destinations' -Query $topNetworkDestinationsQuery -PageId $networkPageId -DataSourceId $dataSourceId -VisualType 'table' -X 0 -Y 0 -Width 7 -Height 7 -VisualOptions (New-TableOptions))) | Out-Null
$tiles.Add((New-Tile -Title 'Network connections by process' -Query $networkByProcessQuery -PageId $networkPageId -DataSourceId $dataSourceId -VisualType 'bar' -X 7 -Y 0 -Width 5 -Height 7 -VisualOptions (New-ChartOptions -YAxisLabel 'Connections'))) | Out-Null
$tiles.Add((New-Tile -Title 'Public egress destinations' -Query $publicEgressQuery -PageId $networkPageId -DataSourceId $dataSourceId -VisualType 'table' -X 0 -Y 7 -Width 6 -Height 7 -VisualOptions (New-TableOptions))) | Out-Null
$tiles.Add((New-Tile -Title 'Graph API requests by API / application / AppId' -Query $graphApiRequestsQuery -PageId $networkPageId -DataSourceId $dataSourceId -VisualType 'table' -X 6 -Y 7 -Width 6 -Height 7 -VisualOptions (New-TableOptions))) | Out-Null
$tiles.Add((New-Tile -Title 'Graph API status by method' -Query $graphStatusQuery -PageId $networkPageId -DataSourceId $dataSourceId -VisualType 'column' -X 0 -Y 14 -Width 6 -Height 5 -VisualOptions (New-ChartOptions -YAxisLabel 'Requests'))) | Out-Null
$tiles.Add((New-Tile -Title 'Managed identity sign-ins' -Query $managedIdentityQuery -PageId $networkPageId -DataSourceId $dataSourceId -VisualType 'table' -X 6 -Y 14 -Width 6 -Height 5 -VisualOptions (New-TableOptions))) | Out-Null

$tiles.Add((New-Tile -Title 'Security incidents' -Query $securityIncidentsCardQuery -PageId $timelinePageId -DataSourceId $dataSourceId -VisualType 'card' -X 0 -Y 0 -Width 3 -Height 3 -VisualOptions (New-CardOptions))) | Out-Null
$tiles.Add((New-Tile -Title 'Alerts by severity and category' -Query $alertSeverityQuery -PageId $timelinePageId -DataSourceId $dataSourceId -VisualType 'column' -X 3 -Y 0 -Width 4 -Height 5 -VisualOptions (New-ChartOptions -YAxisLabel 'Alerts'))) | Out-Null
$tiles.Add((New-Tile -Title 'MITRE ATT&CK alert techniques' -Query $mitreAlertQuery -PageId $timelinePageId -DataSourceId $dataSourceId -VisualType 'table' -X 7 -Y 0 -Width 5 -Height 5 -VisualOptions (New-TableOptions))) | Out-Null
$tiles.Add((New-Tile -Title 'Top 20 security incidents by name and number' -Query $topSecurityIncidentsQuery -PageId $timelinePageId -DataSourceId $dataSourceId -VisualType 'table' -X 0 -Y 5 -Width 12 -Height 7 -VisualOptions (New-TableOptions))) | Out-Null
$tiles.Add((New-Tile -Title 'Scenario signal timeline' -Query $scenarioTimelineQuery -PageId $timelinePageId -DataSourceId $dataSourceId -VisualType 'table' -X 0 -Y 12 -Width 12 -Height 8 -VisualOptions (New-TableOptions))) | Out-Null

$tiles.Add((New-Tile -Title 'Devices by OS family / category / type' -Query $deviceOsCategoryQuery -PageId $inventoryPageId -DataSourceId $dataSourceId -VisualType 'bar' -X 0 -Y 0 -Width 6 -Height 6 -VisualOptions (New-ChartOptions -YAxisLabel 'Devices'))) | Out-Null
$tiles.Add((New-Tile -Title 'Machine group posture' -Query $machineGroupPostureQuery -PageId $inventoryPageId -DataSourceId $dataSourceId -VisualType 'column' -X 6 -Y 0 -Width 6 -Height 6 -VisualOptions (New-ChartOptions -YAxisLabel 'Devices'))) | Out-Null
$tiles.Add((New-Tile -Title 'Device inventory drilldown' -Query $deviceInventoryQuery -PageId $inventoryPageId -DataSourceId $dataSourceId -VisualType 'table' -X 0 -Y 6 -Width 12 -Height 8 -VisualOptions (New-TableOptions))) | Out-Null

$dashboard = [ordered]@{
    id = New-WorkshopGuid 'cyber-defense-workshop-dashboard'
    eTag = ''
    title = 'Cyber Defense Workshop - SOC Threat Protection Dashboard'
    tiles = @($tiles)
    dataSources = @(
        [ordered]@{
            id = $dataSourceId
            name = 'Cyber Defense Workshop ADX'
            clusterUri = $ClusterUri.TrimEnd('/')
            database = $DatabaseName
            kind = 'manual-kusto'
            scopeId = 'kusto'
        }
    )
    '$schema' = 'https://dataexplorer.azure.com/static/d/schema/20/dashboard.json'
    autoRefresh = [ordered]@{
        enabled = $true
        defaultInterval = '15m'
        minInterval = '5m'
    }
    parameters = @(
        [ordered]@{
            kind = 'duration'
            id = New-WorkshopGuid 'cyber-defense-workshop-dashboard|time-range'
            displayName = 'Time range'
            beginVariableName = '_startTime'
            endVariableName = '_endTime'
            defaultValue = [ordered]@{
                kind = 'dynamic'
                count = 14
                unit = 'days'
            }
            showOnPages = [ordered]@{
                kind = 'all'
            }
        }
    )
    pages = @(
        [ordered]@{ name = 'SOC Overview'; id = $overviewPageId },
        [ordered]@{ name = 'Identity and Sign-ins'; id = $identityPageId },
        [ordered]@{ name = 'Network and Graph'; id = $networkPageId },
        [ordered]@{ name = 'Alerts and Scenario Timeline'; id = $timelinePageId },
        [ordered]@{ name = 'Inventory and Posture'; id = $inventoryPageId }
    )
    schema_version = '20'
}

$dashboard | ConvertTo-Json -Depth 100 | Set-Content -Path $OutputPath -Encoding utf8

$kqlBuilder = [System.Text.StringBuilder]::new()
[void]$kqlBuilder.AppendLine('// Cyber Defense Workshop ADX Operations Dashboard query pack')
[void]$kqlBuilder.AppendLine('// Use these queries to manually pin tiles if the JSON import path is not available.')
[void]$kqlBuilder.AppendLine('// Adjust StartTime and EndTime if you want a different dashboard window.')
[void]$kqlBuilder.AppendLine('let StartTime = ago(14d);')
[void]$kqlBuilder.AppendLine('let EndTime = now();')
[void]$kqlBuilder.AppendLine()
foreach ($tile in $tiles) {
    $query = ([string]$tile.query).Replace("['_startTime']", 'StartTime').Replace("['_endTime']", 'EndTime')
    [void]$kqlBuilder.AppendLine('// -----------------------------------------------------------------------------')
    [void]$kqlBuilder.AppendLine("// Tile: $($tile.title)")
    [void]$kqlBuilder.AppendLine($query)
    [void]$kqlBuilder.AppendLine()
}

Set-Content -Path $KqlPath -Value $kqlBuilder.ToString() -Encoding utf8

Write-Host "Wrote ADX dashboard JSON: $OutputPath"
Write-Host "Wrote dashboard KQL pack: $KqlPath"
