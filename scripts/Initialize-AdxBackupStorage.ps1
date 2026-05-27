<#
.SYNOPSIS
Creates the secured ADLS Gen2 backing storage and managed identity wiring for ADX database backups.

.DESCRIPTION
Creates or reuses an ADLS Gen2 storage account and filesystem, creates or reuses
a user-assigned managed identity, assigns it to the ADX cluster, grants the
identity Storage Blob Data Contributor on the storage account, and allows that
identity to be used by ADX for export and native ingestion requests.

By default, the storage account disables shared-key authorization, disables
anonymous blob access, denies public network access, and creates ADX managed
private endpoints to the storage account blob and dfs subresources.

.EXAMPLE
.\scripts\Initialize-AdxBackupStorage.ps1 -SubscriptionName 'Security' -ResourceGroupName ADX -ClusterName dibsecadx -ClusterUri 'https://dibsecadx.eastus2.kusto.windows.net' -DatabaseName 'cyber-defend-q0xxzc'

.EXAMPLE
.\scripts\Initialize-AdxBackupStorage.ps1 -StorageAccountName dibsecadxbackup1234 -UserAssignedIdentityName uami-dibsecadx-backup -StorageNetworkMode TrustedServices

.NOTES
Name: Initialize-AdxBackupStorage.ps1
Date: 2026-05-27
Dependencies: Azure CLI, scripts\AdxWorkshop.Common.psm1, Azure permissions to manage storage, identities, ADX, RBAC, and private endpoint approvals.
Key commands: az storage account, az identity, az role assignment, az rest, .alter-merge database policy managed_identity.
#>
[CmdletBinding()]
param(
    [string]$SubscriptionName = 'Security',
    [string]$SubscriptionId,
    [string]$ResourceGroupName = 'ADX',
    [string]$ClusterName = 'dibsecadx',
    [string]$ClusterUri = 'https://dibsecadx.eastus2.kusto.windows.net',
    [string]$DatabaseName = 'CyberDefenseKqlWorkshop',
    [string]$StorageResourceGroupName,
    [string]$Location,
    [string]$StorageAccountName,
    [string]$FileSystemName = 'adx-backups',
    [string]$UserAssignedIdentityName = 'uami-adx-backup',
    [string]$UserAssignedIdentityResourceGroupName,
    [ValidateSet('ManagedPrivateEndpoint', 'TrustedServices')]
    [string]$StorageNetworkMode = 'ManagedPrivateEndpoint',
    [switch]$SkipManagedPrivateEndpoint,
    [switch]$UseClusterManagedIdentityPolicy
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'AdxWorkshop.Common.psm1') -Force

function Invoke-WorkshopAzCli {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [switch]$AsJson,
        [switch]$AllowFailure
    )

    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & az @Arguments 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    $text = [string]::Join([Environment]::NewLine, @($output | ForEach-Object { [string]$_ }))
    if ($exitCode -ne 0) {
        if ($AllowFailure) {
            return [pscustomobject]@{
                Succeeded = $false
                Output = $text
            }
        }

        throw "Azure CLI command failed: az $($Arguments -join ' ')`n$text"
    }

    if ($AllowFailure) {
        return [pscustomobject]@{
            Succeeded = $true
            Output = $text
        }
    }

    if ($AsJson) {
        if ([string]::IsNullOrWhiteSpace($text)) {
            return $null
        }

        return (ConvertFrom-WorkshopAzCliJsonText -Text $text)
    }

    return $text
}

function ConvertFrom-WorkshopAzCliJsonText {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Text)

    $trimmed = $Text.Trim()
    $objectStart = $trimmed.IndexOf('{')
    $arrayStart = $trimmed.IndexOf('[')
    $starts = @(@($objectStart, $arrayStart) | Where-Object { $_ -ge 0 } | Sort-Object)
    if ($starts.Count -eq 0) {
        throw "Azure CLI output did not contain JSON: $Text"
    }

    return ($trimmed.Substring($starts[0]) | ConvertFrom-Json)
}

function Invoke-WorkshopArmRest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        [object]$Body
    )

    $arguments = @('rest', '--method', $Method, '--url', "https://management.azure.com$Path")
    $tempPath = $null
    try {
        if ($null -ne $Body) {
            $tempPath = Join-Path ([System.IO.Path]::GetTempPath()) "adx-backup-arm-$([guid]::NewGuid()).json"
            $Body | ConvertTo-Json -Depth 20 | Set-Content -Path $tempPath -Encoding UTF8
            $arguments += @('--body', "@$tempPath")
        }

        return Invoke-WorkshopAzCli -Arguments ($arguments + @('--output', 'json')) -AsJson
    }
    finally {
        if ($tempPath -and (Test-Path $tempPath)) {
            Remove-Item -Path $tempPath -Force
        }
    }
}

function Get-WorkshopAzCliJsonOrNull {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$Arguments)

    $result = Invoke-WorkshopAzCli -Arguments ($Arguments + @('--output', 'json')) -AllowFailure
    if (-not $result.Succeeded -or [string]::IsNullOrWhiteSpace($result.Output)) {
        return $null
    }

    return (ConvertFrom-WorkshopAzCliJsonText -Text $result.Output)
}

function New-WorkshopStorageAccountName {
    param(
        [Parameter(Mandatory)][string]$ClusterName,
        [Parameter(Mandatory)][string]$DatabaseName
    )

    $safeCluster = ($ClusterName.ToLowerInvariant() -replace '[^a-z0-9]', '')
    $safeDatabase = ($DatabaseName.ToLowerInvariant() -replace '[^a-z0-9]', '')
    $suffix = (([guid]::NewGuid()).Guid -replace '-', '').Substring(0, 8)
    $candidate = "adx$safeCluster$safeDatabase$suffix"
    if ($candidate.Length -gt 24) {
        $candidate = "adx$($safeCluster.Substring(0, [Math]::Min($safeCluster.Length, 10)))$suffix"
    }

    return $candidate.Substring(0, [Math]::Min($candidate.Length, 24))
}

function Add-WorkshopRoleAssignment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PrincipalId,
        [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)][string]$RoleName
    )

    for ($attempt = 1; $attempt -le 6; $attempt++) {
        $previousErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $output = & az role assignment create `
                --assignee-object-id $PrincipalId `
                --assignee-principal-type ServicePrincipal `
                --role $RoleName `
                --scope $Scope `
                --output json 2>&1
            $exitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }
        $text = [string]::Join([Environment]::NewLine, @($output | ForEach-Object { [string]$_ }))
        if ($exitCode -eq 0 -or $text -match 'RoleAssignmentExists|already exists') {
            Write-Host "RBAC ready: $RoleName on $Scope"
            return
        }

        if ($text -match 'PrincipalNotFound' -and $attempt -lt 6) {
            Write-Host "Waiting for managed identity principal propagation before assigning $RoleName. Attempt $attempt of 6."
            Start-Sleep -Seconds 10
            continue
        }

        throw "Could not assign role '$RoleName' to principal '$PrincipalId' on '$Scope': $text"
    }
}

function Add-WorkshopAdxManagedPrivateEndpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ClusterResourceId,
        [Parameter(Mandatory)][string]$StorageResourceId,
        [Parameter(Mandatory)][string]$StorageAccountName,
        [Parameter(Mandatory)][string]$GroupId
    )

    $endpointBaseName = "mpe-$StorageAccountName-$GroupId"
    $endpointName = if ($endpointBaseName.Length -gt 60) { $endpointBaseName.Substring(0, 60) } else { $endpointBaseName }
    $endpointPath = "$ClusterResourceId/managedPrivateEndpoints/$endpointName`?api-version=2023-08-15"
    $body = @{
        properties = @{
            privateLinkResourceId = $StorageResourceId
            groupId = $GroupId
            requestMessage = 'ADX database backup storage access.'
        }
    }

    Write-Host "Creating or updating ADX managed private endpoint $endpointName for storage subresource $GroupId"
    Invoke-WorkshopArmRest -Method PUT -Path $endpointPath -Body $body | Out-Null

    $connection = $null
    for ($attempt = 1; $attempt -le 24; $attempt++) {
        $connections = Invoke-WorkshopAzCli -Arguments @('network', 'private-endpoint-connection', 'list', '--id', $StorageResourceId, '--output', 'json') -AsJson
        $connection = @($connections | Where-Object {
            ([string]$_.properties.privateEndpoint.id) -like "*managedPrivateEndpoints/$endpointName*" -or
            ([string]$_.properties.privateEndpoint.id) -like "*/privateEndpoints/$endpointName" -or
            ([string]$_.name) -like "*$endpointName*"
        } | Select-Object -First 1)
        if ($connection) {
            break
        }

        Write-Host "Waiting for storage private endpoint connection for $endpointName. Attempt $attempt of 24."
        Start-Sleep -Seconds 10
    }

    if (-not $connection) {
        Write-Warning "Managed private endpoint $endpointName was created, but no storage private endpoint connection was found to approve. Approve it in the storage account Networking blade if export cannot connect."
        return
    }

    $status = [string]$connection.properties.privateLinkServiceConnectionState.status
    if ($status -ne 'Approved') {
        Write-Host "Approving storage private endpoint connection $($connection.name) for $GroupId"
        Invoke-WorkshopAzCli -Arguments @('network', 'private-endpoint-connection', 'approve', '--id', [string]$connection.id, '--description', 'Approved for ADX database backup exports.', '--output', 'json') -AsJson | Out-Null
    }
    else {
        Write-Host "Storage private endpoint connection $($connection.name) is already approved."
    }
}

function Test-WorkshopAdxManagedIdentityPolicyUsage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ClusterUri,
        [Parameter(Mandatory)][string]$DatabaseName,
        [Parameter(Mandatory)][string]$ShowCommand,
        [Parameter(Mandatory)][string]$ObjectId,
        [Parameter(Mandatory)][string[]]$RequiredUsage
    )

    $response = Invoke-WorkshopAdxManagementCommand -ClusterUri $ClusterUri -DatabaseName $DatabaseName -Command $ShowCommand -ServerTimeoutSeconds 300
    $rows = @(ConvertFrom-WorkshopAdxResponseRows -Response $response)
    foreach ($row in $rows) {
        $policyText = if ($row.PSObject.Properties['Policy']) { [string]$row.Policy } else { '' }
        if ([string]::IsNullOrWhiteSpace($policyText) -or $policyText -eq '[]') {
            continue
        }

        $policyItems = @($policyText | ConvertFrom-Json)
        foreach ($policyItem in $policyItems) {
            if ([string]$policyItem.ObjectId -ne $ObjectId) {
                continue
            }

            $allowedUsages = @([string]$policyItem.AllowedUsages -split '\s*,\s*' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            $missingUsages = @($RequiredUsage | Where-Object { $allowedUsages -notcontains $_ })
            if ($missingUsages.Count -eq 0) {
                return $true
            }
        }
    }

    return $false
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'Azure CLI is required to provision backup storage. Install Azure CLI and run az login.'
}

if (-not [string]::IsNullOrWhiteSpace($SubscriptionId)) {
    Invoke-WorkshopAzCli -Arguments @('account', 'set', '--subscription', $SubscriptionId) | Out-Null
}
elseif (-not [string]::IsNullOrWhiteSpace($SubscriptionName)) {
    Invoke-WorkshopAzCli -Arguments @('account', 'set', '--subscription', $SubscriptionName) | Out-Null
}

$account = Invoke-WorkshopAzCli -Arguments @('account', 'show', '--output', 'json') -AsJson
$effectiveSubscriptionId = [string]$account.id
if ([string]::IsNullOrWhiteSpace($StorageResourceGroupName)) {
    $StorageResourceGroupName = $ResourceGroupName
}
if ([string]::IsNullOrWhiteSpace($UserAssignedIdentityResourceGroupName)) {
    $UserAssignedIdentityResourceGroupName = $StorageResourceGroupName
}

$clusterResourceId = "/subscriptions/$effectiveSubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Kusto/clusters/$ClusterName"
$cluster = Invoke-WorkshopArmRest -Method GET -Path "$clusterResourceId`?api-version=2023-08-15"
if (-not $cluster) {
    throw "ADX cluster '$ClusterName' was not found in resource group '$ResourceGroupName'."
}

if ([string]::IsNullOrWhiteSpace($Location)) {
    $Location = [string]$cluster.location
}
if ([string]::IsNullOrWhiteSpace($ClusterUri) -and $cluster.properties.uri) {
    $ClusterUri = [string]$cluster.properties.uri
}
if ([string]::IsNullOrWhiteSpace($StorageAccountName)) {
    $StorageAccountName = New-WorkshopStorageAccountName -ClusterName $ClusterName -DatabaseName $DatabaseName
}

Assert-WorkshopAdxClusterRunning `
    -ResourceGroupName $ResourceGroupName `
    -ClusterName $ClusterName `
    -SubscriptionId $effectiveSubscriptionId `
    -ClusterUri $ClusterUri | Out-Null

if (-not (Get-WorkshopAzCliJsonOrNull -Arguments @('group', 'show', '--name', $StorageResourceGroupName))) {
    Write-Host "Creating resource group $StorageResourceGroupName in $Location"
    Invoke-WorkshopAzCli -Arguments @('group', 'create', '--name', $StorageResourceGroupName, '--location', $Location, '--output', 'json') -AsJson | Out-Null
}
if ($UserAssignedIdentityResourceGroupName -ne $StorageResourceGroupName -and -not (Get-WorkshopAzCliJsonOrNull -Arguments @('group', 'show', '--name', $UserAssignedIdentityResourceGroupName))) {
    Write-Host "Creating managed identity resource group $UserAssignedIdentityResourceGroupName in $Location"
    Invoke-WorkshopAzCli -Arguments @('group', 'create', '--name', $UserAssignedIdentityResourceGroupName, '--location', $Location, '--output', 'json') -AsJson | Out-Null
}

$identity = Get-WorkshopAzCliJsonOrNull -Arguments @('identity', 'show', '--resource-group', $UserAssignedIdentityResourceGroupName, '--name', $UserAssignedIdentityName)
if (-not $identity) {
    Write-Host "Creating user-assigned managed identity $UserAssignedIdentityName"
    $identity = Invoke-WorkshopAzCli -Arguments @('identity', 'create', '--resource-group', $UserAssignedIdentityResourceGroupName, '--name', $UserAssignedIdentityName, '--location', $Location, '--output', 'json') -AsJson
}
else {
    Write-Host "Using existing user-assigned managed identity $UserAssignedIdentityName"
}
$identityResourceId = [string]$identity.id
$identityPrincipalId = [string]$identity.principalId

$storage = Get-WorkshopAzCliJsonOrNull -Arguments @('storage', 'account', 'show', '--resource-group', $StorageResourceGroupName, '--name', $StorageAccountName)
$publicNetworkAccess = if ($StorageNetworkMode -eq 'ManagedPrivateEndpoint') { 'Disabled' } else { 'Enabled' }
$networkBypass = if ($StorageNetworkMode -eq 'TrustedServices') { 'AzureServices' } else { 'None' }
if (-not $storage) {
    Write-Host "Creating ADLS Gen2 storage account $StorageAccountName in $Location"
    $storage = Invoke-WorkshopAzCli -Arguments @(
        'storage', 'account', 'create',
        '--resource-group', $StorageResourceGroupName,
        '--name', $StorageAccountName,
        '--location', $Location,
        '--sku', 'Standard_LRS',
        '--kind', 'StorageV2',
        '--hierarchical-namespace', 'true',
        '--https-only', 'true',
        '--min-tls-version', 'TLS1_2',
        '--allow-blob-public-access', 'false',
        '--allow-shared-key-access', 'false',
        '--public-network-access', $publicNetworkAccess,
        '--default-action', 'Deny',
        '--bypass', $networkBypass,
        '--output', 'json'
    ) -AsJson
}
else {
    Write-Host "Using existing storage account $StorageAccountName"
    if (-not [bool]$storage.isHnsEnabled) {
        throw "Storage account '$StorageAccountName' exists but hierarchical namespace is not enabled. Use an ADLS Gen2 storage account."
    }
}

Write-Host "Hardening storage account $StorageAccountName"
Invoke-WorkshopAzCli -Arguments @(
    'storage', 'account', 'update',
    '--resource-group', $StorageResourceGroupName,
    '--name', $StorageAccountName,
    '--https-only', 'true',
    '--min-tls-version', 'TLS1_2',
    '--allow-blob-public-access', 'false',
    '--allow-shared-key-access', 'false',
    '--public-network-access', $publicNetworkAccess,
    '--default-action', 'Deny',
    '--bypass', $networkBypass,
    '--output', 'json'
) -AsJson | Out-Null
$storage = Invoke-WorkshopAzCli -Arguments @('storage', 'account', 'show', '--resource-group', $StorageResourceGroupName, '--name', $StorageAccountName, '--output', 'json') -AsJson
$storageResourceId = [string]$storage.id

Write-Host "Creating or updating ADLS Gen2 filesystem $FileSystemName with no anonymous access"
$containerPath = "$storageResourceId/blobServices/default/containers/$FileSystemName`?api-version=2023-01-01"
Invoke-WorkshopArmRest -Method PUT -Path $containerPath -Body @{ properties = @{ publicAccess = 'None' } } | Out-Null

Write-Host "Assigning user-assigned identity to ADX cluster $ClusterName"
$cluster = Invoke-WorkshopArmRest -Method GET -Path "$clusterResourceId`?api-version=2023-08-15"
$identityType = if ($cluster.identity -and $cluster.identity.PSObject.Properties['type']) { [string]$cluster.identity.type } else { '' }
$identityTypeParts = New-Object System.Collections.Generic.List[string]
if ($identityType -match 'SystemAssigned') {
    $identityTypeParts.Add('SystemAssigned') | Out-Null
}
$identityTypeParts.Add('UserAssigned') | Out-Null
$userAssignedIdentities = [ordered]@{}
if ($cluster.identity -and $cluster.identity.PSObject.Properties['userAssignedIdentities']) {
    foreach ($property in $cluster.identity.userAssignedIdentities.PSObject.Properties) {
        $userAssignedIdentities[$property.Name] = @{}
    }
}
$userAssignedIdentities[$identityResourceId] = @{}
$identityPatch = @{
    identity = @{
        type = ($identityTypeParts.ToArray() -join ', ')
        userAssignedIdentities = $userAssignedIdentities
    }
}
Invoke-WorkshopArmRest -Method PATCH -Path "$clusterResourceId`?api-version=2023-08-15" -Body $identityPatch | Out-Null

for ($attempt = 1; $attempt -le 40; $attempt++) {
    $cluster = Invoke-WorkshopArmRest -Method GET -Path "$clusterResourceId`?api-version=2023-08-15"
    $assignedIdentityNames = @()
    if ($cluster.identity -and $cluster.identity.PSObject.Properties['userAssignedIdentities']) {
        $assignedIdentityNames = @($cluster.identity.userAssignedIdentities.PSObject.Properties.Name)
    }
    $provisioningState = [string]$cluster.properties.provisioningState
    if ($assignedIdentityNames -contains $identityResourceId -and $provisioningState -eq 'Succeeded') {
        break
    }

    Write-Host "Waiting for ADX cluster identity assignment. State: $provisioningState. Attempt $attempt of 40."
    Start-Sleep -Seconds 15
}

$cluster = Invoke-WorkshopArmRest -Method GET -Path "$clusterResourceId`?api-version=2023-08-15"
$assignedIdentityNames = @()
if ($cluster.identity -and $cluster.identity.PSObject.Properties['userAssignedIdentities']) {
    $assignedIdentityNames = @($cluster.identity.userAssignedIdentities.PSObject.Properties.Name)
}
if ($assignedIdentityNames -notcontains $identityResourceId) {
    throw "Timed out waiting for ADX cluster '$ClusterName' to have managed identity '$identityResourceId'."
}

Add-WorkshopRoleAssignment -PrincipalId $identityPrincipalId -Scope $storageResourceId -RoleName 'Storage Blob Data Contributor'

if ($StorageNetworkMode -eq 'ManagedPrivateEndpoint' -and -not $SkipManagedPrivateEndpoint) {
    Invoke-WorkshopAzCli -Arguments @('provider', 'register', '--namespace', 'Microsoft.Network') | Out-Null
    foreach ($groupId in @('blob', 'dfs')) {
        Add-WorkshopAdxManagedPrivateEndpoint `
            -ClusterResourceId $clusterResourceId `
            -StorageResourceId $storageResourceId `
            -StorageAccountName $StorageAccountName `
            -GroupId $groupId
    }
}

$databaseIdentifier = ConvertTo-WorkshopKustoIdentifier -Name $DatabaseName
$policyScope = if ($UseClusterManagedIdentityPolicy) { 'cluster' } else { "database $databaseIdentifier" }
$allowedUsages = 'ExportRequest, NativeIngestion'
$requiredUsages = @('ExportRequest', 'NativeIngestion')
$policyJson = @(@{ ObjectId = $identityPrincipalId; AllowedUsages = $allowedUsages }) | ConvertTo-Json -Compress
$clusterPolicyHasUsage = Test-WorkshopAdxManagedIdentityPolicyUsage `
    -ClusterUri $ClusterUri `
    -DatabaseName $DatabaseName `
    -ShowCommand '.show cluster policy managed_identity' `
    -ObjectId $identityPrincipalId `
    -RequiredUsage $requiredUsages
$databasePolicyHasUsage = $false
if (-not $UseClusterManagedIdentityPolicy) {
    $databasePolicyHasUsage = Test-WorkshopAdxManagedIdentityPolicyUsage `
        -ClusterUri $ClusterUri `
        -DatabaseName $DatabaseName `
        -ShowCommand ".show database $databaseIdentifier policy managed_identity" `
        -ObjectId $identityPrincipalId `
        -RequiredUsage $requiredUsages
}

if ($clusterPolicyHasUsage) {
    $policyScope = 'cluster'
    Write-Host "ADX managed identity policy already allows $allowedUsages on cluster."
}
elseif ($databasePolicyHasUsage) {
    Write-Host "ADX managed identity policy already allows $allowedUsages on $policyScope."
}
else {
    $policyCommand = ".alter-merge $policyScope policy managed_identity " + '```' + $policyJson + '```'
    Write-Host "Allowing managed identity for ADX $allowedUsages on $policyScope"
    try {
        Invoke-WorkshopAdxManagementCommand -ClusterUri $ClusterUri -DatabaseName $DatabaseName -Command $policyCommand | Out-Null
    }
    catch {
        if ($UseClusterManagedIdentityPolicy) {
            throw
        }

        Write-Warning "Database-scope managed identity policy failed: $($_.Exception.Message)"
        Write-Warning 'Retrying the managed identity policy at cluster scope.'
        $policyScope = 'cluster'
        $policyCommand = ".alter-merge cluster policy managed_identity " + '```' + $policyJson + '```'
        Invoke-WorkshopAdxManagementCommand -ClusterUri $ClusterUri -DatabaseName $DatabaseName -Command $policyCommand | Out-Null
    }
}

$result = [ordered]@{
    subscriptionId = $effectiveSubscriptionId
    clusterResourceId = $clusterResourceId
    clusterUri = $ClusterUri
    databaseName = $DatabaseName
    storageAccountName = $StorageAccountName
    storageResourceGroupName = $StorageResourceGroupName
    storageResourceId = $storageResourceId
    fileSystemName = $FileSystemName
    storageNetworkMode = $StorageNetworkMode
    publicNetworkAccess = $publicNetworkAccess
    sharedKeyAccess = 'Disabled'
    blobPublicAccess = 'Disabled'
    userAssignedIdentityName = $UserAssignedIdentityName
    userAssignedIdentityResourceGroupName = $UserAssignedIdentityResourceGroupName
    userAssignedIdentityResourceId = $identityResourceId
    userAssignedIdentityObjectId = $identityPrincipalId
    managedIdentityPolicyScope = $policyScope
    managedIdentityAllowedUsages = $allowedUsages
    backupCommand = ".\scripts\Backup-AdxDatabase.ps1 -ClusterUri '$ClusterUri' -DatabaseName '$DatabaseName' -StorageAccountName '$StorageAccountName' -FileSystemName '$FileSystemName' -ManagedIdentityObjectId '$identityPrincipalId'"
}

$result | ConvertTo-Json -Depth 10