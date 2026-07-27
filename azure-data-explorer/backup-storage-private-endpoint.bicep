targetScope = 'resourceGroup'

@description('Name of the student ADX cluster that owns the managed private endpoint.')
param clusterName string

@description('Name for the managed private endpoint, for example mpe-<storageAccount>-dfs.')
param dfsEndpointName string

// No default. This previously carried a real subscription id and storage account
// name, which put tenant identifiers into a tracked template. Pass them at deploy
// time from workshop.settings.json or a .bicepparam file kept outside the repo.
@description('Full resource id of the ADLS Gen2 backup storage account.')
param backupStorageResourceId string

@description('Region of the backup storage account, for example eastus2.')
param backupStorageRegion string

resource backupStorageDfsPrivateEndpoint 'Microsoft.Kusto/clusters/managedPrivateEndpoints@2024-04-13' = {
  name: '${clusterName}/${dfsEndpointName}'
  properties: {
    groupId: 'dfs'
    privateLinkResourceId: backupStorageResourceId
    privateLinkResourceRegion: backupStorageRegion
    requestMessage: 'Student ADX Cyber Defend database restore access.'
  }
}

output dfsManagedPrivateEndpointResourceId string = backupStorageDfsPrivateEndpoint.id
