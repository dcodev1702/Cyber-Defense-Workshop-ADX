# ADX Database Backup and Restore

This workflow backs up an Azure Data Explorer database with the two-step method:

1. Capture the database schema as a CSL recreation script and JSON schema record.
2. Export each table to ADLS Gen2 as compressed Parquet under a per-table prefix.

The storage path is designed for a user-assigned managed identity (UAMI), Azure RBAC, no shared keys, and no anonymous blob access.

## Security Model

`Initialize-AdxBackupStorage.ps1` creates or reuses:

- An ADLS Gen2 storage account with hierarchical namespace enabled.
- A private filesystem named `adx-backups` by default.
- A user-assigned managed identity.
- `Storage Blob Data Contributor` for the UAMI scoped to the storage account.
- An ADX managed identity policy allowing `ExportRequest` and `NativeIngestion` for the UAMI. The script tries database scope first and falls back to cluster scope if the ADX service rejects the database-scope policy merge.

By default, the storage account is configured with:

- `allowSharedKeyAccess = false`
- `allowBlobPublicAccess = false`
- public network access disabled
- ADX managed private endpoints for `blob` and `dfs`

If managed private endpoint approval is not available in your role, rerun with `-StorageNetworkMode TrustedServices` to use a storage firewall deny-by-default posture with the Azure trusted services bypass.

## Provision Backup Storage

```powershell
.\adx_db_backupNrestore\Initialize-AdxBackupStorage.ps1 `
  -SubscriptionName 'Security' `
  -ResourceGroupName 'ADX' `
  -ClusterName 'dibsecadx' `
  -ClusterUri 'https://dibsecadx.eastus2.kusto.windows.net' `
  -DatabaseName 'cyber-defend-q0xxzc'
```

The script emits JSON with the storage account, filesystem, UAMI object ID, and a ready-to-run `backupCommand`.

## Run a Backup

```powershell
.\adx_db_backupNrestore\Backup-AdxDatabase.ps1 `
  -ClusterUri 'https://dibsecadx.eastus2.kusto.windows.net' `
  -DatabaseName 'cyber-defend-q0xxzc' `
  -StorageAccountName '<storage-account-name>' `
  -FileSystemName 'adx-backups' `
  -ManagedIdentityObjectId '<uami-object-id>'
```

The backup writes:

- Local `schema.csl`, `schema.json`, and `backup-manifest.json` under `data\backups\<backup-name>\`.
- Schema records in ADLS under `<backup-name>/schema/csl/` and `<backup-name>/schema/json/`.
- Parquet table exports under `<backup-name>/data/<table-name>/`.

To back up a subset of tables:

```powershell
.\adx_db_backupNrestore\Backup-AdxDatabase.ps1 `
  -ClusterUri 'https://dibsecadx.eastus2.kusto.windows.net' `
  -DatabaseName 'cyber-defend-q0xxzc' `
  -StorageAccountName '<storage-account-name>' `
  -ManagedIdentityObjectId '<uami-object-id>' `
  -TableName DeviceInfo,SecurityIncident
```

## Restore or Import Later

Create the target database first, then run:

```powershell
.\adx_db_backupNrestore\Restore-AdxDatabaseBackup.ps1 `
  -ClusterUri 'https://dibsecadx.eastus2.kusto.windows.net' `
  -DatabaseName '<restore-database-name>' `
  -ManifestPath '.\data\backups\<backup-name>\backup-manifest.json'
```

Use `-ClearExistingData` only when the restore target already contains data that should be removed before ingesting the backup artifacts.

## Notes

- The ADX export/import operations use `;managed_identity=<uami-object-id>` in Kusto storage connection strings.
- The local manifest is important because it records the exact Parquet artifact paths returned by `.show operation <operation-id> details`.
- Keep `schema.csl` with the manifest. The schema is also exported into ADLS as a JSON record, but the restore script intentionally reads the local CSL file so it can execute the recreation script directly.
- For strict private storage, keep the default managed-private-endpoint mode. ADX Parquet export uses the storage `blob` endpoint; the script also creates a `dfs` endpoint for ADLS Gen2 filesystem access.