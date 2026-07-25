# Managed Azure ADX + Microsoft Entra B2B (secondary delivery model)

> **Scope.** This guide covers the **secondary** delivery model end to end: standing up a managed Azure Data Explorer cluster database, generating and ingesting the workshop telemetry, and provisioning participants as Microsoft Entra B2B guests.
>
> For the **primary** conference route — Docker Kustainer, Cloudflare Service Auth, and the read-only gateway — stay in the [repository README](../README.md) and [docs/cloudflare_adx_access.md](cloudflare_adx_access.md).

## When to use this model

| Delivery model | Position | Best fit |
| --- | --- | --- |
| Docker Kustainer + Cloudflare Service Auth | **Primary** | Time-boxed security conferences, random participants, and fast classroom setup. |
| Managed Azure ADX + Microsoft Entra B2B | **Secondary** | Governed, recurring, or long-running programs that require per-person identities, MFA policy, and lifecycle governance. |

Choose this route when you need per-person identities, Conditional Access and MFA enforcement, access-package lifecycle, and auditable offboarding. It costs more setup time and requires tenant permissions that a walk-up conference audience will not have.

---

## Prerequisites

Use these only for the managed Azure delivery model:

- An existing ADX cluster and permissions to create or manage the workshop database
- ADX database admin permissions for table creation and ingestion
- Entra permissions for B2B guest onboarding, access packages, security groups, and Conditional Access
- PowerShell 7 with the Azure, Kusto, and Microsoft Graph modules installed

### Tooling install commands

Install PowerShell 7 silently / non-interactively from Windows Terminal, Command Prompt, or an existing PowerShell session:

```powershell
winget install --id Microsoft.PowerShell --source winget --silent --accept-package-agreements --accept-source-agreements
```

After PowerShell 7 installs, open a new **PowerShell 7** terminal and install the required modules:

```powershell
Install-Module -Name Az -Repository PSGallery -Scope CurrentUser -Force
Install-Module -Name Az.Kusto -Repository PSGallery -Scope CurrentUser -Force
Install-Module -Name Microsoft.Graph -Repository PSGallery -Scope CurrentUser -Force
```

Install Azure CLI silently / non-interactively:

```powershell
winget install --id Microsoft.AzureCLI --source winget --silent --accept-package-agreements --accept-source-agreements
```

Close and reopen the terminal after installing PowerShell 7 or Azure CLI.

### 🔗 Official install references

- PowerShell 7 on Windows: <https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-windows>
- Azure PowerShell Az module: <https://learn.microsoft.com/powershell/azure/install-azure-powershell>
- Az.Kusto module reference: <https://learn.microsoft.com/powershell/module/az.kusto/>
- Azure CLI on Windows: <https://learn.microsoft.com/cli/azure/install-azure-cli-windows>
- Microsoft Graph PowerShell SDK: <https://learn.microsoft.com/microsoftgraph/installation>

---

## Setup

Run all commands from the repository root.

### 1. Refresh table schemas from Microsoft Learn

The repository already includes generated schemas. Use this command only when you want to refresh them from Microsoft Learn.

```powershell
.\tools\Build-SchemasFromMicrosoftLearn.ps1 -Force
```

For tables that Microsoft Learn does not document yet, or whose published schema lags the live one, build the schema straight from the live table instead. This is how the `AgentsInfo`, `StorageBlobLogs`, `IntuneDevices`, `SecurityEvent`, the email tables, and the cloud control plane tables were added.

```powershell
.\tools\Build-SchemaFromLiveTable.ps1 -TableName AgentsInfo, StorageBlobLogs, IntuneDevices
.\tools\Build-SchemaFromLiveTable.ps1 -TableName SecurityEvent -Source LogAnalytics
.\tools\Build-SchemaFromLiveTable.ps1 -TableName ThreatIntelIndicators, SecurityAlert, AzureActivity, ASimDnsActivityLogs, OfficeActivity -Source LogAnalytics
.\tools\Build-SchemaFromLiveTable.ps1 -TableName ExposureGraphNodes, ExposureGraphEdges, CloudStorageAggregatedEvents
```

`ThreatIntelIndicators` is the current threat intelligence table. The legacy `ThreatIntelligenceIndicator` table is empty in this tenant and is deliberately not used.

This builder reads `<Table> | getschema`, which is metadata only. That matters for three tables: `ExposureGraphEdges` times out against the advanced hunting data API, and `AADRiskyServicePrincipals` and `AADServicePrincipalRiskEvents` hold no rows in the source tenant. All three still yield an exact live schema because `getschema` does not read data.

### 2. Sample real telemetry to ground synthetic generation

Synthetic realism is measured against real telemetry rather than guessed. This exports up to 1000 rows per table from the Log Analytics workspace and Microsoft Defender XDR advanced hunting, writes them as NDJSON under `sample\<DTG>\`, and writes a per-column field profile next to them.

The generator reads those profiles automatically and uses the observed distinct-value ratios, null rates, and enum distributions when it fills columns. Dated export folders are git-ignored because they contain real tenant identities.

```powershell
.\scripts\Export-TenantTelemetrySamples.ps1 -MaxRowsPerTable 1000 -LookbackDays 90
```

Log Analytics access uses the Az context. Defender advanced hunting uses Microsoft Graph with the `ThreatHunting.Read.All` delegated scope through interactive browser sign-in. Advanced hunting retains 30 days regardless of the requested lookback.

### 3. Generate telemetry at workshop volume

The single-process generator is fine for one table. For the full set, use the parallel driver, which partitions tables across worker processes. Output is identical either way because the generator reseeds per table from `RandomSeed` XOR the table seed.

```powershell
.\scripts\New-SyntheticTelemetryParallel.ps1 -RowsPerTable 8000
```

Row counts are resolved per table. `DeviceProcessEvents` defaults to 32000 because process creation is by a wide margin the highest-volume endpoint table, and small reference tables are reduced. Override any table explicitly:

```powershell
.\scripts\New-SyntheticTelemetryParallel.ps1 -RowsPerTable 8000 -TableRowOverride @{ DeviceProcessEvents = 32000; DeviceNetworkEvents = 16000 }
```

> ⚠️ **Generated telemetry is large.** The full 79-table set at 8000 rows per table is roughly 876 MB, and `DeviceProcessEvents` alone is 92 MB. It is committed so the workshop can be run without Azure access, but it is fully reproducible from the generator, so prefer regenerating over re-committing it. `Initialize-Workshop.ps1` regenerates it by default unless you pass `-SkipGenerateData`.

### 4. Build the ADX database, tables, mappings, and ingest data

```powershell
.\scripts\Initialize-Workshop.ps1 `
  -ResourceGroupName '<resource-group>' `
  -ClusterName '<adx-cluster-name>' `
  -DatabaseName 'CyberDefenseKqlWorkshop' `
  -ForceRecreateTables
```

If the database already exists and you only need to create tables and load data:

```powershell
.\scripts\Initialize-Workshop.ps1 `
  -ResourceGroupName '<resource-group>' `
  -ClusterName '<adx-cluster-name>' `
  -ClusterUri 'https://<cluster>.<region>.kusto.windows.net' `
  -DatabaseName 'CyberDefenseKqlWorkshop' `
  -SkipDatabaseCreate `
  -ForceRecreateTables
```

### 5. Optional: back up the ADX database to secured ADLS Gen2

The backup flow uses a user-assigned managed identity, RBAC, no shared keys, and no anonymous blob access. The default storage mode disables public network access and creates ADX managed private endpoints to the storage account.

```powershell
.\adx_db_backupNrestore\Initialize-AdxBackupStorage.ps1 `
  -SubscriptionName 'Security' `
  -ResourceGroupName 'ADX' `
  -ClusterName 'dibsecadx' `
  -ClusterUri 'https://dibsecadx.eastus2.kusto.windows.net' `
  -DatabaseName 'cyber-defend-q0xxzc'
```

Use the `backupCommand` from that script's JSON output, or run the backup directly:

```powershell
.\adx_db_backupNrestore\Backup-AdxDatabase.ps1 `
  -ClusterUri 'https://dibsecadx.eastus2.kusto.windows.net' `
  -DatabaseName 'cyber-defend-q0xxzc' `
  -StorageAccountName '<storage-account-name>' `
  -FileSystemName 'adx-backups' `
  -ManagedIdentityObjectId '<uami-object-id>'
```

Restore later from the generated local manifest and schema file:

```powershell
.\adx_db_backupNrestore\Restore-AdxDatabaseBackup.ps1 `
  -ClusterUri 'https://dibsecadx.eastus2.kusto.windows.net' `
  -DatabaseName '<restore-database-name>' `
  -ManifestPath '.\data\backups\<backup-name>\backup-manifest.json'
```

For operational details and the security model, see [`adx_db_backupNrestore\adx_backup.md`](../adx_db_backupNrestore/adx_backup.md).

---

## Participant access with Microsoft Entra B2B

Provision students as Microsoft Entra B2B guests through an entitlement management access package. The access package should add approved participants to a resource-tenant security group, enforce MFA through Conditional Access, and expire access after the event.

Grant ADX database viewer access to the participant security group:

```powershell
.\scripts\Grant-StudentAdxAccess.ps1 `
  -ClusterUri 'https://<cluster>.<region>.kusto.windows.net' `
  -DatabaseName 'CyberDefenseKqlWorkshop' `
  -GroupObjectId '<student-group-object-id>'
```

### Give participants the ADX Web UI URL

```text
https://dataexplorer.azure.com/clusters/<cluster>.<region>.kusto.windows.net/databases/CyberDefenseKqlWorkshop
```

Students sign in with their home organization identity, redeem the guest invitation when prompted, and complete MFA according to the resource tenant policy.

After login, students should see the ADX database, workshop tables, and query results in the web UI. The screenshot below shows the expected query experience using `SecurityIncident` telemetry:

![ADX Web UI showing SecurityIncident query results](../images/adx-query-securityincident-results.png)

### Share the dashboard

Import the dashboard as described in the [README dashboard section](../README.md#import-the-adx-soc-threat-protection-dashboard), then share it with the participant security group using dashboard `Can view` permission and distribute the link. Dashboard access still requires underlying ADX database viewer access.

---

## Security and lifecycle notes

- Use B2B guest access only for this managed Azure model. External conference participants should use the primary Docker and Cloudflare Service Auth route instead.
- Treat generated student roster CSV files as sensitive if using the internal-only identity helper scripts, because they may contain initial passwords or TAP values.
- Treat ADX backup manifests and local `schema.csl` files as sensitive operational artifacts. Local backups are written under `data\backups\`, which is git-ignored.
- ADX backups use ADLS Gen2, a user-assigned managed identity, RBAC, disabled shared-key access, and disabled anonymous blob access. Prefer the default managed-private-endpoint mode for nonpublic storage.
- Expire or remove participant access package assignments after the event and confirm the participant security group is empty.
- If reusing the ADX database for another class, rerun setup with `-ForceRecreateTables`.

---

## Related documentation

- Repository README (primary Docker-first route): [`README.md`](../README.md)
- B2B user provisioning detail: [`user_creation\README.md`](../user_creation/README.md)
- Student access guide: [`docs\student_access.md`](student_access.md)
- ADX backup guide: [`adx_db_backupNrestore\adx_backup.md`](../adx_db_backupNrestore/adx_backup.md)
- ADX cluster Bicep templates: [`azure-data-explorer\README.md`](../azure-data-explorer/README.md)
