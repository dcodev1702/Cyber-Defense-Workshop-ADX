<#
.SYNOPSIS
Restores an ADX database backup created by Backup-AdxDatabase.ps1.

.DESCRIPTION
Replays the captured schema.csl file with .execute database script, then ingests
the exported Parquet artifacts listed in backup-manifest.json into matching ADX
tables. Storage reads use the user-assigned managed identity in each Kusto
storage connection string; no storage keys or SAS tokens are used.

.EXAMPLE
.\scripts\Restore-AdxDatabaseBackup.ps1 -ClusterUri 'https://dibsecadx.eastus2.kusto.windows.net' -DatabaseName 'cyber-defend-restore' -ManifestPath '.\data\backups\cyber-defend-q0xxzc-20260527T120000Z\backup-manifest.json'

.EXAMPLE
.\scripts\Restore-AdxDatabaseBackup.ps1 -ManifestPath '.\data\backups\backup-manifest.json' -DatabaseName 'cyber-defend-restore' -ClearExistingData -TableName DeviceInfo,SecurityIncident

.NOTES
Name: Restore-AdxDatabaseBackup.ps1
Date: 2026-05-27
Dependencies: scripts\AdxWorkshop.Common.psm1, ADX database admin permissions, managed identity policy with NativeIngestion, Storage Blob Data Reader or Contributor on the ADLS Gen2 account.
Key commands: .execute database script, .clear table data, .ingest async into table, .show operations.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ManifestPath,
    [string]$ClusterUri,
    [string]$DatabaseName,
    [string]$ManagedIdentityObjectId,
    [string[]]$TableName,
    [ValidateRange(1, 250)]
    [int]$ArtifactBatchSize = 50,
    [ValidateRange(1, 3600)][int]$PollSeconds = 15,
    [ValidateRange(1, 1440)][int]$OperationTimeoutMinutes = 240,
    [switch]$SkipSchema,
    [switch]$SkipData,
    [switch]$ClearExistingData,
    [switch]$NoWait
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'AdxWorkshop.Common.psm1') -Force

function ConvertTo-KustoObfuscatedVerbatimStringLiteral {
    param([AllowEmptyString()][string]$Value = '')

    return "h@'$($Value.Replace("'", "''"))'"
}

function Get-AdxOperationIdFromResponse {
    param([Parameter(Mandatory)]$Response)

    $rows = @(ConvertFrom-WorkshopAdxResponseRows -Response $Response)
    foreach ($row in $rows) {
        foreach ($property in $row.PSObject.Properties) {
            $value = [string]$property.Value
            if ([string]::IsNullOrWhiteSpace($value)) {
                continue
            }

            $parsedGuid = [guid]::Empty
            if ([guid]::TryParse($value, [ref]$parsedGuid)) {
                return $parsedGuid.ToString()
            }
        }
    }

    throw 'ADX async command did not return an operation ID.'
}

function Wait-AdxOperationCompleted {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$OperationId)

    $deadline = (Get-Date).AddMinutes($OperationTimeoutMinutes)
    do {
        $response = Invoke-WorkshopAdxManagementCommand -ClusterUri $ClusterUri -DatabaseName $DatabaseName -Command ".show operations $OperationId" -ServerTimeoutSeconds 300
        $rows = @(ConvertFrom-WorkshopAdxResponseRows -Response $response)
        if ($rows.Count -gt 0) {
            $row = $rows | Select-Object -First 1
            $state = [string]$row.State
            $status = [string]$row.Status
            Write-Host "ADX operation $OperationId state: $state"
            switch ($state) {
                'Completed' { return $row }
                'Failed' { throw "ADX operation $OperationId failed: $status" }
                'PartiallySucceeded' { throw "ADX operation $OperationId partially succeeded: $status" }
                'Abandoned' { throw "ADX operation $OperationId was abandoned: $status" }
                'BadInput' { throw "ADX operation $OperationId had bad input: $status" }
                'Canceled' { throw "ADX operation $OperationId was canceled: $status" }
                'Throttled' { throw "ADX operation $OperationId was throttled: $status" }
            }
        }
        else {
            Write-Host "ADX operation $OperationId has not appeared in .show operations yet."
        }

        Start-Sleep -Seconds $PollSeconds
    } while ((Get-Date) -lt $deadline)

    throw "Timed out waiting for ADX operation $OperationId after $OperationTimeoutMinutes minute(s)."
}

function Get-BackupArtifactPath {
    param([Parameter(Mandatory)]$Artifact)

    foreach ($property in $Artifact.PSObject.Properties) {
        $value = [string]$property.Value
        if ($value -match '^https?://') {
            return (($value -split ';')[0])
        }
    }

    return $null
}

function Split-BackupBatches {
    param(
        [Parameter(Mandatory)][object[]]$Items,
        [Parameter(Mandatory)][int]$BatchSize
    )

    for ($offset = 0; $offset -lt $Items.Count; $offset += $BatchSize) {
        $end = [Math]::Min($offset + $BatchSize - 1, $Items.Count - 1)
        ,@($Items[$offset..$end])
    }
}

if (-not (Test-Path $ManifestPath)) {
    throw "Backup manifest not found: $ManifestPath"
}
if (-not [System.IO.Path]::IsPathRooted($ManifestPath)) {
    $ManifestPath = Join-Path (Get-Location).Path $ManifestPath
}

$manifestDirectory = Split-Path -Path $ManifestPath -Parent
$manifest = Get-Content -Path $ManifestPath -Raw | ConvertFrom-Json
if ([string]::IsNullOrWhiteSpace($ClusterUri)) {
    $ClusterUri = [string]$manifest.clusterUri
}
if ([string]::IsNullOrWhiteSpace($DatabaseName)) {
    $DatabaseName = [string]$manifest.databaseName
}
if ([string]::IsNullOrWhiteSpace($ManagedIdentityObjectId)) {
    $ManagedIdentityObjectId = [string]$manifest.managedIdentityObjectId
}
if ([string]::IsNullOrWhiteSpace($ClusterUri) -or [string]::IsNullOrWhiteSpace($DatabaseName) -or [string]::IsNullOrWhiteSpace($ManagedIdentityObjectId)) {
    throw 'ClusterUri, DatabaseName, and ManagedIdentityObjectId must be supplied either as parameters or in the manifest.'
}

if (-not $SkipSchema) {
    $schemaCslPath = [string]$manifest.schema.localCslPath
    if ([string]::IsNullOrWhiteSpace($schemaCslPath) -or -not (Test-Path $schemaCslPath)) {
        $schemaCslPath = Join-Path $manifestDirectory 'schema.csl'
    }
    if (-not (Test-Path $schemaCslPath)) {
        throw "Schema CSL file not found. Expected local schema.csl next to the manifest or at manifest path '$($manifest.schema.localCslPath)'."
    }

    Write-Host "Executing schema script $schemaCslPath against $DatabaseName"
    $schemaScript = Get-Content -Path $schemaCslPath -Raw
    $executeCommand = ".execute database script with (ThrowOnErrors=true) <|`n$schemaScript"
    Invoke-WorkshopAdxManagementCommand -ClusterUri $ClusterUri -DatabaseName $DatabaseName -Command $executeCommand -ServerTimeoutSeconds 1800 | Out-Null
}

if (-not $SkipData) {
    $tableEntries = @($manifest.tables)
    if ($TableName) {
        $tableEntries = @($tableEntries | Where-Object { $TableName -contains [string]$_.tableName })
    }
    if ($tableEntries.Count -eq 0) {
        throw 'No table entries were selected from the backup manifest.'
    }

    foreach ($tableEntry in $tableEntries) {
        $table = [string]$tableEntry.tableName
        $tableIdentifier = ConvertTo-WorkshopKustoIdentifier -Name $table
        $artifactPaths = @($tableEntry.artifacts | ForEach-Object { Get-BackupArtifactPath -Artifact $_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($artifactPaths.Count -eq 0) {
            Write-Warning "Skipping $table because no artifact paths were found in the manifest."
            continue
        }

        if ($ClearExistingData) {
            Write-Host "Clearing existing data from $table"
            Invoke-WorkshopAdxManagementCommand -ClusterUri $ClusterUri -DatabaseName $DatabaseName -Command ".clear table $tableIdentifier data" -ServerTimeoutSeconds 1800 | Out-Null
        }

        foreach ($batch in (Split-BackupBatches -Items $artifactPaths -BatchSize $ArtifactBatchSize)) {
            $sourceLiterals = foreach ($artifactPath in $batch) {
                ConvertTo-KustoObfuscatedVerbatimStringLiteral -Value "$artifactPath;managed_identity=$ManagedIdentityObjectId"
            }
            $sourceList = $sourceLiterals -join ', '
            $ingestCommand = ".ingest async into table $tableIdentifier ($sourceList) with (format='parquet')"
            Write-Host "Ingesting $($batch.Count) Parquet artifact(s) into $table"
            $response = Invoke-WorkshopAdxManagementCommand -ClusterUri $ClusterUri -DatabaseName $DatabaseName -Command $ingestCommand -ServerTimeoutSeconds 1800
            $operationId = Get-AdxOperationIdFromResponse -Response $response
            if (-not $NoWait) {
                Wait-AdxOperationCompleted -OperationId $operationId | Out-Null
            }
        }
    }
}

Write-Host "ADX restore/import complete for database $DatabaseName."