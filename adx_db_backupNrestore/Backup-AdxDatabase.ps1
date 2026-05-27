<#
.SYNOPSIS
Backs up an ADX database schema and table data to ADLS Gen2 storage.

.DESCRIPTION
Runs the two-step ADX backup flow for a database:

1. Captures the database schema as CSL and JSON locally, then exports those
   schema records to ADLS Gen2 through ADX using a user-assigned managed identity.
2. Exports each selected table to compressed Parquet files in ADLS Gen2, one
   table per prefix, again using the same managed identity and RBAC.

The script waits for every async export operation and writes a local manifest
with operation IDs and exported artifact paths. No storage keys or SAS tokens are
used.

.EXAMPLE
.\adx_db_backupNrestore\Backup-AdxDatabase.ps1 -ClusterUri 'https://dibsecadx.eastus2.kusto.windows.net' -DatabaseName 'cyber-defend-q0xxzc' -StorageAccountName '<storage-account>' -ManagedIdentityObjectId '<uami-object-id>'

.EXAMPLE
.\adx_db_backupNrestore\Backup-AdxDatabase.ps1 -ClusterUri 'https://dibsecadx.eastus2.kusto.windows.net' -DatabaseName CyberDefenseKqlWorkshop -StorageAccountName '<storage-account>' -ManagedIdentityObjectId '<uami-object-id>' -TableName DeviceInfo,SecurityIncident

.NOTES
Name: Backup-AdxDatabase.ps1
Date: 2026-05-27
Dependencies: scripts\AdxWorkshop.Common.psm1, ADX database viewer/export permissions, and an ADX managed identity policy that allows ExportRequest for the supplied identity.
Key commands: .show database schema as csl script, .show database schema as json, .export async compressed to json/parquet, .show operations, .show operation details.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ClusterUri,
    [Parameter(Mandatory)][string]$DatabaseName,
    [Parameter(Mandatory)][string]$StorageAccountName,
    [string]$FileSystemName = 'adx-backups',
    [string]$ManagedIdentityObjectId,
    [string]$UserAssignedIdentityName,
    [string]$UserAssignedIdentityResourceGroupName = 'ADX',
    [string[]]$TableName,
    [string]$BackupName,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\data\backups'),
    [ValidateSet('gzip', 'snappy', 'lz4_raw', 'brotli', 'zstd')]
    [string]$ParquetCompressionType = 'snappy',
    [ValidateRange(104857600, 4294967296)]
    [long]$SizeLimitBytes = 1073741824,
    [ValidateRange(1, 3600)][int]$PollSeconds = 15,
    [ValidateRange(1, 1440)][int]$OperationTimeoutMinutes = 240,
    [switch]$SkipSchemaExport,
    [switch]$SkipDataExport
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\scripts\AdxWorkshop.Common.psm1') -Force

function Invoke-BackupAzCliJson {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$Arguments)

    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        throw 'Azure CLI is required when ManagedIdentityObjectId is not supplied.'
    }

    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & az @Arguments --output json 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    $text = [string]::Join([Environment]::NewLine, @($output | ForEach-Object { [string]$_ }))
    if ($exitCode -ne 0) {
        throw "Azure CLI command failed: az $($Arguments -join ' ') --output json`n$text"
    }

    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    $trimmed = $text.Trim()
    $objectStart = $trimmed.IndexOf('{')
    $arrayStart = $trimmed.IndexOf('[')
    $starts = @(@($objectStart, $arrayStart) | Where-Object { $_ -ge 0 } | Sort-Object)
    if ($starts.Count -eq 0) {
        throw "Azure CLI output did not contain JSON: $text"
    }

    return ($trimmed.Substring($starts[0]) | ConvertFrom-Json)
}

function ConvertTo-BackupPathSegment {
    param([Parameter(Mandatory)][string]$Value)

    return ($Value -replace '[^A-Za-z0-9_.=-]', '_')
}

function ConvertTo-KustoVerbatimStringLiteral {
    param([AllowEmptyString()][string]$Value = '')

    return "@'$($Value.Replace("'", "''"))'"
}

function ConvertTo-KustoObfuscatedVerbatimStringLiteral {
    param([AllowEmptyString()][string]$Value = '')

    return "h@'$($Value.Replace("'", "''"))'"
}

function Get-FirstAdxStringValue {
    param([Parameter(Mandatory)]$Response)

    $rows = @(ConvertFrom-WorkshopAdxResponseRows -Response $Response)
    foreach ($row in $rows) {
        foreach ($property in $row.PSObject.Properties) {
            if ($null -ne $property.Value -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
                return [string]$property.Value
            }
        }
    }

    throw 'ADX response did not include a schema string.'
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
    param(
        [Parameter(Mandatory)][string]$OperationId,
        [Parameter(Mandatory)][string]$ClusterUri,
        [Parameter(Mandatory)][string]$DatabaseName,
        [Parameter(Mandatory)][int]$PollSeconds,
        [Parameter(Mandatory)][int]$TimeoutMinutes
    )

    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
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

    throw "Timed out waiting for ADX operation $OperationId after $TimeoutMinutes minute(s)."
}

function Get-AdxOperationDetailsRows {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OperationId,
        [Parameter(Mandatory)][string]$ClusterUri,
        [Parameter(Mandatory)][string]$DatabaseName
    )

    $response = Invoke-WorkshopAdxManagementCommand -ClusterUri $ClusterUri -DatabaseName $DatabaseName -Command ".show operation $OperationId details" -ServerTimeoutSeconds 300
    return @(ConvertFrom-WorkshopAdxResponseRows -Response $response)
}

function Save-BackupManifest {
    param(
        [Parameter(Mandatory)]$Manifest,
        [Parameter(Mandatory)][string]$Path
    )

    $Manifest | ConvertTo-Json -Depth 30 | Set-Content -Path $Path -Encoding UTF8
}

if ([string]::IsNullOrWhiteSpace($ManagedIdentityObjectId)) {
    if ([string]::IsNullOrWhiteSpace($UserAssignedIdentityName)) {
        throw 'Supply ManagedIdentityObjectId, or supply UserAssignedIdentityName so the object ID can be resolved with Azure CLI.'
    }

    $identity = Invoke-BackupAzCliJson -Arguments @('identity', 'show', '--resource-group', $UserAssignedIdentityResourceGroupName, '--name', $UserAssignedIdentityName)
    $ManagedIdentityObjectId = [string]$identity.principalId
}

if ([string]::IsNullOrWhiteSpace($ManagedIdentityObjectId)) {
    throw 'Managed identity object ID could not be resolved.'
}

if ([string]::IsNullOrWhiteSpace($BackupName)) {
    $safeDatabaseName = ConvertTo-BackupPathSegment -Value $DatabaseName
    $BackupName = "$safeDatabaseName-$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))"
}

if (-not [System.IO.Path]::IsPathRooted($OutputDirectory)) {
    $OutputDirectory = Join-Path (Get-Location).Path $OutputDirectory
}
$backupDirectory = Join-Path $OutputDirectory (ConvertTo-BackupPathSegment -Value $BackupName)
New-Item -Path $backupDirectory -ItemType Directory -Force | Out-Null
$manifestPath = Join-Path $backupDirectory 'backup-manifest.json'
$schemaCslPath = Join-Path $backupDirectory 'schema.csl'
$schemaJsonPath = Join-Path $backupDirectory 'schema.json'
$capturedOn = (Get-Date).ToUniversalTime()
$databaseIdentifier = ConvertTo-WorkshopKustoIdentifier -Name $DatabaseName
$storageConnectionString = "https://$StorageAccountName.blob.core.windows.net/$FileSystemName;managed_identity=$ManagedIdentityObjectId"
$storageLiteral = ConvertTo-KustoObfuscatedVerbatimStringLiteral -Value $storageConnectionString

$manifest = [ordered]@{
    manifestVersion = 1
    capturedOn = $capturedOn.ToString('o')
    clusterUri = $ClusterUri
    databaseName = $DatabaseName
    storageAccountName = $StorageAccountName
    fileSystemName = $FileSystemName
    backupName = $BackupName
    managedIdentityObjectId = $ManagedIdentityObjectId
    localBackupDirectory = $backupDirectory
    schema = [ordered]@{}
    tables = @()
}

if (-not $SkipSchemaExport) {
    Write-Host "Capturing database schema for $DatabaseName"
    $schemaCslResponse = Invoke-WorkshopAdxManagementCommand -ClusterUri $ClusterUri -DatabaseName $DatabaseName -Command ".show database $databaseIdentifier schema as csl script" -ServerTimeoutSeconds 600
    $schemaCsl = Get-FirstAdxStringValue -Response $schemaCslResponse
    $schemaCsl | Set-Content -Path $schemaCslPath -Encoding UTF8

    $schemaJsonResponse = Invoke-WorkshopAdxManagementCommand -ClusterUri $ClusterUri -DatabaseName $DatabaseName -Command ".show database $databaseIdentifier schema as json" -ServerTimeoutSeconds 600
    $schemaJson = Get-FirstAdxStringValue -Response $schemaJsonResponse
    $schemaJson | Set-Content -Path $schemaJsonPath -Encoding UTF8

    $manifest.schema.localCslPath = $schemaCslPath
    $manifest.schema.localJsonPath = $schemaJsonPath

    foreach ($schemaExport in @(
        @{ Format = 'csl'; Text = $schemaCsl; Prefix = "$BackupName/schema/csl/" },
        @{ Format = 'json'; Text = $schemaJson; Prefix = "$BackupName/schema/json/" }
    )) {
        $formatLiteral = ConvertTo-WorkshopKustoStringLiteral -Value ([string]$schemaExport.Format)
        $databaseLiteral = ConvertTo-WorkshopKustoStringLiteral -Value $DatabaseName
        $schemaTextLiteral = ConvertTo-KustoVerbatimStringLiteral -Value ([string]$schemaExport.Text)
        $prefixLiteral = ConvertTo-WorkshopKustoStringLiteral -Value ([string]$schemaExport.Prefix)
        $capturedOnLiteral = $capturedOn.ToString('o')
        $schemaExportCommand = @"
.export async compressed to json ($storageLiteral) with (namePrefix=$prefixLiteral, compressionType='gzip')
<|
print DatabaseName=$databaseLiteral, CapturedOn=datetime($capturedOnLiteral), SchemaFormat=$formatLiteral, SchemaText=$schemaTextLiteral
"@
        Write-Host "Exporting $($schemaExport.Format) schema record to ADLS Gen2 prefix $($schemaExport.Prefix)"
        $schemaExportResponse = Invoke-WorkshopAdxManagementCommand -ClusterUri $ClusterUri -DatabaseName $DatabaseName -Command $schemaExportCommand -ServerTimeoutSeconds 1800
        $schemaOperationId = Get-AdxOperationIdFromResponse -Response $schemaExportResponse
        Wait-AdxOperationCompleted -OperationId $schemaOperationId -ClusterUri $ClusterUri -DatabaseName $DatabaseName -PollSeconds $PollSeconds -TimeoutMinutes $OperationTimeoutMinutes | Out-Null
        $schemaArtifacts = @(Get-AdxOperationDetailsRows -OperationId $schemaOperationId -ClusterUri $ClusterUri -DatabaseName $DatabaseName)
        $manifest.schema["$($schemaExport.Format)Export"] = [ordered]@{
            operationId = $schemaOperationId
            prefix = [string]$schemaExport.Prefix
            artifacts = $schemaArtifacts
        }
        Save-BackupManifest -Manifest $manifest -Path $manifestPath
    }
}

if (-not $SkipDataExport) {
    Write-Host "Reading ADX table list from $DatabaseName"
    $tablesResponse = Invoke-WorkshopAdxManagementCommand -ClusterUri $ClusterUri -DatabaseName $DatabaseName -Command '.show tables | project TableName' -ServerTimeoutSeconds 600
    $tables = @(ConvertFrom-WorkshopAdxResponseRows -Response $tablesResponse | ForEach-Object { [string]$_.TableName } | Sort-Object)
    if ($TableName) {
        $tables = @($tables | Where-Object { $TableName -contains $_ })
    }
    if ($tables.Count -eq 0) {
        throw 'No ADX tables were selected for backup.'
    }

    foreach ($table in $tables) {
        $tableIdentifier = ConvertTo-WorkshopKustoIdentifier -Name $table
        $tablePrefix = "$BackupName/data/$(ConvertTo-BackupPathSegment -Value $table)/"
        $prefixLiteral = ConvertTo-WorkshopKustoStringLiteral -Value $tablePrefix
        $compressionLiteral = ConvertTo-WorkshopKustoStringLiteral -Value $ParquetCompressionType
        $exportCommand = @"
.export async compressed to parquet ($storageLiteral) with (namePrefix=$prefixLiteral, compressionType=$compressionLiteral, sizeLimit=$SizeLimitBytes)
<|
$tableIdentifier
"@
        Write-Host "Exporting table $table to ADLS Gen2 prefix $tablePrefix"
        $exportResponse = Invoke-WorkshopAdxManagementCommand -ClusterUri $ClusterUri -DatabaseName $DatabaseName -Command $exportCommand -ServerTimeoutSeconds 1800
        $operationId = Get-AdxOperationIdFromResponse -Response $exportResponse
        Wait-AdxOperationCompleted -OperationId $operationId -ClusterUri $ClusterUri -DatabaseName $DatabaseName -PollSeconds $PollSeconds -TimeoutMinutes $OperationTimeoutMinutes | Out-Null
        $artifacts = @(Get-AdxOperationDetailsRows -OperationId $operationId -ClusterUri $ClusterUri -DatabaseName $DatabaseName)
        $manifest.tables += [ordered]@{
            tableName = $table
            prefix = $tablePrefix
            format = 'parquet'
            compressionType = $ParquetCompressionType
            operationId = $operationId
            artifacts = $artifacts
        }
        Save-BackupManifest -Manifest $manifest -Path $manifestPath
    }
}

Save-BackupManifest -Manifest $manifest -Path $manifestPath
Write-Host "ADX backup complete. Manifest: $manifestPath"
$manifest | ConvertTo-Json -Depth 30