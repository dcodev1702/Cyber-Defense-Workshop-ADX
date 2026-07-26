<#
.SYNOPSIS
Creates a portable backup archive for the local Kustainer Student snapshot.

.DESCRIPTION
Archives the persisted database state, any Kustainer recovery directories, and a
restorable NDJSON payload. Stop Kusto before running the script when a
point-in-time backup is required.

The NDJSON payload matters because the emulator keeps its persistent-database
registration inside the container rather than in the mounted state directory. A
fresh container therefore cannot attach the persisted state, and the NDJSON is
what actually makes the archive restorable.

The payload is taken from data\generated, which is the current source of truth
now that the package is produced by scripts\New-SyntheticTelemetry.ps1. If that
directory is empty the script falls back to the newest verified export beneath
data\local-export. Either way the payload is checked against the table manifest,
so an archive cannot silently ship fewer tables than the package defines.

.EXAMPLE
docker compose stop kusto
.\scripts\Backup-LocalKustoSnapshot.ps1
docker compose start kusto

.EXAMPLE
.\scripts\Backup-LocalKustoSnapshot.ps1 -UseLocalExport
#>
[CmdletBinding()]
param(
    [string]$DatabaseName = 'CyberDefendStudentSnapshot',
    [string]$LocalStateDirectory = (Join-Path $PSScriptRoot '..' 'data' 'local-kusto'),
    [string]$ExportRootDirectory = (Join-Path $PSScriptRoot '..' 'data' 'local-export'),
    [string]$GeneratedDirectory = (Join-Path $PSScriptRoot '..' 'data' 'generated'),
    [string]$TableManifestPath = (Join-Path $PSScriptRoot '..' 'metadata' 'tables.manifest.json'),
    [string]$SchemaDirectory = (Join-Path $PSScriptRoot '..' 'schemas'),
    [string]$BackupDirectory = (Join-Path $PSScriptRoot '..' 'data' 'backups' 'local-kusto'),
    [switch]$UseLocalExport,
    [switch]$AllowIncompleteExport
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$databaseRoot = Join-Path $LocalStateDirectory 'dbs'
$stateDirectories = @(
    Get-ChildItem -LiteralPath $databaseRoot -Directory |
        Where-Object { $_.Name -eq $DatabaseName -or $_.Name -like "$DatabaseName.recovery-*" } |
        Sort-Object Name
)
if ($stateDirectories.Count -eq 0) {
    throw "No persisted state directory was found for local database '$DatabaseName' beneath '$databaseRoot'."
}

# The archive needs a payload a fresh container can actually restore from. The
# emulator keeps its persistent-database registration inside the container rather
# than in the mounted state, so persisted state alone cannot be attached by a new
# container; the NDJSON is what makes the archive restorable.
#
# data\generated is preferred because the workshop package is now produced by
# scripts\New-SyntheticTelemetry.ps1 and is the current source of truth. Earlier
# versions of this script always took the newest data\local-export snapshot,
# which silently shipped a stale copy from the last Azure Data Explorer sync.
$manifestTables = @()
if (Test-Path -LiteralPath $TableManifestPath) {
    $manifestTables = @((Get-Content -Raw $TableManifestPath | ConvertFrom-Json) | ForEach-Object { $_.name })
}

$exportSourcePath = $null
$exportSourceKind = $null

if (-not $UseLocalExport) {
    $generatedFiles = @(Get-ChildItem -LiteralPath $GeneratedDirectory -Filter '*.json' -ErrorAction SilentlyContinue)
    if ($generatedFiles.Count -gt 0) {
        $exportSourcePath = (Resolve-Path $GeneratedDirectory).Path
        $exportSourceKind = 'generated'
    }
}

if (-not $exportSourcePath) {
    $localExport = @(
        Get-ChildItem -LiteralPath $ExportRootDirectory -Directory -ErrorAction SilentlyContinue |
            Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'local-kusto-manifest.json') } |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
    )
    if ($localExport.Count -ne 1) {
        throw "No restorable export was found. Generate the package with scripts\New-SyntheticTelemetry.ps1, or provide a verified export beneath '$ExportRootDirectory'."
    }
    $exportSourcePath = $localExport[0].FullName
    $exportSourceKind = 'local-export'
}

# Refuse to ship an archive whose payload does not cover the package. This is the
# check that was missing when a 48-table export was backed up against a 79-table
# database without anything reporting a problem.
$exportTables = @(Get-ChildItem -LiteralPath $exportSourcePath -File |
    Where-Object { $_.Extension -in @('.json', '.ndjson') -and $_.BaseName -notlike '*manifest*' } |
    ForEach-Object { $_.BaseName })

if ($manifestTables.Count -gt 0) {
    $missing = @($manifestTables | Where-Object { $exportTables -notcontains $_ })
    if ($missing.Count -gt 0 -and -not $AllowIncompleteExport) {
        throw ("The export at '{0}' covers {1} of the {2} tables in the manifest and is missing: {3}. Regenerate the package, or pass -AllowIncompleteExport to archive it anyway." -f `
            $exportSourcePath, $exportTables.Count, $manifestTables.Count, (($missing | Select-Object -First 8) -join ', '))
    }
}

Write-Host ("Export payload : {0} ({1} table(s), source '{2}')" -f $exportSourcePath, $exportTables.Count, $exportSourceKind)


New-Item -ItemType Directory -Path $BackupDirectory -Force | Out-Null
$timestamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$archivePath = Join-Path $BackupDirectory "$DatabaseName-$timestamp.zip"
$stagingPath = Join-Path ([System.IO.Path]::GetTempPath()) "$DatabaseName-backup-$timestamp"
$utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)

try {
    New-Item -ItemType Directory -Path $stagingPath -Force | Out-Null
    $stateStagingPath = Join-Path $stagingPath 'persistent-state'
    New-Item -ItemType Directory -Path $stateStagingPath -Force | Out-Null

    foreach ($stateDirectory in $stateDirectories) {
        Copy-Item -LiteralPath $stateDirectory.FullName -Destination (Join-Path $stateStagingPath $stateDirectory.Name) -Recurse -Force
    }

    $exportStagingPath = Join-Path $stagingPath 'export'
    Copy-Item -LiteralPath $exportSourcePath -Destination $exportStagingPath -Recurse -Force

    # Ship the table schemas and manifest inside the archive so a restore does not
    # depend on a matching checkout being present. Without these the NDJSON cannot
    # be ingested, because every table has to be created before it is loaded.
    $schemaStagingPath = Join-Path $stagingPath 'schemas'
    New-Item -ItemType Directory -Path $schemaStagingPath -Force | Out-Null
    if (Test-Path -LiteralPath $SchemaDirectory) {
        Copy-Item -Path (Join-Path $SchemaDirectory '*') -Destination $schemaStagingPath -Recurse -Force
    }
    if (Test-Path -LiteralPath $TableManifestPath) {
        Copy-Item -LiteralPath $TableManifestPath -Destination (Join-Path $stagingPath 'tables.manifest.json') -Force
    }

    $stateBytes = [long](($stateDirectories | ForEach-Object {
        Get-ChildItem -LiteralPath $_.FullName -File -Recurse | Measure-Object -Property Length -Sum
    } | ForEach-Object { $_.Sum } | Measure-Object -Sum).Sum)
    $exportBytes = [long]((Get-ChildItem -LiteralPath $exportSourcePath -File -Recurse | Measure-Object -Property Length -Sum).Sum)
    $manifest = [ordered]@{
        manifestVersion = 2
        createdOn = (Get-Date).ToUniversalTime().ToString('o')
        databaseName = $DatabaseName
        stateDirectories = @($stateDirectories | ForEach-Object Name)
        # Recorded so a restore can tell at a glance what the payload covers,
        # rather than discovering a short table count only when it is needed.
        exportSource = $exportSourceKind
        exportSnapshot = (Split-Path $exportSourcePath -Leaf)
        exportTableCount = $exportTables.Count
        manifestTableCount = $manifestTables.Count
        exportTables = @($exportTables | Sort-Object)
        persistentStateBytes = $stateBytes
        exportBytes = $exportBytes
    }
    [System.IO.File]::WriteAllText(
        (Join-Path $stagingPath 'backup-manifest.json'),
        ($manifest | ConvertTo-Json -Depth 10),
        $utf8WithoutBom
    )

    Compress-Archive -Path (Join-Path $stagingPath '*') -DestinationPath $archivePath -CompressionLevel Optimal
    $archive = Get-Item -LiteralPath $archivePath
    $hash = Get-FileHash -LiteralPath $archivePath -Algorithm SHA256
    [pscustomobject]@{
        ArchivePath = $archive.FullName
        ArchiveBytes = $archive.Length
        ArchiveMiB = [math]::Round($archive.Length / 1MB, 2)
        SHA256 = $hash.Hash
        ExportSource = $exportSourceKind
        ExportTables = $exportTables.Count
    } | Format-List
}
finally {
    if (Test-Path -LiteralPath $stagingPath) {
        Remove-Item -LiteralPath $stagingPath -Recurse -Force
    }
}