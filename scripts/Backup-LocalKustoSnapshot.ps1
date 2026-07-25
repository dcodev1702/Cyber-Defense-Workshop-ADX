<#
.SYNOPSIS
Creates a portable backup archive for the local Kustainer Student snapshot.

.DESCRIPTION
Archives the persisted database state, any Kustainer recovery directories, and
the newest locally verified NDJSON export. Stop Kusto before running the script
when a point-in-time backup is required.

.EXAMPLE
docker compose stop kusto
.\scripts\Backup-LocalKustoSnapshot.ps1
docker compose start kusto
#>
[CmdletBinding()]
param(
    [string]$DatabaseName = 'CyberDefendStudentSnapshot',
    [string]$LocalStateDirectory = (Join-Path $PSScriptRoot '..\data\local-kusto'),
    [string]$ExportRootDirectory = (Join-Path $PSScriptRoot '..\data\local-export'),
    [string]$BackupDirectory = (Join-Path $PSScriptRoot '..\data\backups\local-kusto')
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

$exportSnapshot = @(
    Get-ChildItem -LiteralPath $ExportRootDirectory -Directory |
        Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'local-kusto-manifest.json') } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
)
if ($exportSnapshot.Count -ne 1) {
    throw "No verified local export containing local-kusto-manifest.json was found beneath '$ExportRootDirectory'."
}

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
    Copy-Item -LiteralPath $exportSnapshot[0].FullName -Destination $exportStagingPath -Recurse -Force

    $stateBytes = [long](($stateDirectories | ForEach-Object {
        Get-ChildItem -LiteralPath $_.FullName -File -Recurse | Measure-Object -Property Length -Sum
    } | ForEach-Object { $_.Sum } | Measure-Object -Sum).Sum)
    $exportBytes = [long]((Get-ChildItem -LiteralPath $exportSnapshot[0].FullName -File -Recurse | Measure-Object -Property Length -Sum).Sum)
    $manifest = [ordered]@{
        manifestVersion = 1
        createdOn = (Get-Date).ToUniversalTime().ToString('o')
        databaseName = $DatabaseName
        stateDirectories = @($stateDirectories | ForEach-Object Name)
        exportSnapshot = $exportSnapshot[0].Name
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
        ExportSnapshot = $exportSnapshot[0].Name
    } | Format-List
}
finally {
    if (Test-Path -LiteralPath $stagingPath) {
        Remove-Item -LiteralPath $stagingPath -Recurse -Force
    }
}