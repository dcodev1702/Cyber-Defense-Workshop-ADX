<#
.SYNOPSIS
Restores a local Kustainer backup archive into a Kusto container and verifies it.

.DESCRIPTION
Rebuilds the workshop database from a backup archive produced by
scripts\Backup-LocalKustoSnapshot.ps1, then reconciles the restored row counts
against the archive contents.

The restore uses the archive's NDJSON payload rather than its persisted state.
The emulator keeps its persistent-database registration inside the container
rather than in the mounted state directory, so a fresh container cannot attach
persisted state that another container created; attempting it fails with an
internal service error. The persisted state in the archive is therefore only
useful for putting files back under the same container instance, while the
NDJSON is what makes the archive restorable anywhere.

The archive also carries the table schemas and manifest, so a restore does not
require a matching checkout.

By default this restores into a throwaway container on a spare port and removes
it afterwards, which makes it safe to run as a recovery rehearsal at any time
without touching the workshop cluster.

To rebuild the workshop cluster itself, use -ExtractPayloadTo to put the
archive's telemetry and schemas back on disk, then load them with
scripts\Import-GeneratedDataToKustainer.ps1. That path needs no Azure
connectivity, which matters because the alternative, re-copying from the Student
cluster, is unavailable exactly when it is most likely to be needed.

.EXAMPLE
.\scripts\Restore-LocalKustoSnapshot.ps1

.EXAMPLE
.\scripts\Restore-LocalKustoSnapshot.ps1 -ArchivePath .\data\backups\local-kusto\snap.zip -KeepContainer

.EXAMPLE
.\scripts\Restore-LocalKustoSnapshot.ps1 -ExtractPayloadTo .\data\generated
.\scripts\Import-GeneratedDataToKustainer.ps1
#>
#Requires -Version 7
[CmdletBinding()]
param(
    [string]$ArchivePath,
    [string]$BackupDirectory = (Join-Path $PSScriptRoot '..\data\backups\local-kusto'),
    [string]$DatabaseName = 'CyberDefendStudentSnapshot',
    [string]$ContainerName = 'cdw-restore-check',
    [int]$HostPort = 8099,
    [string]$Image = 'mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest',
    [string]$WorkingDirectory = (Join-Path ([System.IO.Path]::GetTempPath()) 'cdw-restore-check'),
    [string]$Memory = '16g',
    [switch]$KeepContainer,
    [string]$ExtractPayloadTo
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem

# Guard: this script provisions its own container and must never be pointed at
# the workshop cluster, whose database is managed by the Compose stack.
if ($ContainerName -eq 'cyber-conf-wiesbaden-kusto') {
    throw 'Refusing to restore over the workshop container. Use a separate -ContainerName.'
}

if (-not $ArchivePath) {
    $latest = @(Get-ChildItem -LiteralPath $BackupDirectory -Filter '*.zip' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1)
    if ($latest.Count -ne 1) { throw "No backup archive found beneath '$BackupDirectory'." }
    $ArchivePath = $latest[0].FullName
}
$ArchivePath = (Resolve-Path -LiteralPath $ArchivePath).Path

$testUri = "http://127.0.0.1:$HostPort"
$stateDir = Join-Path $WorkingDirectory 'state'
$exportDir = Join-Path $WorkingDirectory 'export'
$schemaDir = Join-Path $WorkingDirectory 'schemas'

function Invoke-RestoreKusto {
    param([string]$Command, [string]$Endpoint = 'query', [int]$TimeoutSec = 600)
    $body = @{ db = $DatabaseName; csl = $Command } | ConvertTo-Json -Depth 4 -Compress
    return Invoke-RestMethod -Method Post -Uri "$testUri/v1/rest/$Endpoint" -Body $body -ContentType 'application/json' -TimeoutSec $TimeoutSec
}

function ConvertTo-KustoType {
    param([string]$Type)
    switch ($Type.ToLowerInvariant()) {
        'string' { 'string' } 'datetime' { 'datetime' } 'long' { 'long' } 'int' { 'int' }
        'real' { 'real' } 'double' { 'real' } 'bool' { 'bool' } 'boolean' { 'bool' }
        'guid' { 'guid' } 'dynamic' { 'dynamic' } 'timespan' { 'timespan' } default { 'string' }
    }
}

Write-Host ("Archive   : {0}" -f $ArchivePath)
if (-not $ExtractPayloadTo) {
    Write-Host ("Container : {0} on 127.0.0.1:{1}" -f $ContainerName, $HostPort)
}
Write-Host ''

$restoredTables = 0
$expectedRows = 0L
$actualRows = 0L
$manifest = $null

try {
    if (-not $ExtractPayloadTo) { docker rm --force $ContainerName 2>$null | Out-Null }
    if (Test-Path $WorkingDirectory) { Remove-Item $WorkingDirectory -Recurse -Force }
    foreach ($dir in @($stateDir, $exportDir, $schemaDir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    Write-Host 'Extracting archive payload...'
    $zip = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        foreach ($entry in $zip.Entries) {
            if ($entry.Name -eq '') { continue }
            $target = $null
            if ($entry.FullName -like 'export/*' -and $entry.Name -like '*.ndjson') { $target = Join-Path $exportDir $entry.Name }
            elseif ($entry.FullName -like 'export/*' -and $entry.Name -like '*.json' -and $entry.Name -notlike '*manifest*') { $target = Join-Path $exportDir $entry.Name }
            elseif ($entry.FullName -like 'schemas/*') { $target = Join-Path $schemaDir $entry.Name }
            elseif ($entry.FullName -eq 'tables.manifest.json') { $target = Join-Path $WorkingDirectory 'tables.manifest.json' }
            elseif ($entry.FullName -eq 'backup-manifest.json') { $target = Join-Path $WorkingDirectory 'backup-manifest.json' }
            if (-not $target) { continue }
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $target, $true)
        }
    }
    finally { $zip.Dispose() }

    $manifestPath = Join-Path $WorkingDirectory 'backup-manifest.json'
    if (Test-Path $manifestPath) {
        $manifest = Get-Content -Raw $manifestPath | ConvertFrom-Json
        Write-Host ("  archive created : {0}" -f $manifest.createdOn)
        if ($manifest.PSObject.Properties['exportSource']) {
            Write-Host ("  payload source  : {0}" -f $manifest.exportSource)
        }
    }

    $dataFiles = @(Get-ChildItem $exportDir -File | Where-Object { $_.Extension -in @('.ndjson', '.json') })
    $schemaFiles = @(Get-ChildItem $schemaDir -Filter '*.schema.json' -ErrorAction SilentlyContinue)
    Write-Host ("  data files      : {0}" -f $dataFiles.Count)
    Write-Host ("  schema files    : {0}" -f $schemaFiles.Count)
    if ($dataFiles.Count -eq 0) { throw 'The archive contains no restorable data payload.' }

    # Catch a short archive here as well as at backup time. An archive that omits
    # tables restores "successfully" and still leaves the workshop incomplete.
    $tableManifestPath = Join-Path $WorkingDirectory 'tables.manifest.json'
    if (Test-Path $tableManifestPath) {
        $declared = @((Get-Content -Raw $tableManifestPath | ConvertFrom-Json) | ForEach-Object { $_.name })
        $present = @($dataFiles | ForEach-Object { $_.BaseName })
        $missing = @($declared | Where-Object { $_ -notin $present })
        Write-Host ("  manifest tables : {0}" -f $declared.Count)
        if ($missing.Count -gt 0) {
            throw ("The archive payload is missing {0} table(s) the manifest declares: {1}" -f $missing.Count, ($missing -join ', '))
        }
    }

    # Recovery of the workshop cluster itself goes through here: put the payload
    # back on disk, then load it with Import-GeneratedDataToKustainer.ps1. No
    # container is started, so this is safe to run while the workshop is up.
    if ($ExtractPayloadTo) {
        New-Item -ItemType Directory -Path $ExtractPayloadTo -Force | Out-Null
        Copy-Item -Path (Join-Path $exportDir '*') -Destination $ExtractPayloadTo -Force
        $target = (Resolve-Path -LiteralPath $ExtractPayloadTo).Path
        Write-Host ''
        Write-Host ("Payload written to {0} ({1} table(s))." -f $target, $dataFiles.Count)
        Write-Host 'Load it into the workshop cluster with:'
        Write-Host '  .\scripts\Import-GeneratedDataToKustainer.ps1'
        return
    }

    Write-Host ''
    Write-Host 'Starting container...'
    docker run --detach --name $ContainerName `
        --publish "127.0.0.1:${HostPort}:8080" `
        --env ACCEPT_EULA=Y --memory $Memory `
        --volume "${stateDir}:/kustodata" `
        --volume "${exportDir}:/restore:ro" `
        $Image | Out-Null

    $ready = $false
    $deadline = (Get-Date).AddMinutes(8)
    while ((Get-Date) -lt $deadline) {
        try {
            $b = @{ csl = '.show cluster' } | ConvertTo-Json -Compress
            Invoke-RestMethod -Method Post -Uri "$testUri/v1/rest/mgmt" -Body $b -ContentType 'application/json' -TimeoutSec 10 | Out-Null
            $ready = $true; break
        }
        catch { Start-Sleep -Seconds 5 }
    }
    if (-not $ready) { throw 'The restore container never became ready.' }
    Write-Host '  engine ready'

    $md = '@"/kustodata/dbs/{0}/md"' -f $DatabaseName
    $data = '@"/kustodata/dbs/{0}/data"' -f $DatabaseName
    $b = @{ csl = ".create database $DatabaseName persist ($md, $data)" } | ConvertTo-Json -Compress
    Invoke-RestMethod -Method Post -Uri "$testUri/v1/rest/mgmt" -Body $b -ContentType 'application/json' -TimeoutSec 300 | Out-Null
    Write-Host '  database created'

    Write-Host ''
    Write-Host 'Restoring tables...'
    $failures = [System.Collections.Generic.List[string]]::new()
    foreach ($file in $dataFiles) {
        $table = $file.BaseName
        $schemaPath = Join-Path $schemaDir "$table.schema.json"
        if (-not (Test-Path $schemaPath)) { $failures.Add("$table (no schema in archive)"); continue }

        $schema = Get-Content -Raw $schemaPath | ConvertFrom-Json
        $cols = @($schema.columns)
        $spec = ($cols | ForEach-Object { '{0}:{1}' -f $_.name, (ConvertTo-KustoType -Type $_.type) }) -join ', '
        $mapName = "${table}_RestoreMapping"
        $mapSpec = ($cols | ForEach-Object { '{{"column":"{0}","Properties":{{"Path":"$.{0}"}}}}' -f $_.name }) -join ', '

        try {
            Invoke-RestoreKusto -Endpoint mgmt -Command ".create-merge table ['$table'] ($spec)" | Out-Null
            Invoke-RestoreKusto -Endpoint mgmt -Command ".create-or-alter table ['$table'] ingestion json mapping '$mapName' '[$mapSpec]'" | Out-Null
            Invoke-RestoreKusto -Endpoint mgmt -Command ".ingest into table ['$table'] (@`"/restore/$($file.Name)`") with (format='multijson', ingestionMappingReference='$mapName')" | Out-Null
            $restoredTables++
        }
        catch { $failures.Add("$table ($($_.Exception.Message))") }

        $n = 0
        $reader = [IO.File]::OpenText($file.FullName)
        try { while ($null -ne $reader.ReadLine()) { $n++ } } finally { $reader.Dispose() }
        $expectedRows += $n
    }
    Write-Host ("  restored {0} of {1} tables" -f $restoredTables, $dataFiles.Count)
    foreach ($f in $failures) { Write-Host ("  FAILED: {0}" -f $f) -ForegroundColor Red }

    Write-Host ''
    Write-Host 'Reconciling...'
    $actualRows = [long]@((Invoke-RestoreKusto -Command 'union withsource=T * | summarize Rows = count()').Tables)[0].Rows[0][0]
    $tableCount = [int]@((Invoke-RestoreKusto -Endpoint mgmt -Command '.show tables | count').Tables)[0].Rows[0][0]
    Write-Host ("  tables : {0}" -f $tableCount)
    Write-Host ("  rows   : {0:N0} restored, {1:N0} in the archive" -f $actualRows, $expectedRows)

    $ok = ($failures.Count -eq 0) -and ($actualRows -eq $expectedRows) -and ($tableCount -eq $dataFiles.Count)
    Write-Host ''
    if ($ok) { Write-Host 'RESTORE VERIFIED.' -ForegroundColor Green }
    else { Write-Host 'RESTORE INCOMPLETE.' -ForegroundColor Red }

    [pscustomobject]@{
        Archive       = $ArchivePath
        Tables        = $tableCount
        Rows          = $actualRows
        ExpectedRows  = $expectedRows
        Failures      = $failures.Count
        Verified      = $ok
        Endpoint      = $testUri
    } | Format-List

    if (-not $ok) { exit 1 }
}
finally {
    if ($ExtractPayloadTo) {
        if (Test-Path $WorkingDirectory) { Remove-Item $WorkingDirectory -Recurse -Force -ErrorAction SilentlyContinue }
    }
    elseif (-not $KeepContainer) {
        docker rm --force $ContainerName 2>$null | Out-Null
        if (Test-Path $WorkingDirectory) { Remove-Item $WorkingDirectory -Recurse -Force -ErrorAction SilentlyContinue }
        Write-Host 'Restore container and working files removed.'
    }
    else {
        Write-Host ("Container '{0}' left running on {1}." -f $ContainerName, $testUri)
    }
}
