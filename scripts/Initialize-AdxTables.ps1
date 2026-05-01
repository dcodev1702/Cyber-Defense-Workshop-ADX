<#
.SYNOPSIS
Creates and validates ADX workshop tables and JSON ingestion mappings.

.DESCRIPTION
Reads workshop schema JSON files, creates missing ADX tables, optionally drops and
recreates existing tables, creates or updates JSON ingestion mappings, and verifies
the expected table set exists in the target database.

.EXAMPLE
.\scripts\Initialize-AdxTables.ps1 -ClusterUri 'https://dibsecadx.eastus2.kusto.windows.net' -DatabaseName CyberDefenseKqlWorkshop -SchemaDirectory .\schemas

.EXAMPLE
.\scripts\Initialize-AdxTables.ps1 -ClusterUri 'https://dibsecadx.eastus2.kusto.windows.net' -DatabaseName CyberDefenseKqlWorkshop -ForceRecreate

.NOTES
Name: Initialize-AdxTables.ps1
Date: 2026-05-01
Authors: dcodev1702 and GitHub Copilot CLI w/ ChatGPT 5.5 xhigh
Dependencies: scripts\AdxWorkshop.Common.psm1, ADX database access, schema JSON files.
Key commands: .show tables, .drop table, .create table, .create-or-alter table ingestion json mapping.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ClusterUri,
    [Parameter(Mandatory)][string]$DatabaseName,
    [string]$SchemaDirectory = (Join-Path $PSScriptRoot '..\schemas'),
    [string[]]$TableName,
    [switch]$ForceRecreate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'AdxWorkshop.Common.psm1') -Force

if (-not (Test-Path $SchemaDirectory)) {
    throw "Schema directory not found: $SchemaDirectory"
}

$schemaFiles = Get-ChildItem -Path $SchemaDirectory -Filter '*.schema.json' | Sort-Object Name
if ($TableName) {
    $schemaFiles = $schemaFiles | Where-Object { $TableName -contains ($_.BaseName -replace '\.schema$', '') }
}

if (-not $schemaFiles) {
    throw 'No schema files selected.'
}

$expectedTableNames = New-Object System.Collections.Generic.List[string]
foreach ($schemaFile in $schemaFiles) {
    $schema = Get-Content -Path $schemaFile.FullName -Raw | ConvertFrom-Json
    $table = [string]$schema.tableName
    $expectedTableNames.Add($table) | Out-Null
    $tableIdentifier = ConvertTo-WorkshopKustoIdentifier -Name $table
    $tableLiteral = ConvertTo-WorkshopKustoStringLiteral -Value $table

    Write-Host "Preparing table $table"
    $existsResponse = Invoke-WorkshopAdxManagementCommand -ClusterUri $ClusterUri -DatabaseName $DatabaseName -Command ".show tables | where TableName == $tableLiteral | project TableName"
    $exists = @(ConvertFrom-WorkshopAdxResponseRows -Response $existsResponse).Count -gt 0

    if ($ForceRecreate -and $exists) {
        Write-Host "Dropping existing table $table"
        Invoke-WorkshopAdxManagementCommand -ClusterUri $ClusterUri -DatabaseName $DatabaseName -Command ".drop table $tableIdentifier ifexists" | Out-Null
        $exists = $false
    }

    if (-not $exists) {
        $columnDeclarations = foreach ($column in $schema.columns) {
            "$(ConvertTo-WorkshopKustoIdentifier -Name ([string]$column.name)):$($column.type)"
        }
        $createCommand = ".create table $tableIdentifier ($($columnDeclarations -join ', '))"
        Invoke-WorkshopAdxManagementCommand -ClusterUri $ClusterUri -DatabaseName $DatabaseName -Command $createCommand | Out-Null
        Write-Host "Created table $table"
    }
    else {
        Write-Host "Table $table already exists"
    }

    $mappingName = if ($schema.adx.mappingName) { [string]$schema.adx.mappingName } else { "${table}_JsonMapping" }
    $mapping = foreach ($column in $schema.columns) {
        [ordered]@{
            column = [string]$column.name
            path = '$.' + [string]$column.name
            datatype = [string]$column.type
        }
    }
    $mappingJson = $mapping | ConvertTo-Json -Compress -Depth 8
    $mappingCommand = ".create-or-alter table $tableIdentifier ingestion json mapping $(ConvertTo-WorkshopKustoStringLiteral -Value $mappingName) $(ConvertTo-WorkshopKustoStringLiteral -Value $mappingJson)"
    Invoke-WorkshopAdxManagementCommand -ClusterUri $ClusterUri -DatabaseName $DatabaseName -Command $mappingCommand | Out-Null
    Write-Host "Created or updated JSON mapping $mappingName"
}

$showTablesResponse = Invoke-WorkshopAdxManagementCommand -ClusterUri $ClusterUri -DatabaseName $DatabaseName -Command '.show tables | project TableName'
$existingTableNames = @(ConvertFrom-WorkshopAdxResponseRows -Response $showTablesResponse | ForEach-Object { [string]$_.TableName })
$missingTables = @($expectedTableNames | Where-Object { $existingTableNames -notcontains $_ })
if ($missingTables.Count -gt 0) {
    throw "ADX table validation failed. Missing table(s): $($missingTables -join ', ')"
}

Write-Host "Validated $($expectedTableNames.Count) ADX table(s) exist in database $DatabaseName."
