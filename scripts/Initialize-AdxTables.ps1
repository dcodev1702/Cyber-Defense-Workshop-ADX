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

foreach ($schemaFile in $schemaFiles) {
    $schema = Get-Content -Path $schemaFile.FullName -Raw | ConvertFrom-Json
    $table = [string]$schema.tableName
    $tableIdentifier = ConvertTo-WorkshopKustoIdentifier -Name $table
    $tableLiteral = ConvertTo-WorkshopKustoStringLiteral -Value $table

    Write-Host "Preparing table $table"
    $existsResponse = Invoke-WorkshopAdxManagementCommand -ClusterUri $ClusterUri -DatabaseName $DatabaseName -Command ".show tables | where TableName == $tableLiteral | project TableName"
    $exists = (ConvertFrom-WorkshopAdxResponseRows -Response $existsResponse).Count -gt 0

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
