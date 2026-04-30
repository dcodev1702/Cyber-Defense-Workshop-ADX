[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ClusterUri,
    [Parameter(Mandatory)][string]$DatabaseName,
    [string]$GroupObjectId,
    [string[]]$UserPrincipalName,
    [string]$StudentCsvPath,
    [ValidateSet('viewer', 'unrestrictedviewer')]
    [string]$Role = 'viewer'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'AdxWorkshop.Common.psm1') -Force

$principals = New-Object System.Collections.Generic.List[string]
if ($GroupObjectId) {
    $principals.Add("aadgroup=$GroupObjectId")
}
if ($UserPrincipalName) {
    foreach ($upn in $UserPrincipalName) {
        $principals.Add("aaduser=$upn")
    }
}
if ($StudentCsvPath) {
    $students = Import-Csv -Path $StudentCsvPath
    foreach ($student in $students) {
        if ($student.UserPrincipalName) {
            $principals.Add("aaduser=$($student.UserPrincipalName)")
        }
    }
}

if ($principals.Count -eq 0) {
    throw 'Supply -GroupObjectId, -UserPrincipalName, or -StudentCsvPath.'
}

$principalList = ($principals | ForEach-Object { ConvertTo-WorkshopKustoStringLiteral -Value $_ }) -join ', '
$rolePlural = if ($Role -eq 'viewer') { 'viewers' } else { 'unrestrictedviewers' }
$dbIdentifier = ConvertTo-WorkshopKustoIdentifier -Name $DatabaseName
$command = ".add database $dbIdentifier $rolePlural ($principalList) 'Cyber defense workshop student access'"

Invoke-WorkshopAdxManagementCommand -ClusterUri $ClusterUri -DatabaseName $DatabaseName -Command $command | Out-Null
Write-Host "Granted $Role access to $($principals.Count) principal(s) for $DatabaseName."
