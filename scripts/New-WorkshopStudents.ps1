<#
.SYNOPSIS
Creates or stages ADX workshop student accounts and access roster data.

.DESCRIPTION
Builds a CSV roster for workshop students and, when requested, creates Microsoft
Entra users, creates or reuses a security group, adds users to that group, and can
issue Temporary Access Pass values for ADX Web UI sign-in.

.EXAMPLE
.\scripts\New-WorkshopStudents.ps1 -TenantDomain contoso.onmicrosoft.com -StudentCount 20

.EXAMPLE
.\scripts\New-WorkshopStudents.ps1 -TenantDomain contoso.onmicrosoft.com -CreateUsers -InitialPassword '<password>' -CreateTemporaryAccessPass

.NOTES
Name: New-WorkshopStudents.ps1
Date: 2026-05-01
Authors: dcodev1702 and GitHub Copilot CLI w/ ChatGPT 5.5 xhigh
Dependencies: Microsoft.Graph PowerShell modules when -CreateUsers or -CreateTemporaryAccessPass is used.
Key commands: Connect-MgGraph, New-MgUser, Get-MgGroup, New-MgGroup, New-MgGroupMember, New-MgUserAuthenticationTemporaryAccessPassMethod, Export-Csv.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantDomain,
    [int]$StudentCount = 20,
    [string]$UserPrefix = 'kqlstudent',
    [string]$DisplayNamePrefix = 'KQL Workshop Student',
    [string]$InitialPassword,
    [string]$GroupDisplayName = 'ADX KQL Cyber Defense Workshop Students',
    [string]$OutputCsvPath = (Join-Path $PSScriptRoot '..\students\students.csv'),
    [switch]$CreateUsers,
    [switch]$CreateTemporaryAccessPass,
    [int]$TemporaryAccessPassLifetimeMinutes = 480
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($CreateUsers -and [string]::IsNullOrWhiteSpace($InitialPassword)) {
    throw 'Supply -InitialPassword when using -CreateUsers.'
}

New-Item -ItemType Directory -Path (Split-Path -Parent $OutputCsvPath) -Force | Out-Null

if ($CreateUsers) {
    $requiredCommands = @('Connect-MgGraph', 'New-MgUser', 'Get-MgGroup', 'New-MgGroup', 'New-MgGroupMember')
    foreach ($command in $requiredCommands) {
        if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
            throw "Microsoft Graph PowerShell command '$command' was not found. Install Microsoft.Graph modules before using -CreateUsers."
        }
    }

    $scopes = @('User.ReadWrite.All', 'Group.ReadWrite.All')
    if ($CreateTemporaryAccessPass) {
        $scopes += 'UserAuthenticationMethod.ReadWrite.All'
    }
    Connect-MgGraph -Scopes $scopes | Out-Null

    $group = Get-MgGroup -Filter "displayName eq '$($GroupDisplayName.Replace("'", "''"))'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $group) {
        $mailNickname = ($GroupDisplayName -replace '[^A-Za-z0-9]', '').ToLowerInvariant()
        $group = New-MgGroup -DisplayName $GroupDisplayName -MailEnabled:$false -MailNickname $mailNickname -SecurityEnabled:$true
    }
}

$rows = New-Object System.Collections.Generic.List[object]
for ($i = 1; $i -le $StudentCount; $i++) {
    $upn = ('{0}{1:D2}@{2}' -f $UserPrefix, $i, $TenantDomain)
    $displayName = ('{0} {1:D2}' -f $DisplayNamePrefix, $i)
    $temporaryAccessPass = ''
    $userId = ''

    if ($CreateUsers) {
        $existing = Get-MgUser -UserId $upn -ErrorAction SilentlyContinue
        if ($existing) {
            $user = $existing
        }
        else {
            $passwordProfile = @{
                password = $InitialPassword
                forceChangePasswordNextSignIn = $false
            }
            $user = New-MgUser -AccountEnabled:$true -DisplayName $displayName -MailNickname ('{0}{1:D2}' -f $UserPrefix, $i) -UserPrincipalName $upn -PasswordProfile $passwordProfile
        }
        $userId = $user.Id

        try {
            New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $user.Id -ErrorAction Stop
        }
        catch {
            if ($_.Exception.Message -notmatch 'already exist|added object references already exist') {
                throw
            }
        }

        if ($CreateTemporaryAccessPass) {
            if (-not (Get-Command New-MgUserAuthenticationTemporaryAccessPassMethod -ErrorAction SilentlyContinue)) {
                throw 'New-MgUserAuthenticationTemporaryAccessPassMethod was not found. Install Microsoft.Graph.Identity.SignIns.'
            }

            $tap = New-MgUserAuthenticationTemporaryAccessPassMethod -UserId $user.Id -BodyParameter @{
                lifetimeInMinutes = $TemporaryAccessPassLifetimeMinutes
                isUsableOnce = $false
            }
            $temporaryAccessPass = $tap.TemporaryAccessPass
        }
    }

    $rows.Add([pscustomobject]@{
        StudentNumber = $i
        DisplayName = $displayName
        UserPrincipalName = $upn
        InitialPassword = $InitialPassword
        TemporaryAccessPass = $temporaryAccessPass
        UserObjectId = $userId
        GroupDisplayName = $GroupDisplayName
        GroupObjectId = if ($CreateUsers) { $group.Id } else { '' }
    }) | Out-Null
}

$rows | Export-Csv -Path $OutputCsvPath -NoTypeInformation -Encoding UTF8
Write-Host "Wrote student roster to $OutputCsvPath"
if ($CreateUsers) {
    Write-Host "Created or confirmed $StudentCount user(s) and group '$GroupDisplayName'."
}
