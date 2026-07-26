#Requires -Version 7
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Scans every committed field profile for tenant data that must never reach a
# public repository: embedded GUIDs, Azure resource paths, UPNs, addresses,
# long hex, or secret-looking tokens inside a captured value vocabulary.

$dir = 'C:\Users\Lorenzo\Downloads\cyber_conf_wiesbaden\metadata\field-profiles'

$indicators = [ordered]@{
    'embedded GUID'      = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    'subscription path'  = '(?i)/subscriptions/'
    'resource group'     = '(?i)/resourcegroups/'
    'tenant path'        = '(?i)/tenants/'
    'onmicrosoft domain' = '(?i)\.onmicrosoft\.com'
    'UPN'                = '(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}'
    'credential'         = '(?i)(bearer\s+[a-z0-9._-]{8,}|eyJ[a-zA-Z0-9._-]{10,})'
    'long hex'           = '\b[0-9a-fA-F]{32,}\b'
}

# Version strings are shaped like an address, so the IPv4 test is applied only to
# columns that are not version fields. Mirrors Export-WorkshopTelemetryProfiles.ps1.
$ipIndicator = '\b\d{1,3}(\.\d{1,3}){3}\b'

$findings = [System.Collections.Generic.List[object]]::new()
$vocabCount = 0

foreach ($file in Get-ChildItem $dir -Filter '*.profile.json') {
    $doc = Get-Content -Raw $file.FullName | ConvertFrom-Json
    foreach ($property in $doc.columns.PSObject.Properties) {
        $values = @($property.Value.topValues | ForEach-Object { [string]$_.value })
        if ($values.Count -eq 0) { continue }
        $vocabCount++

        $tests = [ordered]@{}
        foreach ($label in $indicators.Keys) { $tests[$label] = $indicators[$label] }
        if ($property.Name -notmatch '(?i)version') { $tests['IPv4'] = $ipIndicator }

        foreach ($label in $tests.Keys) {
            $hit = @($values | Where-Object { $_ -match $tests[$label] }) | Select-Object -First 1
            if ($hit) {
                $sample = [string]$hit
                if ($sample.Length -gt 48) { $sample = $sample.Substring(0, 48) + '...' }
                $findings.Add([pscustomobject]@{
                    Table = $doc.tableName; Column = $property.Name; Indicator = $label; Sample = $sample
                })
                break
            }
        }
    }
}

Write-Host ("Profiles scanned            : {0}" -f (Get-ChildItem $dir -Filter '*.profile.json').Count)
Write-Host ("Columns with a vocabulary   : {0}" -f $vocabCount)
Write-Host ''

if ($findings.Count -eq 0) {
    Write-Host 'CLEAN: no tenant data found in any captured vocabulary.' -ForegroundColor Green
    exit 0
}

Write-Host ("LEAKS FOUND: {0}" -f $findings.Count) -ForegroundColor Red
$findings | Format-Table -AutoSize
exit 1
