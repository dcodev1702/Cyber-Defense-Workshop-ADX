<#
.SYNOPSIS
The one definition of "this value looks like live tenant data".

.DESCRIPTION
Three places need to answer that question and they must answer it identically:

  * Test-FieldProfileSafety.ps1  -- the gate that blocks a profile from being committed
  * Build-SchemaFromLiveTable.ps1 -- which embeds an observed sample into every
    schema description, and is where the tenant identifiers in schemas/ came from
  * Export-WorkshopTelemetryProfiles.ps1 -- which suppresses values at capture time

Expressing the list once is not tidiness. The 2026-07-26 evaluation found the
pre-commit hook and CI enforcing different rules because the same intent was
written out twice, and a second copy of these indicators would reproduce that
failure in a place where the cost is live tenant data in a public repository.

Dot-source it:

    . (Join-Path $PSScriptRoot 'WorkshopSensitiveContent.ps1')
    if (Test-WorkshopSensitiveContent -Value $sample) { ... }
#>

# Version strings are shaped like an IPv4 address, so that test is opt-in per
# caller rather than part of the default set.
$script:WorkshopSensitiveIndicators = [ordered]@{
    'embedded GUID'      = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    'subscription path'  = '(?i)/subscriptions/'
    'resource group'     = '(?i)/resourcegroups/'
    'tenant path'        = '(?i)/tenants/'
    'onmicrosoft domain' = '(?i)\.onmicrosoft\.com'
    'UPN'                = '(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}'
    'credential'         = '(?i)(bearer\s+[a-z0-9._-]{8,}|eyJ[a-zA-Z0-9._-]{10,})'
    'long hex'           = '\b[0-9a-fA-F]{32,}\b'
}

$script:WorkshopIPv4Indicator = '\b\d{1,3}(\.\d{1,3}){3}\b'

function Get-WorkshopSensitiveIndicator {
    <#
    .SYNOPSIS
    Returns the indicator table, optionally including the IPv4 test.
    #>
    [CmdletBinding()]
    param([switch]$IncludeIPv4)

    $tests = [ordered]@{}
    foreach ($label in $script:WorkshopSensitiveIndicators.Keys) {
        $tests[$label] = $script:WorkshopSensitiveIndicators[$label]
    }

    if ($IncludeIPv4) { $tests['IPv4'] = $script:WorkshopIPv4Indicator }
    return $tests
}

function Test-WorkshopSensitiveContent {
    <#
    .SYNOPSIS
    Returns the name of the first indicator the value matches, or $null when clean.

    .DESCRIPTION
    Returning the indicator name rather than a bare boolean lets callers say which
    rule fired, which is the difference between a usable refusal and a mystery.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value,

        [switch]$IncludeIPv4
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    $tests = Get-WorkshopSensitiveIndicator -IncludeIPv4:$IncludeIPv4
    foreach ($label in $tests.Keys) {
        if ($Value -match $tests[$label]) { return $label }
    }

    return $null
}
