[CmdletBinding()]
param(
    [string]$ManifestPath = (Join-Path $PSScriptRoot '..\metadata\tables.manifest.json'),
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\schemas'),
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function ConvertFrom-HtmlFragment {
    param([AllowEmptyString()][string]$Html = '')

    $text = $Html -replace '<br\s*/?>', ' '
    $text = $text -replace '</p>', ' '
    $text = $text -replace '<.*?>', ' '
    $text = [System.Net.WebUtility]::HtmlDecode($text)
    $text = $text -replace '\s+', ' '
    return $text.Trim()
}

function ConvertTo-AdxType {
    param([Parameter(Mandatory)][string]$TypeName)

    $normalized = $TypeName.Trim().ToLowerInvariant()
    $normalized = $normalized -replace '^nullable\s+', ''
    switch -Regex ($normalized) {
        '^(bool|boolean)$' { return 'bool' }
        '^(datetime|date/time)$' { return 'datetime' }
        '^(dynamic|object|array)$' { return 'dynamic' }
        '^(guid|uuid)$' { return 'guid' }
        '^(int|int32|integer)$' { return 'int' }
        '^(long|int64)$' { return 'long' }
        '^(real|double|decimal|float)$' { return 'real' }
        '^(string|text)$' { return 'string' }
        default {
            Write-Warning "Unknown type '$TypeName'; defaulting to string."
            return 'string'
        }
    }
}

function Get-TableRowsFromLearnHtml {
    param([Parameter(Mandatory)][string]$Html)

    $regexOptions = [System.Text.RegularExpressions.RegexOptions]::Singleline -bor
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase

    $tableMatches = [regex]::Matches($Html, '<table.*?>.*?</table>', $regexOptions)
    foreach ($tableMatch in $tableMatches) {
        $tableHtml = $tableMatch.Value
        $headers = @()
        $headerMatches = [regex]::Matches($tableHtml, '<th.*?>(.*?)</th>', $regexOptions)
        foreach ($headerMatch in $headerMatches) {
            $headers += ConvertFrom-HtmlFragment $headerMatch.Groups[1].Value
        }

        if (-not ($headers | Where-Object { $_ -match '^Column(\s+name)?$' })) {
            continue
        }
        if (-not ($headers | Where-Object { $_ -match '^(Data\s+type|Type)$' })) {
            continue
        }

        $columnIndex = [Array]::FindIndex([string[]]$headers, [Predicate[string]] { param($h) $h -match '^Column(\s+name)?$' })
        $typeIndex = [Array]::FindIndex([string[]]$headers, [Predicate[string]] { param($h) $h -match '^(Data\s+type|Type)$' })
        $descriptionIndex = [Array]::FindIndex([string[]]$headers, [Predicate[string]] { param($h) $h -match '^Description$' })

        $rows = @()
        $rowMatches = [regex]::Matches($tableHtml, '<tr.*?>.*?</tr>', $regexOptions)
        foreach ($rowMatch in $rowMatches) {
            $cellMatches = [regex]::Matches($rowMatch.Value, '<td.*?>(.*?)</td>', $regexOptions)
            if ($cellMatches.Count -eq 0) {
                continue
            }

            $cells = @()
            foreach ($cellMatch in $cellMatches) {
                $cells += ConvertFrom-HtmlFragment $cellMatch.Groups[1].Value
            }

            if ($cells.Count -le [Math]::Max($columnIndex, $typeIndex)) {
                continue
            }

            $description = ''
            if ($descriptionIndex -ge 0 -and $cells.Count -gt $descriptionIndex) {
                $description = $cells[$descriptionIndex]
            }

            $name = ($cells[$columnIndex] -replace '^`|`$', '').Trim()
            $rawType = ($cells[$typeIndex] -replace '^`|`$', '').Trim()
            if ([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($rawType)) {
                continue
            }

            $rows += [ordered]@{
                name = $name
                type = ConvertTo-AdxType $rawType
                sourceType = $rawType
                description = $description
            }
        }

        if ($rows.Count -gt 0) {
            return $rows
        }
    }

    return @()
}

function Get-MicrosoftLearnPageContent {
    param([Parameter(Mandatory)][string]$Url)

    $response = Invoke-WebRequest -Uri $Url -UseBasicParsing
    $content = $response.Content

    if ([string]::IsNullOrWhiteSpace($content)) {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -Headers @{ 'User-Agent' = 'Mozilla/5.0 schema-export' }
        $content = $response.Content
    }

    if ([string]::IsNullOrWhiteSpace($content) -and (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
        $content = & curl.exe -L -s -A 'Mozilla/5.0 schema-export' $Url
    }

    if ([string]::IsNullOrWhiteSpace($content)) {
        throw "Microsoft Learn returned an empty page body."
    }

    return [string]::Join([Environment]::NewLine, @($content))
}

if (-not (Test-Path $ManifestPath)) {
    throw "Manifest not found: $ManifestPath"
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$manifest = Get-Content -Path $ManifestPath -Raw | ConvertFrom-Json
$failures = New-Object System.Collections.Generic.List[string]

foreach ($entry in $manifest) {
    $outputPath = Join-Path $OutputDirectory "$($entry.name).schema.json"
    if ((Test-Path $outputPath) -and -not $Force) {
        Write-Host "Skipping existing schema: $($entry.name)"
        continue
    }

    Write-Host "Fetching $($entry.name) from $($entry.sourceUrl)"
    try {
        $content = Get-MicrosoftLearnPageContent -Url $entry.sourceUrl
        $columns = Get-TableRowsFromLearnHtml -Html $content
        if ($columns.Count -eq 0) {
            throw "No schema column table found."
        }

        $schema = [ordered]@{
            tableName = $entry.name
            categories = @($entry.categories)
            sourceProduct = $entry.sourceProduct
            sourceUrl = $entry.sourceUrl
            schemaSource = 'Microsoft Learn'
            columns = $columns
            adx = [ordered]@{
                mappingName = "$($entry.name)_JsonMapping"
            }
        }

        $schema | ConvertTo-Json -Depth 12 | Set-Content -Path $outputPath -Encoding UTF8
        Write-Host "Wrote $outputPath ($($columns.Count) columns)"
    }
    catch {
        $message = "$($entry.name): $($_.Exception.Message)"
        $failures.Add($message)
        Write-Warning $message
    }
}

if ($failures.Count -gt 0) {
    $failureText = $failures -join [Environment]::NewLine
    throw "Schema generation completed with failures:$([Environment]::NewLine)$failureText"
}
