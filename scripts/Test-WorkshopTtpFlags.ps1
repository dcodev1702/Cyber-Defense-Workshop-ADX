<#
.SYNOPSIS
Validates the workshop TTP catalog, pivot chains, generated flags, and KQL.

.DESCRIPTION
The matrix is the contract for the cyber-range challenges. Static checks require
one or two pivots, prohibit flags from trainee step queries, and verify every
declared table and final flag column against the workshop schemas.

When DataDirectory is supplied, each exact flag must occur once, only in its
declared final table and top-level column. When ClusterUri is supplied, each
multi-table validation query is executed and must return its expected flag.

.EXAMPLE
.\scripts\Test-WorkshopTtpFlags.ps1

.EXAMPLE
.\scripts\Test-WorkshopTtpFlags.ps1 -DataDirectory .\data\generated

.EXAMPLE
.\scripts\Test-WorkshopTtpFlags.ps1 -ClusterUri http://127.0.0.1:8080 -Database CyberDefendStudentSnapshot
#>
#Requires -Version 7
[CmdletBinding()]
param(
    [string]$MatrixPath = (Join-Path $PSScriptRoot '..' 'metadata' 'ttp-flag-matrix.json'),
    [string]$SchemaDirectory = (Join-Path $PSScriptRoot '..' 'schemas'),
    [string]$TraineeQueryPath = (Join-Path $PSScriptRoot '..' 'docs' 'ttp-hunt-queries.kql'),
    [string]$DataDirectory,
    [string]$ClusterUri,
    [string]$Database = 'CyberDefendStudentSnapshot'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$failures = [System.Collections.Generic.List[string]]::new()

function Add-TtpFailure {
    param([Parameter(Mandatory)][string]$Message)
    $script:failures.Add($Message)
}

function Get-KustoRows {
    param([Parameter(Mandatory)]$Response)

    $legacyTablesProperty = $Response.PSObject.Properties['Tables']
    if ($legacyTablesProperty) {
        $legacyTable = @($legacyTablesProperty.Value | Select-Object -First 1)
        if ($legacyTable.Count -eq 0) { return @() }

        $columns = @($legacyTable[0].Columns | ForEach-Object { [string]$_.ColumnName })
        return @(
            foreach ($row in @($legacyTable[0].Rows)) {
                $item = [ordered]@{}
                for ($index = 0; $index -lt $columns.Count; $index++) {
                    $item[$columns[$index]] = $row[$index]
                }
                [pscustomobject]$item
            }
        )
    }

    $frames = @($Response)
    $dataFrame = @($frames | Where-Object { $_.FrameType -eq 'DataTable' } | Select-Object -First 1)
    if ($dataFrame.Count -eq 0) { return @() }

    $columns = @($dataFrame[0].TableSchema.Columns | ForEach-Object { [string]$_.ColumnName })
    return @(
        foreach ($row in @($dataFrame[0].Rows)) {
            $item = [ordered]@{}
            for ($index = 0; $index -lt $columns.Count; $index++) {
                $item[$columns[$index]] = $row[$index]
            }
            [pscustomobject]$item
        }
    )
}

if (-not (Test-Path -LiteralPath $MatrixPath -PathType Leaf)) {
    throw "TTP matrix not found: $MatrixPath"
}

$matrix = Get-Content -LiteralPath $MatrixPath -Raw | ConvertFrom-Json
$selected = [System.Collections.Generic.List[object]]::new()
$knownFlags = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
$traineeQueries = if (Test-Path -LiteralPath $TraineeQueryPath -PathType Leaf) {
    Get-Content -LiteralPath $TraineeQueryPath -Raw
}
else {
    Add-TtpFailure "Trainee TTP query pack not found: $TraineeQueryPath"
    ''
}
if ($traineeQueries -match 'FLAG:\{') {
    Add-TtpFailure 'Trainee TTP query pack must not contain flag literals.'
}

foreach ($category in @($matrix.categories)) {
    $categorySelected = @($category.ttps | Where-Object { [bool]$_.selected })
    if ($categorySelected.Count -lt 1 -or $categorySelected.Count -gt 2) {
        Add-TtpFailure "Category '$($category.name)' must select one or two TTPs; found $($categorySelected.Count)."
    }

    foreach ($ttp in @($category.ttps)) {
        if (-not [bool]$ttp.selected) {
            if ($ttp.PSObject.Properties['flag']) {
                Add-TtpFailure "Unselected TTP '$($ttp.id)' must not declare a flag."
            }
            continue
        }

        $selected.Add($ttp)
        if ($traineeQueries -notmatch "(?m)^// TTP-ID: $([regex]::Escape([string]$ttp.id))\r?$") {
            Add-TtpFailure "Trainee query pack is missing selected TTP '$($ttp.id)'."
        }
        foreach ($property in @('finalTable', 'flagColumn', 'flag', 'pivotSteps', 'validationKql')) {
            $matrixProperty = $ttp.PSObject.Properties[$property]
            $matrixValue = if ($matrixProperty) { $matrixProperty.Value } else { $null }
            $isEmptyCollection = $matrixValue -is [System.Collections.IEnumerable] -and $matrixValue -isnot [string] -and @($matrixValue).Count -eq 0
            if (-not $matrixProperty -or $null -eq $matrixValue -or $isEmptyCollection -or ($matrixValue -is [string] -and [string]::IsNullOrWhiteSpace($matrixValue))) {
                Add-TtpFailure "Selected TTP '$($ttp.id)' is missing $property."
            }
        }

        $flag = [string]$ttp.flag
        if ($flag -notmatch '^FLAG:\{[A-Za-z0-9]+\}$') {
            Add-TtpFailure "TTP '$($ttp.id)' has malformed flag '$flag'."
        }
        elseif (-not $knownFlags.Add($flag)) {
            Add-TtpFailure "Flag '$flag' is assigned more than once."
        }

        $steps = @($ttp.pivotSteps)
        if ($steps.Count -lt 2 -or $steps.Count -gt 3) {
            Add-TtpFailure "TTP '$($ttp.id)' must require one or two pivots (two or three tables); found $($steps.Count) steps."
        }
        if ($steps.Count -gt 0 -and [string]$steps[-1].table -ne [string]$ttp.finalTable) {
            Add-TtpFailure "TTP '$($ttp.id)' final pivot table does not match finalTable '$($ttp.finalTable)'."
        }
        for ($index = 0; $index -lt $steps.Count; $index++) {
            $step = $steps[$index]
            if ([string]$step.kql -match 'FLAG:\{') {
                Add-TtpFailure "TTP '$($ttp.id)' step $($index + 1) exposes a flag literal."
            }
            if ($index -gt 0 -and [string]$step.table -eq [string]$steps[$index - 1].table) {
                Add-TtpFailure "TTP '$($ttp.id)' step $($index + 1) does not pivot to another table."
            }
            if (-not (Test-Path -LiteralPath (Join-Path $SchemaDirectory "$($step.table).schema.json") -PathType Leaf)) {
                Add-TtpFailure "TTP '$($ttp.id)' references unknown table '$($step.table)'."
            }
        }

        $queryMarker = "// TTP-ID: $($ttp.id)"
        $queryStart = $traineeQueries.IndexOf($queryMarker, [System.StringComparison]::Ordinal)
        if ($queryStart -ge 0) {
            $nextMarker = $traineeQueries.IndexOf('// TTP-ID:', $queryStart + $queryMarker.Length, [System.StringComparison]::Ordinal)
            $querySection = if ($nextMarker -gt $queryStart) {
                $traineeQueries.Substring($queryStart, $nextMarker - $queryStart)
            }
            else {
                $traineeQueries.Substring($queryStart)
            }
            $sectionTables = @([regex]::Matches($querySection, '(?m)^([A-Za-z][A-Za-z0-9_]*)\r?$') | ForEach-Object { $_.Groups[1].Value })
            foreach ($step in $steps) {
                if ([string]$step.table -notin $sectionTables) {
                    Add-TtpFailure "Trainee query '$($ttp.id)' does not reference pivot table '$($step.table)'."
                }
            }
            if ($sectionTables.Count -lt $steps.Count) {
                Add-TtpFailure "Trainee query '$($ttp.id)' has fewer table statements than its $($steps.Count)-step pivot chain."
            }
            if ($querySection -notmatch '(?m)Evidence\s*=') {
                Add-TtpFailure "Trainee query '$($ttp.id)' does not project its final telemetry field as Evidence."
            }
        }

        $joinCount = ([regex]::Matches([string]$ttp.validationKql, '(?im)\|\s*join\b')).Count
        if ($joinCount -ne ($steps.Count - 1)) {
            Add-TtpFailure "TTP '$($ttp.id)' validation query must contain $($steps.Count - 1) joins; found $joinCount."
        }

        $finalSchemaPath = Join-Path $SchemaDirectory "$($ttp.finalTable).schema.json"
        if (Test-Path -LiteralPath $finalSchemaPath -PathType Leaf) {
            $finalSchema = Get-Content -LiteralPath $finalSchemaPath -Raw | ConvertFrom-Json
            if ([string]$ttp.flagColumn -notin @($finalSchema.columns.name)) {
                Add-TtpFailure "TTP '$($ttp.id)' flag column '$($ttp.flagColumn)' is absent from '$($ttp.finalTable)'."
            }
        }
    }
}

if (-not [string]::IsNullOrWhiteSpace($DataDirectory)) {
    if (-not (Test-Path -LiteralPath $DataDirectory -PathType Container)) {
        Add-TtpFailure "Generated data directory not found: $DataDirectory"
    }
    else {
        $occurrences = [System.Collections.Generic.List[object]]::new()
        foreach ($dataFile in @(Get-ChildItem -LiteralPath $DataDirectory -Filter '*.json' -File)) {
            $lineNumber = 0
            foreach ($line in [System.IO.File]::ReadLines($dataFile.FullName)) {
                $lineNumber++
                if ($line -notmatch 'FLAG:') { continue }

                try { $record = $line | ConvertFrom-Json }
                catch {
                    Add-TtpFailure "Invalid JSON in $($dataFile.Name) line $($lineNumber): $($_.Exception.Message)"
                    continue
                }

                foreach ($property in @($record.PSObject.Properties)) {
                    $propertyJson = $property.Value | ConvertTo-Json -Depth 20 -Compress
                    if ($propertyJson -notmatch 'FLAG:') { continue }
                    $flagMatches = @([regex]::Matches($propertyJson, 'FLAG:\{[^}\r\n]*\}'))
                    $unmatchedFlagText = [regex]::Replace($propertyJson, 'FLAG:\{[^}\r\n]*\}', '')
                    if ($unmatchedFlagText -match 'FLAG:') {
                        Add-TtpFailure "Malformed flag marker found in $($dataFile.BaseName).$($property.Name) line $lineNumber."
                    }
                    if ($flagMatches.Count -eq 0) {
                        continue
                    }
                    foreach ($match in $flagMatches) {
                        $occurrences.Add([pscustomobject]@{
                                Flag = $match.Value
                                Table = $dataFile.BaseName
                                Column = $property.Name
                                Line = $lineNumber
                            })
                    }
                }
            }
        }

        foreach ($occurrence in $occurrences) {
            if (-not $knownFlags.Contains([string]$occurrence.Flag)) {
                Add-TtpFailure "Unknown flag '$($occurrence.Flag)' found in $($occurrence.Table).$($occurrence.Column)."
            }
        }
        foreach ($ttp in $selected) {
            $hits = @($occurrences | Where-Object { $_.Flag -ceq [string]$ttp.flag })
            if ($hits.Count -ne 1) {
                Add-TtpFailure "Flag '$($ttp.flag)' must occur exactly once in generated telemetry; found $($hits.Count)."
                continue
            }
            if ([string]$hits[0].Table -ne [string]$ttp.finalTable -or [string]$hits[0].Column -ne [string]$ttp.flagColumn) {
                Add-TtpFailure "Flag '$($ttp.flag)' is in $($hits[0].Table).$($hits[0].Column), expected $($ttp.finalTable).$($ttp.flagColumn)."
            }
        }
    }
}

if (-not [string]::IsNullOrWhiteSpace($ClusterUri)) {
    foreach ($ttp in $selected) {
        try {
            $body = @{ db = $Database; csl = [string]$ttp.validationKql } | ConvertTo-Json -Compress
            $response = Invoke-RestMethod -Method Post -Uri "$($ClusterUri.TrimEnd('/'))/v1/rest/query" -ContentType 'application/json' -Body $body -TimeoutSec 120
            $rows = @(Get-KustoRows -Response $response)
            $flags = @($rows | ForEach-Object { [string]$_.Flag })
            if ($flags.Count -ne 1 -or $flags[0] -notlike "*$($ttp.flag)*") {
                Add-TtpFailure "TTP '$($ttp.id)' validation KQL returned '$($flags -join ', ')' instead of one '$($ttp.flag)' result."
            }
        }
        catch {
            Add-TtpFailure "TTP '$($ttp.id)' validation KQL failed: $($_.Exception.Message)"
        }
    }
}

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Error $_ }
    throw "TTP flag validation failed with $($failures.Count) error(s)."
}

Write-Host ("TTP flag validation passed: {0} categories, {1} selected TTPs." -f @($matrix.categories).Count, $selected.Count)