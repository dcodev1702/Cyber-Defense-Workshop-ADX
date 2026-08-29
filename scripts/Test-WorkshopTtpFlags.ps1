<#
.SYNOPSIS
Validates the workshop TTP catalog, pivot chains, generated flags, and KQL.

.DESCRIPTION
The matrix is the contract for the cyber-range challenges. Static checks require
all 19 catalog entries to be implemented, exactly seven to form the canonical
scenario, one or two pivots per challenge, researched ATT&CK/reference metadata,
globally unique flags, and schema-valid final flag columns. Trainee step queries
must never expose a flag literal.

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
    [string]$InstructorAnswerKeyPath = (Join-Path $PSScriptRoot '..' 'docs' 'instructor_answer_key.kql'),
    [string]$ScenarioSummaryPath = (Join-Path $PSScriptRoot '..' 'data' 'scenario-summary.json'),
    [string]$DataDirectory,
    [string]$ClusterUri,
    [string]$Database = 'CyberDefendStudentSnapshot'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$failures = [System.Collections.Generic.List[string]]::new()
$expectedTtpCount = 19
$expectedScenarioTtpCount = 7

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
$scenarioTtps = [System.Collections.Generic.List[object]]::new()
$knownTtpIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
$knownFlags = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
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
$instructorAnswerKey = if (Test-Path -LiteralPath $InstructorAnswerKeyPath -PathType Leaf) {
    Get-Content -LiteralPath $InstructorAnswerKeyPath -Raw
}
else {
    Add-TtpFailure "Instructor answer key not found: $InstructorAnswerKeyPath"
    ''
}

foreach ($category in @($matrix.categories)) {
    foreach ($ttp in @($category.ttps)) {
        if (-not $knownTtpIds.Add([string]$ttp.id)) {
            Add-TtpFailure "TTP id '$($ttp.id)' is assigned more than once."
        }

        if (-not [bool]$ttp.selected) {
            Add-TtpFailure "Catalog TTP '$($ttp.id)' must be implemented and selected."
            continue
        }

        $selected.Add($ttp)
        $scenarioProperty = $ttp.PSObject.Properties['scenario']
        if (-not $scenarioProperty -or $scenarioProperty.Value -isnot [bool]) {
            Add-TtpFailure "Selected TTP '$($ttp.id)' must declare a boolean scenario value."
        }
        elseif ([bool]$scenarioProperty.Value) {
            $scenarioTtps.Add($ttp)
        }
        if ($traineeQueries -notmatch "(?m)^// TTP-ID: $([regex]::Escape([string]$ttp.id))\r?$") {
            Add-TtpFailure "Trainee query pack is missing selected TTP '$($ttp.id)'."
        }
        foreach ($property in @('description', 'enhancement', 'mitreAttack', 'references', 'finalTable', 'flagColumn', 'flag', 'pivotSteps', 'validationKql')) {
            $matrixProperty = $ttp.PSObject.Properties[$property]
            $matrixValue = if ($matrixProperty) { $matrixProperty.Value } else { $null }
            $isEmptyCollection = $matrixValue -is [System.Collections.IEnumerable] -and $matrixValue -isnot [string] -and @($matrixValue).Count -eq 0
            if (-not $matrixProperty -or $null -eq $matrixValue -or $isEmptyCollection -or ($matrixValue -is [string] -and [string]::IsNullOrWhiteSpace($matrixValue))) {
                Add-TtpFailure "Selected TTP '$($ttp.id)' is missing $property."
            }
        }

        foreach ($mapping in @($ttp.mitreAttack)) {
            if ([string]$mapping.id -notmatch '^T\d{4}(\.\d{3})?$') {
                Add-TtpFailure "TTP '$($ttp.id)' has malformed ATT&CK id '$($mapping.id)'."
            }
            if ([string]$mapping.name -eq '') {
                Add-TtpFailure "TTP '$($ttp.id)' has an ATT&CK mapping without a name."
            }
            if ([string]$mapping.url -notmatch '^https://attack\.mitre\.org/techniques/') {
                Add-TtpFailure "TTP '$($ttp.id)' ATT&CK mapping '$($mapping.id)' has a non-MITRE URL."
            }
        }
        foreach ($reference in @($ttp.references)) {
            if ([string]$reference.title -eq '' -or [string]$reference.url -notmatch '^https://') {
                Add-TtpFailure "TTP '$($ttp.id)' has an incomplete authoritative reference."
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
            $sectionTableMatches = [regex]::Matches($querySection, '(?m)^([A-Za-z][A-Za-z0-9_]*)\r?$')
            $sectionTables = @($sectionTableMatches | ForEach-Object { $_.Groups[1].Value })
            $expectedTables = @($steps | ForEach-Object { [string]$_.table })
            if ($sectionTables.Count -ne $expectedTables.Count) {
                Add-TtpFailure "Trainee query '$($ttp.id)' must contain exactly $($expectedTables.Count) table statements; found $($sectionTables.Count)."
            }
            elseif (Compare-Object -ReferenceObject $expectedTables -DifferenceObject $sectionTables -SyncWindow 0) {
                Add-TtpFailure "Trainee query '$($ttp.id)' table order '$($sectionTables -join ' -> ')' does not match '$($expectedTables -join ' -> ')'."
            }
            if ($sectionTableMatches.Count -gt 0) {
                $finalStepSection = $querySection.Substring($sectionTableMatches[-1].Index)
                $evidencePattern = '(?m)\bEvidence\s*=\s*{0}\b' -f [regex]::Escape([string]$ttp.flagColumn)
                if ($finalStepSection -notmatch $evidencePattern) {
                    Add-TtpFailure "Trainee query '$($ttp.id)' final step must project Evidence=$($ttp.flagColumn)."
                }
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

if ($knownTtpIds.Count -ne $expectedTtpCount) {
    Add-TtpFailure "TTP catalog must contain exactly $expectedTtpCount unique entries; found $($knownTtpIds.Count)."
}
if ($selected.Count -ne $expectedTtpCount) {
    Add-TtpFailure "All $expectedTtpCount catalog TTPs must be implemented; found $($selected.Count)."
}
if ($scenarioTtps.Count -ne $expectedScenarioTtpCount) {
    Add-TtpFailure "Exactly $expectedScenarioTtpCount TTPs must form the canonical scenario; found $($scenarioTtps.Count)."
}

if (-not (Test-Path -LiteralPath $ScenarioSummaryPath -PathType Leaf)) {
    Add-TtpFailure "Tracked scenario summary not found: $ScenarioSummaryPath"
}
else {
    $scenarioSummary = Get-Content -LiteralPath $ScenarioSummaryPath -Raw | ConvertFrom-Json
    $summaryTtps = @($scenarioSummary.ttpScenario)
    if ($summaryTtps.Count -ne $expectedScenarioTtpCount) {
        Add-TtpFailure "Tracked scenario summary must contain exactly $expectedScenarioTtpCount TTPs; found $($summaryTtps.Count)."
    }

    $summaryIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $previousOffset = [int]::MinValue
    foreach ($summaryTtp in $summaryTtps) {
        if (-not $summaryIds.Add([string]$summaryTtp.Id)) {
            Add-TtpFailure "Tracked scenario summary repeats TTP '$($summaryTtp.Id)'."
        }
        if ([string]::IsNullOrWhiteSpace([string]$summaryTtp.Title) -or [string]::IsNullOrWhiteSpace([string]$summaryTtp.Command)) {
            Add-TtpFailure "Tracked scenario summary TTP '$($summaryTtp.Id)' must include a title and evidence path."
        }
        $offset = [int]$summaryTtp.Offset
        if ($offset -le $previousOffset) {
            Add-TtpFailure "Tracked scenario summary offsets must be strictly increasing; '$($summaryTtp.Id)' has offset $offset after $previousOffset."
        }
        $previousOffset = $offset
    }
    foreach ($ttp in $scenarioTtps) {
        $summaryRows = @($summaryTtps | Where-Object Id -CEQ ([string]$ttp.id))
        if ($summaryRows.Count -ne 1) {
            Add-TtpFailure "Tracked scenario summary must contain one row for '$($ttp.id)'; found $($summaryRows.Count)."
            continue
        }
        $expectedTechnique = @($ttp.mitreAttack | ForEach-Object { [string]$_.id }) -join ','
        if ([string]$summaryRows[0].Technique -cne $expectedTechnique) {
            Add-TtpFailure "Tracked scenario summary '$($ttp.id)' technique is '$($summaryRows[0].Technique)', expected '$expectedTechnique'."
        }
    }
}

$instructorTtpQuery = ''
if (-not [string]::IsNullOrWhiteSpace($instructorAnswerKey)) {
    $answerKeyStart = $instructorAnswerKey.IndexOf('let TtpAnswerKey = datatable', [System.StringComparison]::Ordinal)
    $observedFlagsStart = $instructorAnswerKey.IndexOf('let ObservedTtpFlags = union', [System.StringComparison]::Ordinal)
    $answerQueryStart = if ($observedFlagsStart -ge 0) {
        $instructorAnswerKey.IndexOf('TtpAnswerKey', $observedFlagsStart + 'let ObservedTtpFlags = union'.Length, [System.StringComparison]::Ordinal)
    }
    else { -1 }

    if ($answerKeyStart -lt 0 -or $observedFlagsStart -le $answerKeyStart -or $answerQueryStart -le $observedFlagsStart) {
        Add-TtpFailure 'Instructor answer key is missing the complete TtpAnswerKey/ObservedTtpFlags query.'
    }
    else {
        $answerKeySection = $instructorAnswerKey.Substring($answerKeyStart, $observedFlagsStart - $answerKeyStart)
        $answerRowPattern = "(?m)^\s*'(?<ChallengeId>[^']+)',\s*(?<Scenario>true|false),\s*'(?<RequiredPath>[^']+)',\s*'(?<MITRE>[^']+)',\s*'(?<FinalField>[^']+)',\s*'(?<ExpectedFlag>FLAG:\{[A-Za-z0-9]+\})',?\s*$"
        $answerRows = @(
            [regex]::Matches($answerKeySection, $answerRowPattern) | ForEach-Object {
                [pscustomobject]@{
                    ChallengeId = $_.Groups['ChallengeId'].Value
                    Scenario = [bool]::Parse($_.Groups['Scenario'].Value)
                    RequiredPath = $_.Groups['RequiredPath'].Value
                    MITRE = $_.Groups['MITRE'].Value
                    FinalField = $_.Groups['FinalField'].Value
                    ExpectedFlag = $_.Groups['ExpectedFlag'].Value
                }
            }
        )
        if ($answerRows.Count -ne $expectedTtpCount) {
            Add-TtpFailure "Instructor answer key must contain exactly $expectedTtpCount TTP rows; found $($answerRows.Count)."
        }

        $answerIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        $answerFlags = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($row in $answerRows) {
            if (-not $answerIds.Add([string]$row.ChallengeId)) {
                Add-TtpFailure "Instructor answer key repeats challenge '$($row.ChallengeId)'."
            }
            if (-not $answerFlags.Add([string]$row.ExpectedFlag)) {
                Add-TtpFailure "Instructor answer key repeats flag '$($row.ExpectedFlag)'."
            }
        }
        $answerScenarioCount = @($answerRows | Where-Object Scenario).Count
        if ($answerScenarioCount -ne $expectedScenarioTtpCount) {
            Add-TtpFailure "Instructor answer key must identify exactly $expectedScenarioTtpCount scenario TTPs; found $answerScenarioCount."
        }

        foreach ($ttp in $selected) {
            $rowsForTtp = @($answerRows | Where-Object ChallengeId -CEQ ([string]$ttp.id))
            if ($rowsForTtp.Count -ne 1) {
                Add-TtpFailure "Instructor answer key must contain one row for '$($ttp.id)'; found $($rowsForTtp.Count)."
                continue
            }

            $row = $rowsForTtp[0]
            $expectedPath = @($ttp.pivotSteps | ForEach-Object { [string]$_.table }) -join ' -> '
            $expectedMitre = @($ttp.mitreAttack | ForEach-Object { [string]$_.id }) -join ','
            $expectedFinalField = '{0}.{1}' -f $ttp.finalTable, $ttp.flagColumn
            foreach ($comparison in @(
                    @{ Name = 'Scenario'; Actual = [bool]$row.Scenario; Expected = [bool]$ttp.scenario },
                    @{ Name = 'RequiredPath'; Actual = [string]$row.RequiredPath; Expected = $expectedPath },
                    @{ Name = 'MITRE'; Actual = [string]$row.MITRE; Expected = $expectedMitre },
                    @{ Name = 'FinalField'; Actual = [string]$row.FinalField; Expected = $expectedFinalField },
                    @{ Name = 'ExpectedFlag'; Actual = [string]$row.ExpectedFlag; Expected = [string]$ttp.flag }
                )) {
                if ($comparison.Actual -cne $comparison.Expected) {
                    Add-TtpFailure "Instructor answer key '$($ttp.id)' $($comparison.Name) is '$($comparison.Actual)', expected '$($comparison.Expected)'."
                }
            }
        }

        $observedFlagsSection = $instructorAnswerKey.Substring($observedFlagsStart, $answerQueryStart - $observedFlagsStart)
        $observedBranchPattern = "(?m)^\s*\((?<Table>[A-Za-z][A-Za-z0-9_]*)\s+\|[^\r\n]*FinalField='(?<FinalField>[^']+)'[^\r\n]*\),?\r?$"
        $observedBranches = @(
            [regex]::Matches($observedFlagsSection, $observedBranchPattern) | ForEach-Object {
                [pscustomobject]@{
                    Table = $_.Groups['Table'].Value
                    FinalField = $_.Groups['FinalField'].Value
                }
            }
        )
        $expectedFinalFields = @($selected | ForEach-Object { '{0}.{1}' -f $_.finalTable, $_.flagColumn } | Sort-Object -Unique)
        if ($observedBranches.Count -ne $expectedFinalFields.Count) {
            Add-TtpFailure "Instructor ObservedTtpFlags must contain exactly $($expectedFinalFields.Count) final-field branches; found $($observedBranches.Count)."
        }
        foreach ($finalField in $expectedFinalFields) {
            $matchingBranches = @($observedBranches | Where-Object FinalField -CEQ $finalField)
            if ($matchingBranches.Count -ne 1) {
                Add-TtpFailure "Instructor ObservedTtpFlags must contain one '$finalField' branch; found $($matchingBranches.Count)."
                continue
            }
            $expectedTable = $finalField.Split('.')[0]
            if ([string]$matchingBranches[0].Table -cne $expectedTable) {
                Add-TtpFailure "Instructor ObservedTtpFlags field '$finalField' reads from '$($matchingBranches[0].Table)', expected '$expectedTable'."
            }
        }

        $answerQuery = $instructorAnswerKey.Substring($answerQueryStart)
        if ($answerQuery -notmatch '(?s)\|\s*join\s+kind=leftouter\s+ObservedTtpFlags\s+on\s+\$left\.ExpectedFlag\s*==\s*\$right\.ObservedFlag\s*,\s*\$left\.FinalField\s*==\s*\$right\.FinalField') {
            Add-TtpFailure 'Instructor TTP answer query must join on both ExpectedFlag and FinalField.'
        }
        if ($observedFlagsSection -notmatch '(?s)let\s+ObservedTtpFlagTotals\s*=\s*ObservedTtpFlags\s*\|\s*summarize\s+TotalOccurrences\s*=\s*sum\(Occurrences\)\s+by\s+ObservedFlag') {
            Add-TtpFailure 'Instructor TTP answer query must total each flag across all declared evidence fields.'
        }
        if ($answerQuery -notmatch '(?s)\|\s*join\s+kind=leftouter\s+ObservedTtpFlagTotals\s+on\s+\$left\.ExpectedFlag\s*==\s*\$right\.ObservedFlag') {
            Add-TtpFailure 'Instructor TTP answer query must join each expected flag to its global occurrence total.'
        }
        $occurrenceExtend = $answerQuery.IndexOf('| extend Occurrences=coalesce(Occurrences, 0)', [System.StringComparison]::Ordinal)
        $totalOccurrenceExtend = $answerQuery.IndexOf('| extend TotalOccurrences=coalesce(TotalOccurrences, 0)', [System.StringComparison]::Ordinal)
        $statusExtend = $answerQuery.IndexOf('| extend Status=case(', [System.StringComparison]::Ordinal)
        if ($occurrenceExtend -lt 0 -or $totalOccurrenceExtend -le $occurrenceExtend -or $statusExtend -le $totalOccurrenceExtend) {
            Add-TtpFailure 'Instructor TTP answer query must normalize location and global occurrence counts before classifying Status.'
        }
        if ($answerQuery -notmatch "(?s)TotalOccurrences\s*==\s*0\s*,\s*'Missing'.*Occurrences\s*==\s*0\s*,\s*'Misplaced'.*TotalOccurrences\s*>\s*1\s*,\s*'Duplicate'.*Occurrences\s*==\s*1\s*,\s*'PresentOnce'") {
            Add-TtpFailure 'Instructor TTP answer query must distinguish missing, misplaced, duplicate, and unique flags.'
        }

        $nextInstructorQuery = $instructorAnswerKey.IndexOf('// Query 02 -', $answerQueryStart, [System.StringComparison]::Ordinal)
        if ($nextInstructorQuery -le $answerQueryStart) {
            Add-TtpFailure 'Instructor answer key is missing the Query 02 boundary after its TTP query.'
        }
        else {
            $instructorTtpQuery = $instructorAnswerKey.Substring($answerKeyStart, $nextInstructorQuery - $answerKeyStart).Trim()
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

    if (-not [string]::IsNullOrWhiteSpace($instructorTtpQuery)) {
        try {
            $body = @{ db = $Database; csl = $instructorTtpQuery } | ConvertTo-Json -Compress
            $response = Invoke-RestMethod -Method Post -Uri "$($ClusterUri.TrimEnd('/'))/v1/rest/query" -ContentType 'application/json' -Body $body -TimeoutSec 120
            $rows = @(Get-KustoRows -Response $response)
            if ($rows.Count -ne $expectedTtpCount) {
                Add-TtpFailure "Instructor TTP answer query returned $($rows.Count) rows instead of $expectedTtpCount."
            }
            $liveScenarioCount = @($rows | Where-Object { [bool]$_.Scenario }).Count
            if ($liveScenarioCount -ne $expectedScenarioTtpCount) {
                Add-TtpFailure "Instructor TTP answer query returned $liveScenarioCount scenario rows instead of $expectedScenarioTtpCount."
            }
            foreach ($row in $rows) {
                if ([string]$row.Status -cne 'PresentOnce' -or [long]$row.Occurrences -ne 1 -or [long]$row.TotalOccurrences -ne 1) {
                    Add-TtpFailure "Instructor TTP answer query classified '$($row.ChallengeId)' as '$($row.Status)' with $($row.Occurrences) occurrence(s) in the expected field and $($row.TotalOccurrences) overall."
                }
            }
        }
        catch {
            Add-TtpFailure "Instructor TTP answer query failed: $($_.Exception.Message)"
        }
    }
}

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Error $_ }
    throw "TTP flag validation failed with $($failures.Count) error(s)."
}

Write-Host ("TTP flag validation passed: {0} categories, {1} selected TTPs." -f @($matrix.categories).Count, $selected.Count)