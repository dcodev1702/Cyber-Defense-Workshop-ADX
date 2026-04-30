[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\workshop\CyberDefenseKqlWorkshop.pptx')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    $powerPoint = New-Object -ComObject PowerPoint.Application
}
catch {
    throw 'PowerPoint COM automation is not available. Use workshop\slide_deck_outline.md as the slide source or run this script on a workstation with PowerPoint installed.'
}

$powerPoint.Visible = $true
$presentation = $powerPoint.Presentations.Add()

$slides = @(
    @{ Title = 'Cyber Defense with KQL in ADX'; Body = 'Two-hour instructor-led workshop`nSynthetic Defender XDR, MDE, MDI, Entra, Graph, and alert telemetry' },
    @{ Title = 'Learning objectives'; Body = 'Use KQL across security telemetry`nCorrelate endpoint, identity, cloud, Graph, and alerts`nMap evidence to MITRE ATT&CK`nBuild an incident timeline' },
    @{ Title = 'Lab environment'; Body = '2 DCs with MDI`n10 Windows 11 25H2 endpoints with MDE`n5 Ubuntu endpoints with MDE`nEntra Connect server`nHybrid Entra ID' },
    @{ Title = 'Threat actor framing'; Body = 'FIN7-inspired credential-access intrusion`nCompromised user: Victor Alvarez`nInitial endpoint: WIN11-04`nHigh-value pivot: AADCONNECT01' },
    @{ Title = 'Scenario timeline'; Body = 'Risky sign-in -> OAuth consent -> Graph enumeration`nEndpoint staging -> credential access -> Kerberoasting`nService-account use -> alert correlation' },
    @{ Title = 'Table families'; Body = 'MDE Device* tables`nMDI Identity* tables`nSigninLogs and EntraId* tables`nGraphApiAuditEvents and MicrosoftGraphActivityLogs`nCloudAppEvents, AlertInfo, AlertEvidence' },
    @{ Title = 'MITRE coverage'; Body = 'T1552.002 Credentials in Registry`nT1003.002 SAM dumping`nT1555.003 Browser credentials`nT1558.003 Kerberoasting`nT1003.001 LSASS memory`nT1555 Password stores' },
    @{ Title = 'KQL investigation pattern'; Body = 'Start broad`nProject narrow`nSummarize`nJoin`nBuild timeline`nExplain evidence' },
    @{ Title = 'Student checkpoints'; Body = 'Find risky sign-in`nCorrelate OAuth and Graph activity`nHunt process/file/registry evidence`nConfirm Kerberoasting`nJoin alerts to evidence' },
    @{ Title = 'Debrief'; Body = 'What telemetry was decisive?`nWhich detection would you operationalize?`nWhich controls reduce credential-access impact?' }
)

foreach ($slideDef in $slides) {
    $slide = $presentation.Slides.Add($presentation.Slides.Count + 1, 2)
    $slide.Shapes.Title.TextFrame.TextRange.Text = $slideDef.Title
    $slide.Shapes.Item(2).TextFrame.TextRange.Text = ($slideDef.Body -replace '`n', [Environment]::NewLine)
}

New-Item -ItemType Directory -Path (Split-Path -Parent $OutputPath) -Force | Out-Null
$presentation.SaveAs((Resolve-Path (Split-Path -Parent $OutputPath)).Path + '\' + (Split-Path -Leaf $OutputPath))
$presentation.Close()
$powerPoint.Quit()
Write-Host "Wrote PowerPoint deck to $OutputPath"
