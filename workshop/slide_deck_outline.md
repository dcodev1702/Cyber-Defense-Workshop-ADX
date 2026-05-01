# Instructor slide deck outline

## Slide 1 - Workshop title

Cyber Defense with KQL in Azure Data Explorer

Speaker note: Frame this as a detection and investigation exercise using synthetic Defender-style telemetry.

## Slide 2 - Learning objectives

- Navigate Defender and Entra-style tables in ADX
- Correlate endpoint, identity, cloud, Graph, and alert evidence
- Map findings to MITRE ATT&CK
- Build a defensible incident timeline

## Slide 3 - Lab environment

- 2 DCs with MDI
- 10 Windows 11 25H2 endpoints with MDE
- 5 Ubuntu endpoints with MDE only
- UBUNTU-05 hosts a notional Oracle database for an optional Linux branch
- Entra Connect server
- Hybrid Entra ID

## Slide 4 - Threat actor framing

FIN7-inspired intrusion emulation focused on credential access and hybrid identity pivoting.

## Slide 5 - Scenario timeline

Compromised sign-in -> OAuth consent -> Graph enumeration -> endpoint staging -> credential access -> Kerberoasting -> service-account use -> optional Ubuntu SSH/sudo/Oracle branch -> alert correlation.

## Slide 6 - Table families

MDE Device* for Windows and Ubuntu, MDI Identity* for Windows identity infrastructure, Entra sign-in, Microsoft Graph, CloudAppEvents, AlertInfo, AlertEvidence.

## Slide 7 - MITRE coverage

T1552.002, T1003.002, T1555.003, T1558.003, T1003.001, T1555, T1021.004, T1548.003, T1059.004, T1059.006, T1005.

## Slide 8 - KQL investigation pattern

Start broad, project narrow, summarize, join, build timeline.

## Slide 9 - Student lab checkpoints

1. Find risky sign-in
2. Correlate Graph and OAuth activity
3. Hunt process/file/registry evidence
4. Confirm Kerberoasting in identity telemetry
5. Compare Ubuntu SSH/sudo/auditd telemetry with Windows endpoint rows
6. Trace optional Python/Go Oracle data-access branch
7. Join alerts and evidence

## Slide 10 - Debrief

What telemetry was decisive? What detections would you keep? What controls reduce impact?
