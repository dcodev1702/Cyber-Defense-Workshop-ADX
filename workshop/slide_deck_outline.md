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

- MIDNIGHT BLIZZARD / APT29-inspired state-backed collection scenario
- Core path: valid cloud account -> OAuth consent -> service-principal credential persistence -> Graph collection -> hybrid identity pivot
- Endpoint tool names stay in the lab to satisfy the required credential-access vectors and give students concrete MDE hunting practice

Speaker note: Do not frame the Windows tools as the actor's signature. Frame them as follow-on credential expansion after the identity/OAuth foothold.

## Slide 5 - Scenario timeline

Compromised sign-in -> OAuth consent -> service-principal credential added -> app-only Graph activity -> endpoint staging -> credential access -> Kerberoasting -> service-account use against Entra Connect -> optional Ubuntu SSH/sudo/Oracle branch -> alert correlation.

Speaker note: The important shift is that the application identity can keep working even if Victor's password is reset. That is the key Midnight Blizzard lesson.

## Slide 6 - Table families

MDE Device* for Windows and Ubuntu, MDI Identity* for Windows identity infrastructure, Entra sign-in, Microsoft Graph, CloudAppEvents, AlertInfo, AlertEvidence.

## Slide 7 - MITRE coverage

- Cloud/identity: T1078.004, T1110.003, T1090.002, T1528, T1098.001, T1098.003, T1550.001, T1087.004, T1114.002, T1530
- Windows credential access: T1552.002, T1003.002, T1555.003, T1558.003, T1003.001, T1555
- Lateral movement and hybrid identity: T1021.006, T1087.002
- Linux bonus branch: T1021.004, T1548.003, T1059.004, T1059.006, T1005

Speaker note: Tell students to write the technique and the evidence table together. A technique without a table/query is not a defensible finding.

## Slide 8 - KQL investigation pattern

Start broad, project narrow, summarize, join, build timeline.

Speaker note: Reinforce the `let` pattern. Students should capture a suspicious IP, user, app ID, service-principal ID, and device name once, then reuse those pivots instead of hardcoding every query.

## Slide 9 - Student lab checkpoints

1. Find risky sign-in
2. Correlate OAuth consent, service-principal credential creation, and Graph activity
3. Hunt process/file/registry evidence
4. Confirm Kerberoasting in identity telemetry
5. Confirm service-account movement to `AADCONNECT01`
6. Compare Ubuntu SSH/sudo/auditd telemetry with Windows endpoint rows
7. Trace optional Python/Go Oracle data-access branch
8. Join alerts and evidence

## Slide 10 - Debrief

What telemetry was decisive? What detections would you keep? What controls reduce impact?

Speaker note: Expected answer should include identity controls, app governance, service-principal credential monitoring, Graph API auditing, Tier-0 isolation for Entra Connect, and MDE/MDI coverage across Windows and Linux.
