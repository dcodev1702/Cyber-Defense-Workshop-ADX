# Two-hour workshop design

## Learning objectives

By the end of the workshop, students can:

1. Use KQL to orient across ADX tables that mirror Microsoft Defender and Entra telemetry.
2. Correlate identity, endpoint, Graph, cloud app, and alert events into a single attack timeline.
3. Recognize credential-access tradecraft and map findings to MITRE ATT&CK.
4. Explain what telemetry is produced by MDE, MDI, Entra ID sign-in logs, Microsoft Graph logs, CloudAppEvents, AlertInfo, and AlertEvidence.

## Scenario

The intrusion is a FIN7-inspired emulation against a hybrid AD/Entra organization using `usag-cyber.local` and account domain `USAG-CYBER`. The attacker compromises `victor.alvarez@usag-cyber.local`, completes MFA, grants a suspicious OAuth app, enumerates Graph data, lands on `WIN11-04`, then performs a credential-access sequence covering registry credentials, SAM hive saves, browser credential harvesting, Kerberoasting, LSASS dumping, password-store harvesting tools, and Mimikatz-style credential dumping. The attacker later uses a cracked service account to access `AADCONNECT01`.

## Agenda

| Segment | Duration | Instructor flow | Student activity |
| --- | ---: | --- | --- |
| Access check and KQL warm-up | 10 min | Confirm ADX Web UI access and explain the table families | Run inventory queries |
| Scenario and infrastructure | 15 min | Walk through hybrid topology and FIN7-inspired objectives | Identify users, hosts, and high-value assets |
| Entra and Graph investigation | 20 min | Start with risky sign-in and OAuth/Graph activity | Correlate SigninLogs, CloudAppEvents, AuditLogs, GraphApiAuditEvents |
| Endpoint credential access | 35 min | Pivot from compromised user to `WIN11-04` process/file/registry telemetry | Hunt the 11 screenshot attack vectors in MDE-style tables |
| MDI and lateral movement | 20 min | Show SPN enumeration, Kerberos activity, and service-account use | Correlate IdentityQueryEvents, IdentityLogonEvents, DeviceLogonEvents |
| Alert correlation and timeline | 15 min | Join AlertInfo and AlertEvidence, summarize ATT&CK coverage | Build an incident timeline |
| Debrief | 5 min | Discuss detections and prevention opportunities | Capture takeaways |

## Included table families

- MDE-style Device tables from Microsoft Learn schema references
- MDI-style Identity tables from Microsoft Learn schema references
- Entra sign-in tables: current `EntraId*`, legacy `AAD*`, and Azure Monitor `SigninLogs`
- Microsoft Graph tables: `GraphApiAuditEvents` and `MicrosoftGraphActivityLogs`
- Cloud and alert tables: `CloudAppEvents`, `AlertInfo`, `AlertEvidence`

## Schema notes

`DeviceAlertEvents` is intentionally not created because Microsoft Learn states that `AlertInfo` and `AlertEvidence` replace it in Microsoft Defender XDR. `DeviceInternetFacing` and `DeviceScriptEvents` appear in some product-scope lists, but public Microsoft Learn schema pages did not expose stable column references during generation; internet-facing context is represented through `DeviceInfo.IsInternetFacing` and `DeviceNetworkEvents`.
