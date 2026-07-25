# Two-hour workshop design

## Learning objectives

By the end of the workshop, students can:

1. Use KQL to orient across ADX tables that mirror Microsoft Defender and Entra telemetry.
2. Correlate email, identity, endpoint, Graph, cloud app, threat-intel, and alert events into a single attack timeline.
3. Recognize credential-access tradecraft and map findings to MITRE ATT&CK.
4. Separate a malicious device-code sign-in from a legitimate one that looks almost identical.
5. Explain what telemetry is produced by Defender for Office 365, MDE, MDI, Entra ID sign-in logs, Microsoft Graph logs, `CloudAppEvents`, `AlertInfo`, and `AlertEvidence`.

## Scenario

The intrusion is a MIDNIGHT BLIZZARD emulation against a hybrid AD/Entra organization using `usag-cyber.local` and account domain `USAG-CYBER`. It opens with delivery rather than mid-stream: a device-code phishing mail reaches `victor.alvarez@usag-cyber.local` carrying a lure that points at the genuine `microsoft.com/devicelogin`, so URL reputation never fires and the victim completes real MFA against real Microsoft infrastructure. The attacker redeems the resulting token from `185.225.73.18` on an unmanaged device. A deliberately benign twin sits alongside it: `alice.weber` performs a legitimate device-code sign-in from a compliant, Azure AD joined device, so any detection keyed on the protocol alone flags the wrong user.

From that foothold the attacker grants a suspicious OAuth app, adds service-principal credentials for persistence, enumerates Graph data, lands on `WIN11-04`, then performs a credential-access sequence covering registry credentials, SAM hive saves, browser credential harvesting, Kerberoasting, LSASS dumping, password-store harvesting tools, and Mimikatz-style credential dumping. The Windows tool names remain in the lab because they cover the required screenshot attack vectors; instructor framing should make clear that the actor-specific core is the identity/OAuth/service-principal/Graph chain, while endpoint tooling is the follow-on credential expansion exercise. The attacker later uses a cracked service account to access `AADCONNECT01`.

The scenario then establishes impact rather than stopping at credential theft: storage account key listing, bulk blob reads, and mailbox access show data actually moving. Closing beats correlate the hand-found indicators against threat intelligence, show how UEBA and Identity Protection scored the same activity independently, and group the eleven alerts into four SOC incidents. Acts are numbered 0-12 to match the deck; `docs/instructor_answer_key.kql` uses the same numbering and adds Acts 13-16 for material beyond the deck.

An additive Linux/Oracle branch gives students realistic Ubuntu/MDE pivots without replacing the core Midnight Blizzard path. Treat it as bonus telemetry realism and a comparison exercise: the Linux branch includes SSH logons, `sudo`, `auditd`, CUPS/IPP exposure, package/vulnerability context, Linux paths under `/etc`, `/usr`, `/var/log`, and `.so` shared-object image loads. A secondary branch follows synthetic Python and Go tooling from `UBUNTU-03` to Oracle TNS access against `UBUNTU-05`, ending in a synthetic sensitive-data export from an Oracle database.

## Agenda

| Segment | Duration | Instructor flow | Student activity |
| --- | ---: | --- | --- |
| Frame and access check | 10 min | Confirm ADX Web UI access, then set up the KQL mental model, the lab terrain, and the kill chain | Run inventory queries (Acts 0-1) |
| Phish, device code, and the benign twin | 20 min | Open on the device-code lure and the legitimate sign-in that mimics it | Correlate `EmailEvents`, `EmailUrlInfo`, `UrlClickEvents`, and `SigninLogs` (Acts 2-4) |
| OAuth consent, Graph, and persistence | 20 min | Follow the attacker IP into consent, service-principal credential add, and app-only Graph use | Correlate `OAuthAppInfo`, `CloudAppEvents`, `AuditLogs`, `GraphAPIAuditEvents` (Act 5) |
| Endpoint credential access | 30 min | Pivot from compromised user to `WIN11-04` process/file/registry telemetry | Hunt the credential-access chain in MDE-style tables (Acts 6-7) |
| Kerberoast and hybrid identity pivot | 20 min | Show SPN enumeration, RC4 service tickets, and the `AADCONNECT01` pivot | Correlate `IdentityQueryEvents`, `SecurityEvent`, `DeviceLogonEvents` (Acts 8-9) |
| Linux MDE branch | Optional | Show Ubuntu SSH/sudo/auditd, Oracle TNS, and TVM pivots | Compare Linux paths, `.so` loads, SSH/sudo telemetry, and Oracle data-access evidence with Windows endpoint rows |
| Cloud exfil, threat intel, and XDR | 15 min | Storage key listing and mailbox reads, the threat-intel join, then alert correlation | Correlate `AzureActivity`, `OfficeActivity`, `ThreatIntelIndicators`, `AlertInfo` + `AlertEvidence` (Acts 10-12) |
| Debrief and next | 5 min | What was decisive, then SOAR, detection engineering, and enhanced defense | Capture takeaways |

## Included table families

The package creates 79 tables. The families that carry the investigation are:

- Defender for Office 365 mail tables behind the device-code lure: `EmailEvents`, `EmailUrlInfo`, `UrlClickEvents`, `EmailAttachmentInfo`, `EmailPostDeliveryEvents`
- MDE-style Device tables from Microsoft Learn schema references, including Windows and Ubuntu Linux hosts
- MDI-style Identity tables from Microsoft Learn schema references for Windows Server domain controllers and identity-role servers
- Entra sign-in tables: current `EntraId*`, legacy `AAD*`, and Azure Monitor `SigninLogs`
- Microsoft Graph and OAuth tables: `GraphAPIAuditEvents`, `MicrosoftGraphActivityLogs`, `OAuthAppInfo`, `AuditLogs`
- Cloud and alert tables: `CloudAppEvents`, `AlertInfo`, `AlertEvidence`
- Windows auditing, threat intel, and case tables: `SecurityEvent`, `ThreatIntelIndicators`, `SecurityIncident`, `SecurityAlert`
- Cloud control plane and data movement: `AzureActivity`, `CloudStorageAggregatedEvents`, `OfficeActivity`, `StorageBlobLogs`
- Risk, behaviour, and exposure context: `AADRiskyUsers`, `AADRiskyServicePrincipals`, `BehaviorAnalytics`, `ExposureGraphNodes`, `ExposureGraphEdges`

The authoritative list is [`metadata/tables.manifest.json`](../metadata/tables.manifest.json).

## Schema notes

`DeviceAlertEvents` is intentionally not created because Microsoft Learn states that `AlertInfo` and `AlertEvidence` replace it in Microsoft Defender XDR. `DeviceInternetFacing` and `DeviceScriptEvents` appear in some product-scope lists, but public Microsoft Learn schema pages did not expose stable column references during generation; internet-facing context is represented through `DeviceInfo.IsInternetFacing` and `DeviceNetworkEvents`.

Linux servers are modeled as Microsoft Defender for Endpoint onboarded Ubuntu hosts. They do not emit Defender for Identity sensor telemetry. Linux telemetry uses Ubuntu file-system paths, SSH/PAM/sudo/auditd concepts, package inventory, kernel/package vulnerability context, Oracle listener/database paths under `/opt/oracle` and `/u01/app/oracle`, and ELF shared objects (`.so`) rather than Windows registry or DLL patterns.
