# Instructor guide

## Setup checklist

1. Confirm the ADX cluster exists.
2. Run `scripts\Initialize-Workshop.ps1` to create the database, tables, mappings, generated data, and ingestion.
3. Create or stage the 20 student accounts using `scripts\New-WorkshopStudents.ps1`.
4. Grant the student group ADX database viewer access using `scripts\Grant-StudentAdxAccess.ps1`.
5. Open the ADX Web UI URL and confirm the database is visible.
6. Load `workshop\student_lab.kql` in the query editor.

## Instructor storyline

Start with the sign-in. Students should find a high-risk interactive sign-in for `victor.alvarez@usag-cyber.local` from `185.225.73.18`, followed by OAuth consent, service-principal credential creation, app-only Microsoft Graph access, and Graph enumeration/collection. The endpoint pivot is `WIN11-04.usag-cyber.local`. The credential-access chain begins with PowerShell staging and progresses through registry credential discovery, SAM hive save, browser database copy, Kerberoasting, LSASS dump, password-store harvesting, and Mimikatz-style credential dumping. Keep the tool names visible because they cover the required screenshot vectors, but frame them as follow-on credential expansion after the Midnight Blizzard-style identity/OAuth foothold. The identity pivot is the service account `svc_sql`, which is later used against `AADCONNECT01`. `SecurityIncident` should be introduced as the SOC incident queue: incident titles are generic and analyst-friendly, while `AlertIds` and `AdditionalData` tie the incidents back to the scenario evidence and supporting TVM tables.

Use the Ubuntu branch as an optional comparison pivot after the Windows path is understood. Students should see that `UBUNTU-03.usag-cyber.local` emits MDE device telemetry, not MDI telemetry: SSH/PAM logons in `DeviceLogonEvents`, `sudo` and shell execution in `DeviceProcessEvents`, audit artifacts in `DeviceEvents` and `DeviceFileEvents`, Linux `.so` image loads in `DeviceImageLoadEvents`, CUPS/IPP network context in `DeviceNetworkEvents`, and Linux package/CVE context in TVM tables. The additive Oracle branch stages a synthetic Python helper and Go binary on `UBUNTU-03`, connects to Oracle TNS on `UBUNTU-05:1521`, and creates a synthetic sensitive export under `/tmp/.oracle`.

## Pacing and scope control

| Track | Use in class | Time guidance |
| --- | --- | --- |
| Must-find cloud identity path | Acts 2-4d: risky sign-in, OAuth consent, service-principal credential addition, Graph access | Do not skip. This is the strongest Midnight Blizzard alignment. |
| Must-find Windows credential path | Acts 5-10: endpoint process/file/registry, Kerberoasting, `svc_sql` to `AADCONNECT01`, alert join, timeline | Keep tool names visible, but emphasize technique families and follow-on credential expansion. |
| SOC incident correlation | Act 9 and final timeline: `SecurityIncident` to `AlertInfo`/`AlertEvidence`, plus TVM evidence tables in `AdditionalData` | Make clear that incident names are not actor-branded; the value is the grouping and pivots. |
| Optional Linux telemetry comparison | Act 11 | Use if the class is moving quickly or if Linux MDE telemetry is a learning goal. |
| Optional Linux/Oracle collection | Act 12 | Treat as a bonus branch; do not let it displace the cloud identity investigation. |

## Expected key findings

| Finding | Evidence |
| --- | --- |
| Suspicious sign-in | `SigninLogs` and `EntraIdSignInEvents` show high-risk sign-in for Victor Alvarez |
| OAuth/Graph activity | `CloudAppEvents`, `AuditLogs`, `GraphApiAuditEvents`, and `MicrosoftGraphActivityLogs` show app consent, service-principal credential creation, app-only Graph sign-in, mailbox reads, file reads, and directory enumeration |
| Service-principal persistence | `AuditLogs`, `CloudAppEvents`, `AADServicePrincipalSignInLogs`, `GraphApiAuditEvents`, `AlertInfo`, and `AlertEvidence` show `USAG Cyber Sync Helper` receiving a credential and using Microsoft Graph |
| SOC incident grouping | `SecurityIncident` shows generic SOC-style incidents such as `Multi-stage incident involving identity and endpoint activity`, with `AlertIds` joining to `AlertInfo`/`AlertEvidence` and `AdditionalData.tvmEvidenceTables` pointing to the TVM context |
| Endpoint staging | `DeviceNetworkEvents` shows `WIN11-04` connecting to `cdn.update-check.example` |
| Registry credentials | `DeviceRegistryEvents` shows saved VPN credential value access |
| SAM hive dumping | `DeviceProcessEvents` and `DeviceFileEvents` show `reg.exe save HKLM\SAM` and output files |
| Browser credential collection | `DeviceProcessEvents` and `DeviceFileEvents` show `esentutl.exe` copying Chrome Login Data |
| Kerberoasting | `IdentityQueryEvents` shows LDAP SPN search and `IdentityLogonEvents` shows Kerberos activity |
| LSASS dumping | `DeviceProcessEvents`, `DeviceFileEvents`, and alerts show minidump behavior |
| Password-store harvesting | Process events show PwDump7, gsecdump, LaZagne, and Mimikatz-style tools |
| Lateral movement | `DeviceLogonEvents` and `IdentityLogonEvents` show `svc_sql` remote logon to `AADCONNECT01` |
| TVM exposure context | The aligned TVM tables show vulnerable software, inventory, evidence paths, configuration gaps, certificate context, hardware/firmware context, and vulnerability KB entries for `WIN11-04`, `AADCONNECT01`, and the Ubuntu branch |
| Linux SSH/sudo branch | `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceEvents`, `DeviceImageLoadEvents`, `DeviceNetworkEvents`, and TVM tables show Ubuntu SSH, sudo, auditd, CUPS/IPP, `.so`, and package/CVE context |
| Linux Oracle branch | `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `AlertInfo`, and `AlertEvidence` show Python/Go tooling, Oracle TNS access on TCP/1521, and a synthetic sensitive export |

## Instructor-only alert answer key

Do not put these IDs on the student slides. The generated `AlertId` values are intentionally opaque so students learn to hunt by behavior, title, timestamp, entity, MITRE technique, `SecurityIncident.AlertIds`, and `AlertEvidence`, not by actor-branded IDs.

Use [`workshop\instructor_alert_answer_key.kql`](../workshop/instructor_alert_answer_key.kql) as the corresponding instructor-only query pack. It contains the static AlertId answer key plus the cloud, endpoint, identity, incident, TVM, Linux/Oracle, and full-timeline pivots needed to tell the scenario story.

| Scenario signal | AlertId | Offset | Alert title | MITRE ATT&CK |
| --- | --- | --- | --- | --- |
| OAuth service-principal persistence | `09fb0e10-de44-00fd-6478-518affd9a260` | +6 min | Suspicious OAuth service principal persistence | T1528, T1098.001, T1550.001 |
| PowerShell credential discovery | `621e484e-f436-6fbb-0a0c-7af49802e455` | +15 min | Suspicious PowerShell credential discovery | T1552.002 |
| Kerberoasting | `1d5d47bd-113b-c938-6499-e01752a4d4db` | +35 min | Suspected Kerberoasting activity | T1558.003 |
| LSASS dump | `97185c44-fd9b-0dc3-ae32-ef6315b35a26` | +50 min | Credential dumping from LSASS | T1003.001 |
| Password-store harvesting | `df57168c-010c-a303-3edb-d05782c407a9` | +65 min | Password store harvesting tool observed | T1555 |
| Credential dumping tool | `710e468b-1a6f-1455-61d3-7bc4181de115` | +73 min | Mimikatz credential dumping | T1003.001 |
| OAuth and Graph correlation | `9b507934-0bc3-d4ff-32d2-1b2a64796429` | +6 min | OAuth application credential added and used for Graph access | T1528, T1098.001, T1550.001 |
| Endpoint credential material correlation | `196bc75c-9d49-eb62-a9fe-79941b6507e0` | +50 min | Credential material collection on one endpoint | T1003.001, T1552.002, T1555, T1558.003 |
| Hybrid identity lateral movement correlation | `3d3bc433-e857-dc28-fec2-0131500cbf87` | +82 min | Service account interactive sign-in to identity synchronization server | T1078.002, T1021.006 |
| Linux sudo privilege escalation | `16f35dea-f474-2198-8d0c-3467e6da3f26` | +68 min | Suspicious sudo chroot usage on Linux server | T1548.003, T1059.004 |
| Linux Oracle collection | `b28ccabf-2b63-fc49-2ef3-31864d151643` | +74 min | Linux privilege escalation followed by Oracle data access | T1548.003, T1059.006, T1005 |

## Facilitation tips

- Keep students in pairs if login troubleshooting takes more than a few minutes.
- Encourage `project` and `summarize` early so students do not drown in wide schemas.
- Let students try pivots before revealing the next table.
- When students find a process, ask: "What identity is tied to it? What host? What network or file artifact follows?"

## Suggested debrief questions

1. Which table gave the earliest signal?
2. Which credential-access technique had the strongest endpoint evidence?
3. Which activity required identity telemetry rather than endpoint telemetry?
4. How did `SecurityIncident` change the investigation compared with starting directly in `AlertInfo`?
5. Which TVM rows helped explain exposure or hardening gaps rather than attacker activity?
6. What prevention or hardening would have reduced the blast radius?
7. What detections would you operationalize after this hunt?
8. How does Linux MDE telemetry differ from Windows endpoint and MDI identity telemetry?
9. Which Linux evidence distinguishes ordinary SSH administration from privilege escalation and Oracle data collection?
