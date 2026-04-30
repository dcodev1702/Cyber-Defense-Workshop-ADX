# Instructor guide

## Setup checklist

1. Confirm the ADX cluster exists.
2. Run `scripts\Initialize-Workshop.ps1` to create the database, tables, mappings, generated data, and ingestion.
3. Create or stage the 20 student accounts using `scripts\New-WorkshopStudents.ps1`.
4. Grant the student group ADX database viewer access using `scripts\Grant-StudentAdxAccess.ps1`.
5. Open the ADX Web UI URL and confirm the database is visible.
6. Load `workshop\student_lab.kql` in the query editor.

## Instructor storyline

Start with the sign-in. Students should find a high-risk interactive sign-in for `victor.alvarez@usag-cyber.local` from `185.225.73.18`, followed by OAuth consent and Graph enumeration. The endpoint pivot is `WIN11-04.usag-cyber.local`. The credential-access chain begins with PowerShell staging and progresses through registry credential discovery, SAM hive save, browser database copy, Kerberoasting, LSASS dump, password-store harvesting, and Mimikatz-style credential dumping. The identity pivot is the service account `svc_sql`, which is later used against `AADCONNECT01`.

## Expected key findings

| Finding | Evidence |
| --- | --- |
| Suspicious sign-in | `SigninLogs` and `EntraIdSignInEvents` show high-risk sign-in for Victor Alvarez |
| OAuth/Graph activity | `CloudAppEvents`, `AuditLogs`, `GraphApiAuditEvents`, and `MicrosoftGraphActivityLogs` show app consent and Graph reads |
| Endpoint staging | `DeviceNetworkEvents` shows `WIN11-04` connecting to `cdn.update-check.example` |
| Registry credentials | `DeviceRegistryEvents` shows saved VPN credential value access |
| SAM hive dumping | `DeviceProcessEvents` and `DeviceFileEvents` show `reg.exe save HKLM\SAM` and output files |
| Browser credential collection | `DeviceProcessEvents` and `DeviceFileEvents` show `esentutl.exe` copying Chrome Login Data |
| Kerberoasting | `IdentityQueryEvents` shows LDAP SPN search and `IdentityLogonEvents` shows Kerberos activity |
| LSASS dumping | `DeviceProcessEvents`, `DeviceFileEvents`, and alerts show minidump behavior |
| Password-store harvesting | Process events show PwDump7, gsecdump, LaZagne, and Mimikatz-style tools |
| Lateral movement | `DeviceLogonEvents` and `IdentityLogonEvents` show `svc_sql` remote logon to `AADCONNECT01` |

## Facilitation tips

- Keep students in pairs if login troubleshooting takes more than a few minutes.
- Encourage `project` and `summarize` early so students do not drown in wide schemas.
- Let students try pivots before revealing the next table.
- When students find a process, ask: "What identity is tied to it? What host? What network or file artifact follows?"

## Suggested debrief questions

1. Which table gave the earliest signal?
2. Which credential-access technique had the strongest endpoint evidence?
3. Which activity required identity telemetry rather than endpoint telemetry?
4. What prevention or hardening would have reduced the blast radius?
5. What detections would you operationalize after this hunt?
