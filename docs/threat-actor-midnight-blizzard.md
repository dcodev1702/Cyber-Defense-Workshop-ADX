# Threat Actor Profile — Midnight Blizzard (APT29)

> **Why this matters for this workshop.** The scenario you investigate in `student_guide.md` is modeled on Midnight Blizzard tradecraft. Read this before the workshop so you understand *why* each query is shaped the way it is, then come back after the workshop to see which of MB's real-world techniques you just hunted.

---

## TL;DR

**Midnight Blizzard** (also known as **APT29**, **Cozy Bear**, **NOBELIUM**, and **The Dukes**) is a long-running, highly capable cyber-espionage group widely attributed to Russia's foreign intelligence service (SVR). They've been active since at least 2008. Western governments and multiple major security vendors agree on attribution.

For SOC analysts working in Microsoft environments, MB is one of the most important threat actors to understand because their tradecraft has *moved with the platform*: from on-prem AD compromise (early 2010s) to supply chain attacks (SolarWinds, 2020) to identity-first attacks against Entra ID and Microsoft 365 (2023–present). They are the canonical example of an actor who treats your IdP as the perimeter.

---

## Naming

Threat actor naming is a mess. Here's how the same group shows up across vendors and reports:

| Source | Name |
| --- | --- |
| Microsoft (current) | Midnight Blizzard |
| Microsoft (legacy) | NOBELIUM, YTTRIUM |
| Mandiant / Google TI | APT29 |
| CrowdStrike | Cozy Bear |
| US/UK governments | APT29 (attributed to SVR) |
| Other vendor names | The Dukes, CozyDuke, UNC2452, IRON RITUAL, IRON HEMLOCK, Dark Halo, SolarStorm, Blue Kitsune, NobleBaron, UNC3524 |

Microsoft renamed NOBELIUM to Midnight Blizzard in April 2023 when they moved to a weather-themed taxonomy (Blizzard = Russian state-sponsored). For this workshop we use **Midnight Blizzard** (or **MB** when space is tight) because we're working in Microsoft telemetry.

---

## Attribution

Multiple Western governments have publicly attributed MB activity to Russia's **Foreign Intelligence Service (SVR)** — most notably the joint US/UK April 2021 statement attributing the SolarWinds supply chain compromise to SVR with high confidence. Subsequent advisories from CISA, NSA, FBI, NCSC (UK), and partner agencies have continued to attribute MB activity to SVR, with particular focus on adapted tactics for cloud and identity-first environments.

This means MB is a **state-funded, long-dwell intelligence collection actor** — not a smash-and-grab criminal group. They are patient, well-resourced, and willing to spend months inside an environment before acting.

---

## Targeting

MB targets organizations whose data has intelligence value for the Russian state:

- **Government agencies and ministries** — particularly foreign affairs, defense, and intelligence
- **Diplomatic missions** — embassies, NATO-aligned governments, EU institutions
- **Defense industrial base** — primes and key suppliers
- **Think tanks and policy research organizations**
- **Technology and IT service providers** — Microsoft, HPE, software developers, MSPs
- **NGOs and academic institutions** with foreign-policy or vaccine-research relevance
- **Critical infrastructure** sectors

Geographically: heavy targeting of US, UK, Western Europe, and increasingly NATO-aligned countries near Russia's borders. The scenario in this workshop — a research org with a hybrid identity environment — is exactly the kind of victim MB has compromised in the real world.

---

## Recent significant activity

A non-exhaustive timeline focused on the last few years:

- **2020 — SolarWinds supply chain compromise.** Trojanized Orion updates (SUNBURST, TEARDROP, SUNSHUTTLE) deployed to ~18,000 customers, with selective second-stage activity against ~9 US federal agencies and dozens of private sector targets. Publicly attributed to SVR by US/UK governments in April 2021.
- **2020 — COVID-19 vaccine research targeting.** UK/US/Canada joint advisory describing MB use of WellMess and WellMail malware against organizations involved in vaccine development.
- **November 2023 → March 2024 — Microsoft corporate breach.** Password spray against a legacy non-production test tenant lacking MFA. Pivoted via a forgotten OAuth application that had elevated permissions in the corporate tenant. Created additional malicious OAuth apps and a new user account to grant consent. Eventually granted themselves the `full_access_as_app` role on Exchange Online and accessed senior leadership, security, and legal team mailboxes. In March 2024, Microsoft confirmed MB had used exfiltrated secrets to access source code repositories.
- **May 2023 → 2025 — HPE breach.** Similar tradecraft — accessed HPE's Microsoft 365 email environment, exfiltrated data from a small percentage of mailboxes including cybersecurity team members. Disclosed January 2024; HPE issued individual data breach notifications in early 2025.
- **March 2024 — German political party phishing.** ROOTSAW and WINELOADER spear-phishing reported by Google Threat Intelligence.
- **October 2024 — Signed RDP file phishing.** Large-scale spear-phishing using malicious signed RDP configuration files connecting to actor-controlled servers, targeting thousands of individuals across more than 100 organizations (per Microsoft).
- **January–April 2025 — European diplomacy phishing.** Wine-tasting and diplomatic event themed lures (WINELOADER, GRAPELOADER) reported by Check Point Research.
- **August 2025 — Device code authentication abuse.** AWS reported disruption of an MB watering-hole campaign abusing Microsoft device code authentication flows.

The pattern across all of these: **MB has shifted heavily toward identity-first attacks against cloud and SaaS environments.** Endpoint malware still appears, but cloud identity is the primary attack surface.

---

## TTPs — what to hunt for

This is the section that maps directly to the queries in `student_guide.md`. Each MITRE technique below is something MB does in the real world *and* something you'll see in the workshop telemetry.

### Initial access

| Technique | What MB does | Where you'll see it in this workshop |
| --- | --- | --- |
| T1110.003 (Password Spraying) | Low-and-slow password spray from residential proxy infrastructure, often targeting legacy or service accounts without MFA | Implied by the risky sign-in in Act 2 — the scenario picks up *after* the credential was guessed |
| T1078.004 (Cloud Accounts) | Use of valid cloud account credentials obtained via spray, phishing, or token theft | `SigninLogs` row for `victor.alvarez` from `185.225.73.18` (Act 2) |
| T1566 (Phishing) | Spear-phishing with weaponized attachments (RDP files, ZIPs hosting malware loaders) | Not directly modeled, but the compromised user `victor.alvarez` is plausibly a phishing victim |

### Persistence and privilege escalation in the cloud

| Technique | What MB does | Where you'll see it in this workshop |
| --- | --- | --- |
| T1098.003 (Additional Cloud Roles) | Grant elevated roles like `full_access_as_app` to attacker-controlled OAuth apps | OAuth consent in Act 3 |
| T1136.003 (Create Cloud Account) | Create new user accounts to grant consent to malicious apps | Not directly modeled in this scenario |
| T1550.001 (Application Access Token) | Use of OAuth tokens for persistent access that survives password resets | Implied — the consent in Act 3 establishes this persistence |
| T1528 (Steal Application Access Token) | Steal access tokens from authenticated sessions | Implied by the OAuth abuse |

### Credential access (the meat of this workshop)

The workshop's Act 5 covers a credential-access playbook with multiple tools per family. While MB's *real* trademark is identity-first cloud abuse, they have demonstrated all of the following on endpoints when on-prem footholds are needed:

| Technique | What MB does | Workshop step |
| --- | --- | --- |
| T1003.001 (LSASS Memory) | LSASS dumping via `procdump`, `comsvcs.dll`, custom tools | Act 5: procdump, mimikatz, rundll32+kiwi |
| T1003.002 (SAM Hive) | SAM/SYSTEM hive extraction via `reg.exe save` or `esentutl` | Act 5: `reg.exe save HKLM\SAM` |
| T1552.002 (Credentials in Registry) | Registry hunting for stored credentials | Act 5 + Act 6: `SavedPassword` value under HKCU VPN key |
| T1555 (Credentials from Password Stores) | Generic password-store sweeps using LaZagne and similar | Act 5: `LaZagne.exe all` |
| T1555.003 (Credentials from Web Browsers) | Browser credential database theft via `esentutl` while files are locked | Act 5: Chrome `Login Data` copy |
| T1558.003 (Kerberoasting) | LDAP SPN enumeration + RC4 service ticket requests for offline cracking | Act 5 + Act 7: Rubeus + PowerShell Empire `Invoke-Kerberoast` |

### Lateral movement and discovery

| Technique | What MB does | Workshop step |
| --- | --- | --- |
| T1021.006 (WinRM) | Remote PowerShell / WinRM lateral movement using cracked or stolen credentials | Act 8: `svc_sql` RemoteInteractive logon to `AADCONNECT01` |
| T1087.002 (Domain Account Discovery) | LDAP queries to map the directory | Act 7: `IdentityQueryEvents` SPN searches |
| T1087.004 (Cloud Account Discovery) | Microsoft Graph enumeration of users, groups, and applications | Act 3: `GraphApiAuditEvents` calls |

### Defense evasion

| Technique | What MB does | Where in workshop |
| --- | --- | --- |
| T1090.002 (External Proxy) | Residential proxy infrastructure to make traffic appear as normal home users | Reflected in the source IP framing in Acts 2–3 |
| T1564 (Hide Artifacts) | Tool renaming, in-memory execution, signed binaries (e.g., signed RDP files in 2024 campaigns) | Act 5: `rundll32 kiwi.dll` to hide Mimikatz |
| T1078.004 (Valid Cloud Accounts) | Heavy reliance on legitimate credentials and tokens to blend in | Throughout — every action runs under `victor.alvarez` |

### Collection and exfiltration

| Technique | What MB does | Workshop step |
| --- | --- | --- |
| T1114.002 (Remote Email Collection) | Mailbox access via Graph API or Exchange Web Services | Implied by OAuth scopes (`Mail.Read`) granted in Act 3 |
| T1530 (Data from Cloud Storage) | Pulling files from OneDrive / SharePoint via Graph | Implied by `Files.Read.All` scope in Act 3 |

---

## Why MB matches this scenario better than commodity actors

If you've worked SOC for a while, you might wonder why the workshop scenario doesn't model a financially-motivated actor (like FIN7) where the goal is ransomware or POS card data. The answer: MB's tradecraft is far more representative of what a defender in a hybrid Microsoft environment is actually likely to face today. Specifically:

1. **Identity-first.** The compromise starts in the cloud (a risky sign-in, an OAuth consent), not on the endpoint. That mirrors how MB works, and how most modern intrusions begin.
2. **Persistent OAuth abuse.** Granting consent to a malicious "Sync Helper" app (Act 3) is a near-direct lift from the Microsoft and HPE breaches.
3. **Patient credential collection.** Multiple tools per credential-access family (Act 5) reflects how a well-resourced actor probes for which detections fire and which don't.
4. **Hybrid pivot.** Using on-prem AD credentials to reach the Entra Connect server (Act 8) reflects MB's interest in the seam between on-prem and cloud identity, which is one of the highest-impact targets in any hybrid environment.

You can run the same workshop queries against your real production telemetry and they'll catch many of MB's actual TTPs.

---

## Detections and controls worth operationalizing

Map these directly to the queries you write in the student guide:

- **Risky sign-in correlation with same-IP cloud activity within 1 hour.** (Workshop: Act 3 `let suspiciousIp = ...` pattern.)
- **OAuth app consent for high-impact scopes** (`Mail.Read`, `Mail.ReadWrite`, `Files.Read.All`, `Directory.ReadWrite.All`, `full_access_as_app`). (Workshop: `CloudAppEvents` filter for `OAuthAppConsentGranted`.)
- **New OAuth app creation followed by self-consent** within a short window.
- **Service-account interactive logon to a Tier-0 system from a workstation.** (Workshop: Act 8 — `svc_*` accounts with `RemoteInteractive` logon type.)
- **Legacy auth or password-spray indicators on tenant-wide sign-in logs**, especially against accounts without MFA.
- **LDAP SPN enumeration followed by RC4 Kerberos service ticket requests.** (Workshop: Act 7 — `IdentityQueryEvents` + `IdentityLogonEvents`.)
- **LSASS process access by non-Windows-signed binaries.** (Workshop: Act 5 — process events for `procdump`, `mimikatz`, `rundll32` loading non-standard DLLs.)

For prevention, the controls that would have stopped or significantly reduced the real Microsoft and HPE breaches:

- MFA on **every** account, including non-production test tenants and service accounts (use managed identities or workload identity federation where possible).
- Inventory and lifecycle for OAuth applications — find dormant apps with elevated permissions and remove them.
- Conditional Access policies that require compliant devices and trusted locations for high-privilege scopes.
- Disable legacy authentication protocols.
- Tier-0 isolation for Entra Connect and similar identity infrastructure; service accounts cannot interactively log in from user workstations.

---

## Public sources for further reading

- MITRE ATT&CK group page: <https://attack.mitre.org/groups/G0016/>
- Microsoft Threat Intelligence response guidance for the 2024 incident: <https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/>
- Microsoft naming taxonomy explanation: <https://learn.microsoft.com/en-us/unified-secops-platform/microsoft-threat-actor-naming>
- CISA / partner agencies advisory on SVR cloud-access tradecraft (Feb 2024): <https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-057a>
- Check Point Research on 2025 European diplomacy campaigns: <https://research.checkpoint.com/>
- Google Threat Intelligence reporting on WINELOADER (2024): <https://cloud.google.com/blog/topics/threat-intelligence>

---

## Disclaimer

This profile is a synthesis of publicly available reporting, written to support workshop learning. Threat actor naming, attribution, and observed TTPs evolve continuously. For current operational intelligence, consult Microsoft Defender Threat Intelligence (MDTI), your organization's threat intelligence platform, and the original sources linked above.
