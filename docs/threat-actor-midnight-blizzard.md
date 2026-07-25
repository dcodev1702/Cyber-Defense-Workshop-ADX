# 🐻 Threat Actor Profile — Midnight Blizzard (APT29)

> **Why this matters for this workshop.** The intrusion you investigate is modeled on Midnight Blizzard tradecraft. Read this before the workshop so you understand *why* each query is shaped the way it is, then come back afterwards to see which of MB's real-world techniques you just hunted. The queries themselves live in [`docs/instructor_answer_key.kql`](instructor_answer_key.kql).

---

## 🎯 Key judgments

1. **MB is an identity-first actor.** Since roughly 2023 the centre of gravity has moved from endpoint malware to tokens, OAuth applications, and service principals. If you only hunt on the endpoint, you will meet them late.
2. **Their access outlives your password reset.** Consented OAuth apps, added service-principal credentials, registered devices, and stolen refresh tokens all survive a credential rotation. Eviction is an identity operation, not a helpdesk one.
3. **They prefer legitimate paths over exploits.** Valid accounts, real MFA, genuine Microsoft URLs, dormant accounts, residential proxies. Very little of what they do looks like malware, which is precisely why behavioural correlation beats signature matching.
4. **They are patient and well resourced.** State-funded collection, long dwell, and a demonstrated willingness to probe which detections fire before committing.
5. **The seam between on-prem AD and Entra ID is a favourite target.** AD FS, Entra Connect, hybrid identity, and token-signing material appear again and again in their operations.

---

## 📇 Naming

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

> ⚠️ **Do not conflate MB with every Russian-aligned cluster.** Microsoft tracks a separate actor, **Storm-2372**, for the large-scale device-code phishing campaign disclosed in February 2025, assessed only with *moderate confidence* as aligned to Russian interests. Volexity reported the same period as *multiple* Russian threat actors converging on device-code authentication. MB has its own, separately reported device-code activity (see the timeline). Attribution discipline matters: same technique does not mean same actor.

---

## 🏛️ Attribution

Multiple Western governments have publicly attributed MB activity to Russia's **Foreign Intelligence Service (SVR)** — most notably the joint US/UK April 2021 statement attributing the SolarWinds supply chain compromise to SVR with high confidence. Subsequent advisories from CISA, NSA, FBI, NCSC (UK), and partner agencies have continued to attribute MB activity to SVR, with particular focus on adapted tactics for cloud and identity-first environments.

This means MB is a **state-funded, long-dwell intelligence collection actor** — not a smash-and-grab criminal group. They are patient, well-resourced, and willing to spend months inside an environment before acting.

---

## 🌍 Targeting

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

## 🕰️ Activity timeline

A non-exhaustive timeline, weighted toward the campaigns that shaped modern MB tradecraft:

| When | Campaign | Why it matters |
| --- | --- | --- |
| **2020** | **SolarWinds supply chain compromise** | Trojanized Orion updates (SUNBURST, TEARDROP, SUNSHUTTLE) reached ~18,000 customers, with selective second-stage activity against ~9 US federal agencies. Introduced Golden SAML — stealing AD FS token-signing material to mint arbitrary tokens. Attributed to SVR by the US and UK in April 2021. |
| **2020** | **COVID-19 vaccine research** | WellMess / WellMail malware against vaccine developers, per a UK/US/Canada joint advisory. |
| **2022** | **MagicWeb** | A malicious DLL loaded into the AD FS process allowed authentication as *any* user. The clearest example of MB attacking hybrid identity infrastructure itself. |
| **Nov 2023 → Mar 2024** | **Microsoft corporate breach** | Password spray against a legacy non-production test tenant lacking MFA. Pivoted through a forgotten OAuth application holding elevated corporate-tenant permissions, created further malicious apps, and granted itself `full_access_as_app` on Exchange Online to read leadership, security, and legal mailboxes. By March 2024 Microsoft confirmed exfiltrated secrets were used to reach source code repositories. |
| **May 2023 → 2025** | **HPE breach** | Same shape — Microsoft 365 mailbox access, including the cybersecurity team's. Disclosed January 2024; individual breach notifications issued in early 2025. |
| **Feb 2024** | **Joint advisory on SVR cloud tradecraft** | CISA/NCSC and partners documented the pivot to cloud: dormant account targeting, residential proxies, token theft, MFA fatigue, and device registration. |
| **Mar 2024** | **German political party phishing** | ROOTSAW and WINELOADER lures, reported by Google Threat Intelligence. |
| **Oct 2024** | **Signed RDP file phishing** | Malicious *signed* RDP configuration files pointing at actor-controlled servers, targeting thousands of individuals across 100+ organizations. Amazon separately disrupted MB domains impersonating AWS in the same campaign. |
| **Jan–Apr 2025** | **European diplomacy phishing** | Wine-tasting and diplomatic event lures delivering WINELOADER and GRAPELOADER, reported by Check Point Research. |
| **Jun 2025** | **Application-specific password abuse** | Google Threat Intelligence reported MB phishing academics and critics of Russia into generating **application-specific passwords** — a legitimate feature that bypasses MFA entirely. |
| **Aug 2025** | **Watering hole → device code authentication** | Amazon disrupted an MB campaign that compromised legitimate websites and injected obfuscated JavaScript, redirecting ~10% of visitors to actor domains (e.g. `findcloudflare[.]com`) that mimicked Cloudflare verification pages. The goal was to trick users into authorizing attacker-controlled devices via **Microsoft's device code authentication flow**. When disrupted, the actor moved infrastructure and switched from client-side to server-side redirects. |

**The through-line:** MB has shifted decisively toward **abusing legitimate authentication features** — device code flow, app passwords, OAuth consent, device registration. None of these are vulnerabilities. All of them are working as designed. That is exactly what makes them hard to detect and why this workshop is built around behavioural correlation rather than signatures.

---

## ⚔️ TTPs — what to hunt for

Each MITRE technique below is something MB does in the real world *and* something you'll see in the workshop telemetry. Act numbers refer to the workshop storyboard (Acts 0–12).

### Initial access

| Technique | What MB does | Where you'll see it in this workshop |
| --- | --- | --- |
| T1566.002 (Spearphishing Link) | Lures pointing at legitimate Microsoft authentication URLs — including `microsoft.com/devicelogin` — so the link survives reputation checks | **Act 2**: `EmailEvents`, `EmailUrlInfo`, and `UrlClickEvents` for the device-code lure |
| T1078.004 (Valid Cloud Accounts) | Valid cloud credentials obtained via spray, phishing, or token theft — the sign-in itself is legitimate | **Act 3**: `SigninLogs` for `victor.alvarez` from `185.225.73.18` |
| T1110.003 (Password Spraying) | Low-and-slow spray from residential proxies, targeting legacy and service accounts without MFA | Implied upstream of Act 3 — the scenario picks up *after* access is obtained |
| T1078.003 (Dormant / Local Accounts) | Deliberately targets inactive accounts belonging to people who have left the organization | Reflected in the account hygiene discussion; hunt `IdentityInfo` for stale enabled accounts |
| T1621 (MFA Request Generation) | Repeated MFA prompts until the user approves out of fatigue | Not modeled — the scenario uses device-code consent instead, which needs no MFA prompt at all |

> 💡 **Why device code phishing works.** The victim sees a real Microsoft sign-in page on a real Microsoft domain, and completes real MFA. Everything they are trained to check looks correct. The only thing wrong is *who is holding the resulting token*. This is why Act 2 pairs `UrlClickEvents` with the sign-in that follows — the click is the only anomalous artifact.

### Persistence and privilege escalation in the cloud

| Technique | What MB does | Where you'll see it in this workshop |
| --- | --- | --- |
| T1098.003 (Additional Cloud Roles) | Grant elevated roles like `full_access_as_app` to attacker-controlled OAuth apps | **Act 5**: OAuth consent for `USAG Cyber Sync Helper` |
| T1098.001 (Additional Cloud Credentials) | Add credentials to an app or service principal so access continues independently of the user's password | **Act 5**: `AuditLogs`, `CloudAppEvents`, and `AADServicePrincipalSignInLogs` showing SP credential creation then app-only sign-in |
| T1098.005 (Device Registration) | Register attacker-controlled devices into the tenant — including enrolling MFA on a compromised dormant account — to obtain a Primary Refresh Token | Not modeled directly; a high-value hunt to add against `AuditLogs` device registration events |
| T1550.001 (Application Access Token) | Use OAuth tokens and app credentials for access that survives password resets | **Act 5**: app-only Graph activity from `USAG Cyber Sync Helper` |
| T1528 (Steal Application Access Token) | Capture tokens from authenticated sessions — the payoff of the device-code lure | **Acts 2 → 5**: the click, then the token being used |
| T1136.003 (Create Cloud Account) | Create new users purely to grant consent to malicious apps | Not directly modeled in this scenario |
| T1556.007 (Hybrid Identity) | Modify AD FS to authenticate as any user (MagicWeb) | Conceptually behind **Act 9** — why reaching the identity server matters so much |
| T1484.002 / T1606.002 (Trust Modification / SAML Tokens) | Golden SAML — steal token-signing certificates and mint tokens for any identity | Context for **Act 9**; the endgame the hybrid pivot is reaching for |

### Credential access (the meat of this workshop)

The workshop's Act 7 covers a credential-access playbook with multiple tools per family. While MB's *real* trademark is identity-first cloud abuse, they have demonstrated all of the following on endpoints when on-prem footholds are needed:

| Technique | What MB does | Workshop step |
| --- | --- | --- |
| T1003.001 (LSASS Memory) | LSASS dumping via `procdump`, `comsvcs.dll`, custom tools | **Act 7**: procdump, mimikatz, rundll32+kiwi |
| T1003.002 (SAM Hive) | SAM/SYSTEM hive extraction via `reg.exe save` or `esentutl` | **Act 7**: `reg.exe save HKLM\SAM` |
| T1552.002 (Credentials in Registry) | Registry hunting for stored credentials | **Acts 6\u20137**: `SavedPassword` value under the HKCU VPN key |
| T1555 (Credentials from Password Stores) | Generic password-store sweeps using LaZagne and similar | **Act 7**: `LaZagne.exe all` |
| T1555.003 (Credentials from Web Browsers) | Browser credential database theft via `esentutl` while files are locked | **Act 7**: Chrome `Login Data` copy |
| T1539 (Steal Web Session Cookie) | Copy browser profile directories to lift session cookies and bypass MFA | Adjacent to **Act 7**; the same Chrome profile access |
| T1558.003 (Kerberoasting) | LDAP SPN enumeration + RC4 service ticket requests for offline cracking | **Act 8**: Rubeus and `Invoke-Kerberoast` |
| T1003.006 (DCSync) | Replicate directory data from a domain controller once privileged | The logical next step after **Act 9** |
| T1552.004 (Private Keys) | Steal AD FS token-signing certificates and private keys | The objective behind the **Act 9** pivot |

### Lateral movement and discovery

| Technique | What MB does | Workshop step |
| --- | --- | --- |
| T1021.006 (WinRM) | Remote PowerShell / WinRM lateral movement using cracked or stolen credentials | **Act 9**: `svc_sql` RemoteInteractive logon to `AADCONNECT01` |
| T1087.002 (Domain Account Discovery) | LDAP queries to map the directory | **Act 8**: `IdentityQueryEvents` SPN searches |
| T1087.004 (Cloud Account Discovery) | Microsoft Graph enumeration of users, groups, service principals, and applications | **Act 5**: `GraphAPIAuditEvents` and `MicrosoftGraphActivityLogs` calls |
| T1021.007 (Cloud Services) | Use synced high-privilege on-prem accounts to move *into* the cloud | The reverse of **Act 9** — worth discussing as the return path |

### Defense evasion

| Technique | What MB does | Where in workshop |
| --- | --- | --- |
| T1090.002 / T1665 (External Proxy, Hide Infrastructure) | Residential proxies — often in the *same ISP range as the victim* — so the source IP looks unremarkable | Source IP framing in **Acts 3–4**; the reason geo-velocity alone is a weak signal |
| T1564 (Hide Artifacts) | Tool renaming, in-memory execution, signed binaries (e.g. the signed RDP files of 2024) | **Act 7**: `rundll32 kiwi.dll` to hide Mimikatz |
| T1078.004 (Valid Cloud Accounts) | Heavy reliance on legitimate credentials and tokens to blend in | Throughout — every action runs under `victor.alvarez` |
| T1562.008 (Disable Cloud Logs) | Disabled Purview Audit on targeted mailboxes before stealing mail | **Act 12** discussion — what absence of evidence should mean to you |

> 🔎 **The benign twin.** Act 4 exists because of this section. MB's whole approach is to look normal, so the workshop deliberately includes a *legitimate* sign-in that superficially resembles the malicious one. If your detection logic can't separate the two, it will drown your SOC in false positives — or miss the real thing.

### Collection and exfiltration

| Technique | What MB does | Workshop step |
| --- | --- | --- |
| T1114.002 (Remote Email Collection) | Mailbox access via Graph API or Exchange Web Services, often keyword-driven | **Act 10**: Graph mailbox reads for `victor.alvarez` |
| T1530 (Data from Cloud Storage) | Pulling files from OneDrive / SharePoint via Graph | **Act 10**: `CloudStorageAggregatedEvents` and `OfficeActivity` |
| T1213.003 (Code Repositories) | Source code theft — the endgame of the Microsoft corporate breach | Context for why **Act 10** matters beyond mail |
| T1567 (Exfiltration Over Web Service) | Exfiltration through legitimate cloud services so traffic blends with normal usage | **Act 10**: destination analysis |

---

## 🧭 Why MB fits this scenario better than a commodity actor

If you've worked SOC for a while, you might wonder why the workshop doesn't model a financially motivated actor chasing ransomware or card data. The answer: MB's identity-first tradecraft is far more representative of what a defender in a hybrid Microsoft environment must actually be ready to investigate.

1. **Identity-first.** The compromise starts in the cloud — a phished device-code authorization (Act 2), then a risky sign-in (Act 3) — not on the endpoint.
2. **Persistent OAuth abuse.** Consent to a malicious "Sync Helper" app (Act 5) is a near-direct lift from the Microsoft and HPE breaches.
3. **Nothing looks like malware.** The opening move uses a genuine Microsoft URL and genuine MFA. You cannot signature your way out of it.
4. **Patient credential collection.** Multiple tools per credential-access family (Act 7) reflects a well-resourced actor probing which detections fire and which don't.
5. **Hybrid pivot.** Using on-prem credentials to reach Entra Connect (Act 9) targets the seam between on-prem and cloud identity — the highest-impact target in most hybrid estates.

You can run the same workshop queries against your real production telemetry and they'll catch many of MB's actual TTPs.

---

## 🔎 Detections worth operationalizing

These map directly to the queries in [`docs/instructor_answer_key.kql`](instructor_answer_key.kql):

- **Clicks on device-code authorization URLs**, then a successful sign-in shortly after. Microsoft's own published hunting query keys on `UrlChain has_any ("microsoft.com/devicelogin", "login.microsoftonline.com/common/oauth2/deviceauth")`. (Workshop: Act 2.)
- **Error code `50199` followed by success** in the same session — the pause while a user reads a code out of a phishing email. (Workshop: Act 2.)
- **Device registration close in time to anomalous token activity** — the tell for an actor converting a phished token into a Primary Refresh Token.
- **Risky sign-in correlated with same-IP cloud activity within one hour.** (Workshop: Act 3 `let suspiciousIp = ...` pattern.)
- **OAuth app consent for high-impact scopes** (`Mail.Read`, `Mail.ReadWrite`, `Files.Read.All`, `Directory.ReadWrite.All`, `full_access_as_app`). (Workshop: Act 5, `CloudAppEvents` filter for `OAuthAppConsentGranted`.)
- **Service-principal credential additions after suspicious consent**, especially followed by app-only Graph sign-ins. (Workshop: Act 5.)
- **New OAuth app creation followed by self-consent** within a short window.
- **LSASS process access by non-Windows-signed binaries.** (Workshop: Act 7 — `procdump`, `mimikatz`, `rundll32` loading non-standard DLLs.)
- **LDAP SPN enumeration followed by RC4 Kerberos service ticket requests.** (Workshop: Act 8.)
- **Service-account interactive logon to a Tier-0 system from a workstation.** (Workshop: Act 9 — `svc_*` accounts with `RemoteInteractive` logon type.)
- **Legacy auth or password-spray indicators**, especially against accounts without MFA.
- **Sign-ins from dormant accounts** that should have been deprovisioned.

---

## 🛡️ Controls that would have blunted the real breaches

- **Block device code flow** with Conditional Access wherever it isn't genuinely required — this is Microsoft's explicit recommendation, and it removes the workshop's entire opening act.
- **Phishing-resistant MFA** (FIDO2, passkeys) on every account, including non-production tenants and service accounts. Prefer managed identities or workload identity federation over shared secrets.
- **Restrict who can register devices** in Entra ID, to break the token → PRT escalation path.
- **Disable application-specific passwords**, which bypass MFA by design and were abused by MB in June 2025.
- **Inventory and lifecycle OAuth applications** — dormant apps with elevated permissions are exactly how the Microsoft breach escalated.
- **Conditional Access requiring compliant devices and trusted locations** for high-privilege scopes.
- **Disable legacy authentication protocols.**
- **Tier-0 isolation** for Entra Connect and AD FS; service accounts must not interactively log on from user workstations.
- **Revoke refresh tokens** (`revokeSignInSessions`) during response — a password reset alone does not evict a token-based intruder.

---

## 📚 Public sources for further reading

- MITRE ATT&CK group page (G0016): <https://attack.mitre.org/groups/G0016/>
- Microsoft Threat Intelligence response guidance for the 2024 incident: <https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/>
- Microsoft on device code phishing (Storm-2372, Feb 2025) — includes hunting queries: <https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/>
- Volexity on multiple Russian actors targeting device code authentication (Feb 2025): <https://www.volexity.com/blog/2025/02/13/multiple-russian-threat-actors-targeting-microsoft-device-code-authentication/>
- Amazon on the APT29 watering hole → device code campaign (Aug 2025): <https://aws.amazon.com/blogs/security/amazon-disrupts-watering-hole-campaign-by-russias-apt29/>
- Microsoft naming taxonomy explanation: <https://learn.microsoft.com/en-us/unified-secops-platform/microsoft-threat-actor-naming>
- CISA / partner agencies advisory on SVR cloud-access tradecraft (Feb 2024): <https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-057a>
- Check Point Research on 2025 European diplomacy campaigns: <https://research.checkpoint.com/>
- Google Threat Intelligence reporting on WINELOADER (2024): <https://cloud.google.com/blog/topics/threat-intelligence>

---

## ⚠️ Disclaimer

This profile is a synthesis of publicly available reporting, written to support workshop learning. Threat actor naming, attribution, and observed TTPs evolve continuously — MITRE last revised the APT29 group entry in January 2026, and the device-code tradecraft described here changed materially within 24 hours of first disclosure. Treat anything here older than a few months as background, not current operational intelligence. For that, consult Microsoft Defender Threat Intelligence (MDTI), your organization's threat intelligence platform, and the original sources linked above.
