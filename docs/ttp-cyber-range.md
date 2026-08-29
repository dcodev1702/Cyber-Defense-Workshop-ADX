# Cloud adversary TTP cyber-range integration

## Source and conversion

This catalog is derived from slides 16-39 of `Elisha - Threat Hunting Training v3.pptx`. The source presentation is local authoring material under the ignored `TTPs/` directory. Its TTP section was converted to Markdown with MarkItDown 0.1.7, then reviewed and normalized here so the durable repository artifact contains the training content rather than presentation layout noise.

The source section groups cloud adversary tradecraft into email, identity, and application categories. Six TTPs are nominated for cyber-range integration: two per category. The implementation contract is [the TTP flag matrix](../metadata/ttp-flag-matrix.json), and the trainee workflow is [the TTP hunt query pack](ttp-hunt-queries.kql).

## Exercise design rules

1. Seed and intermediate telemetry never contain a flag.
2. A trainee starts from a behavioral hypothesis, not a flag value.
3. Every challenge requires one or two pivots across different tables.
4. The final pivot projects an ordinary telemetry field containing `FLAG:{ThemedFlag}`.
5. The exact flag occurs once in the generated dataset and is not used as a search term in trainee KQL.
6. `scripts/Test-WorkshopTtpFlags.ps1` enforces the matrix, placement, uniqueness, and joined end-to-end result.

## Email-based adversary tradecraft

Email is a high-value target for surveillance and data access. These techniques abuse legitimate Exchange Online features and can persist without alerts or user awareness.

### Mailbox Email Forwarding (slide 18, selected)

Attackers configure Victor Alvarez's mailbox to forward communications to `archive@threat-actor.diaries.cn`, maintaining persistent collection without continued authentication or malware. Hunt for forwarding-enabled mailboxes, external destinations, and changes without clear user intent.

### Malicious Inbox Rules (slide 19, selected)

Attackers create or modify inbox rules to move, delete, or redirect messages, hiding security notifications or intercepting sensitive mail. Hunt for destructive actions, security-related keywords, external forwarding, and unexplained long-lived rules.

### Delegated Mailbox Permissions (slide 20)

Attackers grant another user or application mailbox rights so it can read, send, or manage mail without compromising the mailbox owner's credentials. Hunt for unexplained `FullAccess`, `SendAs`, and `SendOnBehalf` assignments and access without corresponding owner sign-ins.

## Identity-based adversary tradecraft

Identity is the primary cloud control plane. Valid credentials, tokens, permissions, and policy changes often appear successful or normal and may persist without alerts.

### Suspicious Sign-In Patterns (slide 22)

Attackers use valid credentials from unfamiliar locations, devices, or networks. Hunt successful sign-ins for behavioral deviations rather than relying only on failures or risk labels.

### Token Abuse (slide 23, selected)

Attackers steal or reuse authentication tokens to continue access without repeated sign-ins or MFA challenges, including after password changes. Hunt session continuity, unfamiliar clients, token types, and activity without expected authentication events.

### OAuth / App Consent Abuse (slide 24)

Attackers abuse application registrations or granted permissions for persistent access to mail, files, and APIs without interactive sign-ins. Hunt broad permissions, unusual consent, service-principal activity, and access that survives user remediation.

### Privileged Role Abuse (slide 25)

Attackers assign or activate privileged Entra roles to gain control over identities, applications, and security configuration. Hunt unexpected permanent assignments and PIM activations, especially for applications or service principals.

### Service Principal Privilege Escalation (slide 26)

Attackers elevate a service principal through directory roles or API permissions, gaining persistent non-interactive access without MFA. Hunt privilege changes and administrative actions performed by non-human identities.

### Conditional Access Policy Abuse (slide 27, selected)

Attackers create, modify, or delete Conditional Access policies to weaken MFA, device compliance, or location enforcement while access still appears policy-compliant. Hunt broad exclusions and changes performed by unusual or non-interactive identities.

### Directory Reconnaissance (slide 28)

Attackers enumerate users, groups, roles, and privilege relationships to select targets and expansion paths. Hunt repeated directory lookups and discovery of privileged identities without administrative context.

### Session Persistence / Continuous Access (slide 29)

Attackers maintain sessions across services without repeated authentication. Hunt service activity that continues without new sign-ins or after remediation.

### Cross-Tenant / B2B Identity Abuse (slide 30)

Attackers abuse guest identities and cross-tenant trust for persistent access that appears to originate from a legitimate partner. Hunt durable external access, sensitive group or role membership, weak MFA, and unusual data volume.

### Identity to Infrastructure Access (slide 31)

Attackers use cloud management interfaces to control compute, storage, or network resources without logging on to the system. Hunt identity-driven resource creation, modification, and command execution, then pivot to endpoint impact.

## Application-based adversary tradecraft

Applications act through delegated or application permissions and can operate without user interaction. Their activity often resembles normal automation and persists beyond password or MFA changes.

### API Access Abuse (slide 34, selected)

Attackers use application permissions or service principals for automated access to mail, files, and directory data without interactive sign-ins. Hunt unusual volume, broad scopes, and API calls outside an application's expected behavior.

### Application Impersonation / On-Behalf-Of Abuse (slide 35)

Attackers abuse OAuth On-Behalf-Of flow so a trusted application acts as a user without direct interaction. Hunt delegated access without recent user sign-ins and sensitive scopes used across multiple users.

### Cross-Tenant / B2B Application Impersonation (slide 36)

Attackers use external applications, service principals, or tenant trust to access internal data as an apparently legitimate partner. Hunt foreign issuers, broad delegated permissions, and cross-tenant access at scale.

### Illicit Consent Grants (slide 37)

Attackers deceive users or administrators into authorizing a malicious application. Hunt new high-risk scopes, consent without business justification, and non-interactive access immediately after consent.

### Cloud Resource Enumeration (slide 38)

Attackers list resources, identities, roles, and configuration through APIs or management interfaces before acting. Hunt bursts of `List` and `Get` operations across resource types and identities.

### Cloud Data Collection / Non-Mail (slide 39, selected)

Attackers collect SharePoint, OneDrive, and storage data through legitimate APIs or application access. Hunt repeated file access, application-only retrieval, high volume, and behavior inconsistent with user or service norms.

## Implemented TTP, table, and flag matrix

This is an instructor answer key. Do not distribute this section with the trainee query pack.

The six challenges span seven unique tables and seventeen total table touches. Each challenge uses two or three tables, which enforces one or two pivots without turning the exercise into an unbounded search.

| Category | TTP | Required path | Flag location | Expected flag |
| --- | --- | --- | --- | --- |
| Email | Mailbox Email Forwarding | `OfficeActivity` -> `CloudAppEvents` -> `AADServicePrincipalSignInLogs` | `UserAgent` | `FLAG:{SilentMailRelay}` |
| Email | Malicious Inbox Rules | `OfficeActivity` -> `SigninLogs` -> `AADNonInteractiveUserSignInLogs` | `AuthenticationDetails` | `FLAG:{InboxShadowRule}` |
| Identity | Token Abuse | `SigninLogs` -> `AADNonInteractiveUserSignInLogs` | `AuthenticationDetails` | `FLAG:{GhostSession}` |
| Identity | Conditional Access Policy Abuse | `AuditLogs` -> `CloudAppEvents` -> `SigninLogs` | `AuthenticationDetails` | `FLAG:{MfaExclusion}` |
| Application | API Access Abuse | `AuditLogs` -> `AADServicePrincipalSignInLogs` -> `GraphAPIAuditEvents` | `RequestUri` | `FLAG:{GraphApiSweep}` |
| Application | Cloud Data Collection / Non-Mail | `CloudAppEvents` -> `GraphAPIAuditEvents` -> `OfficeActivity` | `SourceFileName` | `FLAG:{SharePointHarvest}` |

## Programmatic validation

Validate the matrix and generated telemetry:

```powershell
.\scripts\Test-WorkshopTtpFlags.ps1 -DataDirectory .\data\generated
```

After importing the generated payload, execute every multi-table validation query against Kusto:

```powershell
.\scripts\Test-WorkshopTtpFlags.ps1 `
  -ClusterUri http://127.0.0.1:8080 `
  -Database CyberDefendStudentSnapshot
```

The Kusto mode is intentionally an instructor/CI control. Trainees use the sequential queries and manually carry pivot values; they are never given the joined validation queries or flag literals.

## Operational recommendations

- Treat flags as challenge secrets: keep the instructor matrix out of trainee handouts and screenshots.
- Version challenge IDs separately from flag text so flags can rotate without rewriting lesson references.
- Record completion outside Kusto if scoring is required; the read-only gateway should remain read-only.
- Add per-team flag variants only if the generator receives a protected run seed. Static shared flags are appropriate for the current shared dataset but cannot prove which trainee found them.
- Reset or regenerate the dataset between cohorts if answer sharing matters.
- Keep a clean benign twin near each behavior so trainees must reason about intent rather than match a single operation name.
- Plaintext flags meet the workshop requirement but are not an anti-cheat control: a trainee who searches every table for `FLAG:` can bypass the intended pivots. Do not advertise the marker format, and use a separate scoring service or per-team generated flags if completion integrity matters.
