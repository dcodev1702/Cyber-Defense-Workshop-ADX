# Cloud adversary TTP cyber-range integration

## Source and conversion

This catalog is derived from slides 16-39 of `Elisha - Threat Hunting Training v3.pptx`. The source presentation is local authoring material under the ignored `TTPs/` directory. Its TTP section was converted to Markdown with MarkItDown 0.1.7, then reviewed and normalized here so the durable repository artifact contains the training content rather than presentation layout noise.

The source section groups cloud adversary tradecraft into email, identity, and application categories. All 19 TTPs are implemented as cyber-range challenges with unique flags. Seven form the canonical Midnight Blizzard-inspired scenario arc; the other 12 are independent extension hunts in the same dataset. The implementation contract is [the TTP flag matrix](../metadata/ttp-flag-matrix.json), and the trainee workflow is [the TTP hunt query pack](ttp-hunt-queries.kql).

The catalog was reviewed against MITRE ATT&CK Enterprise v19 and current Microsoft Learn telemetry documentation on 2026-08-28. Slide labels describe teaching concepts, but several are not one-to-one ATT&CK techniques. The reviewed mappings below name the underlying adversary behavior rather than inventing technique IDs for analytic patterns or OAuth protocol flows.

## Exercise design rules

1. Seed and intermediate telemetry never contain a flag.
2. A trainee starts from a behavioral hypothesis, not a flag value.
3. Every challenge requires one or two pivots across different tables.
4. The final pivot projects an ordinary telemetry field containing `FLAG:{ThemedFlag}`.
5. The exact flag occurs once in the generated dataset and is not used as a search term in trainee KQL.
6. `scripts/Test-WorkshopTtpFlags.ps1` enforces the matrix, placement, uniqueness, and joined end-to-end result.

## Email-based adversary tradecraft

Email is a high-value target for surveillance and data access. These techniques abuse legitimate Exchange Online features and can persist without alerts or user awareness.

### Mailbox Email Forwarding (slide 18, scenario)

Attackers configure Victor Alvarez's mailbox to forward communications to `archive@threat-actor.diaries.cn`, maintaining persistent collection without continued authentication or malware. Hunt for forwarding-enabled mailboxes, external destinations, and changes without clear user intent.

Mapping and sources: [T1114.003 Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003/) and [Exchange Online mail flow rules](https://learn.microsoft.com/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules). Enhanced from a single configuration query into an app-attribution chain.

### Malicious Inbox Rules (slide 19, scenario)

Attackers create or modify inbox rules to move, delete, or redirect messages, hiding security notifications or intercepting sensitive mail. Hunt for destructive actions, security-related keywords, external forwarding, and unexplained long-lived rules.

Mapping and sources: [T1070.008 Clear Mailbox Data](https://attack.mitre.org/techniques/T1070/008/), [T1114.003 Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003/), and [Get-InboxRule](https://learn.microsoft.com/powershell/module/exchange/get-inboxrule). Expanded to distinguish the rule from the sessions that created and sustained it.

### Delegated Mailbox Permissions (slide 20)

Attackers grant another user or application mailbox rights so it can read, send, or manage mail without compromising the mailbox owner's credentials. Hunt for unexplained `FullAccess`, `SendAs`, and `SendOnBehalf` assignments and access without corresponding owner sign-ins.

Mapping and sources: [T1098.002 Additional Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002/) and [Add-MailboxPermission](https://learn.microsoft.com/powershell/module/exchange/add-mailboxpermission). Enhanced with delegate identity and background-session pivots.

## Identity-based adversary tradecraft

Identity is the primary cloud control plane. Valid credentials, tokens, permissions, and policy changes often appear successful or normal and may persist without alerts.

### Suspicious Sign-In Patterns (slide 22)

Attackers use valid credentials from unfamiliar locations, devices, or networks. Hunt successful sign-ins for behavioral deviations rather than relying only on failures or risk labels.

Mapping and sources: [T1078.004 Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) and [Microsoft Entra sign-in activity details](https://learn.microsoft.com/entra/identity/monitoring-health/concept-sign-in-log-activity-details). Corrected: "suspicious sign-in patterns" is an analytic description, not an ATT&CK technique.

### Token Abuse (slide 23, scenario)

Attackers steal or reuse authentication tokens to continue access without repeated sign-ins or MFA challenges, including after password changes. Hunt session continuity, unfamiliar clients, token types, and activity without expected authentication events.

Mapping and sources: [T1528 Steal Application Access Token](https://attack.mitre.org/techniques/T1528/), [T1550.001 Application Access Token](https://attack.mitre.org/techniques/T1550/001/), and [Microsoft identity platform access tokens](https://learn.microsoft.com/entra/identity-platform/access-tokens). Clarified token acquisition versus token use.

### OAuth / App Consent Abuse (slide 24, scenario)

Attackers abuse application registrations or granted permissions for persistent access to mail, files, and APIs without interactive sign-ins. Hunt broad permissions, unusual consent, service-principal activity, and access that survives user remediation.

Mapping and sources: [T1098.003 Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/), [T1550.001 Application Access Token](https://attack.mitre.org/techniques/T1550/001/), and [application permission audit logs](https://learn.microsoft.com/entra/identity/enterprise-apps/app-perms-audit-logs). Narrowed to app-only permission persistence so it remains distinct from deceptive user consent.

### Privileged Role Abuse (slide 25)

Attackers assign or activate privileged Entra roles to gain control over identities, applications, and security configuration. Hunt unexpected permanent assignments and PIM activations, especially for applications or service principals.

Mapping and sources: [T1098.003 Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/) and [security operations for privileged accounts](https://learn.microsoft.com/entra/architecture/security-operations-privileged-accounts). The implemented challenge models a permanent user role assignment; PIM activation remains a related hunt, not conflated evidence.

### Service Principal Privilege Escalation (slide 26)

Attackers elevate a service principal through directory roles or API permissions, gaining persistent non-interactive access without MFA. Hunt privilege changes and administrative actions performed by non-human identities.

Mapping and sources: [T1098.003 Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/) and [security operations for applications](https://learn.microsoft.com/entra/architecture/security-operations-applications). Separated app-role assignment from added credentials, which map to T1098.001.

### Conditional Access Policy Abuse (slide 27, scenario)

Attackers create, modify, or delete Conditional Access policies to weaken MFA, device compliance, or location enforcement while access still appears policy-compliant. Hunt broad exclusions and changes performed by unusual or non-interactive identities.

Mapping and sources: [T1556.009 Conditional Access Policies](https://attack.mitre.org/techniques/T1556/009/) and [Microsoft Entra Conditional Access](https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-policies). Corrected from the overly broad T1562 mapping to ATT&CK's exact sub-technique.

### Directory Reconnaissance (slide 28)

Attackers enumerate users, groups, roles, and privilege relationships to select targets and expansion paths. Hunt repeated directory lookups and discovery of privileged identities without administrative context.

Mapping and sources: [T1087.004 Cloud Account Discovery](https://attack.mitre.org/techniques/T1087/004/), [T1069.003 Cloud Groups](https://attack.mitre.org/techniques/T1069/003/), and [IdentityQueryEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-identityqueryevents-table). Corrected the source example: directory reads belong in identity-query and Graph telemetry, not generic directory-change audit logs.

### Session Persistence / Continuous Access (slide 29)

Attackers maintain sessions across services without repeated authentication. Hunt service activity that continues without new sign-ins or after remediation.

Mapping and sources: [T1550.001 Application Access Token](https://attack.mitre.org/techniques/T1550/001/) and [non-interactive sign-ins](https://learn.microsoft.com/entra/identity/monitoring-health/concept-noninteractive-sign-ins). Corrected: continuous access is a timeline pattern, not a standalone ATT&CK technique.

### Cross-Tenant / B2B Identity Abuse (slide 30)

Attackers abuse guest identities and cross-tenant trust for persistent access that appears to originate from a legitimate partner. Hunt durable external access, sensitive group or role membership, weak MFA, and unusual data volume.

Mapping and sources: [T1078.004 Valid Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/), [T1098.003 Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/), and [cross-tenant sign-in details](https://learn.microsoft.com/entra/identity/monitoring-health/concept-sign-in-log-activity-details). Enhanced to prove tenant crossing with home/resource tenant IDs.

### Identity to Infrastructure Access (slide 31)

Attackers use cloud management interfaces to control compute, storage, or network resources without logging on to the system. Hunt identity-driven resource creation, modification, and command execution, then pivot to endpoint impact.

Mapping and sources: [T1651 Cloud Administration Command](https://attack.mitre.org/techniques/T1651/) and [Azure VM Run Command](https://learn.microsoft.com/azure/virtual-machines/windows/run-command). Narrowed to Azure Run Command and expanded through the guest process created by the VM agent.

## Application-based adversary tradecraft

Applications act through delegated or application permissions and can operate without user interaction. Their activity often resembles normal automation and persists beyond password or MFA changes.

### API Access Abuse (slide 34, scenario)

Attackers use application permissions or service principals for automated access to mail, files, and directory data without interactive sign-ins. Hunt unusual volume, broad scopes, and API calls outside an application's expected behavior.

Mapping and sources: [T1059.009 Cloud API](https://attack.mitre.org/techniques/T1059/009/), [T1550.001 Application Access Token](https://attack.mitre.org/techniques/T1550/001/), and [Microsoft Graph authentication](https://learn.microsoft.com/graph/auth/auth-concepts). Clarified authorization material versus API execution.

### Application Impersonation / On-Behalf-Of Abuse (slide 35)

Attackers abuse OAuth On-Behalf-Of flow so a trusted application acts as a user without direct interaction. Hunt delegated access without recent user sign-ins and sensitive scopes used across multiple users.

Mapping and sources: [T1550.001 Application Access Token](https://attack.mitre.org/techniques/T1550/001/) and [OAuth 2.0 On-Behalf-Of flow](https://learn.microsoft.com/entra/identity-platform/v2-oauth2-on-behalf-of-flow). Corrected: OBO is a legitimate protocol flow, not an ATT&CK technique by itself.

### Cross-Tenant / B2B Application Impersonation (slide 36)

Attackers use external applications, service principals, or tenant trust to access internal data as an apparently legitimate partner. Hunt foreign issuers, broad delegated permissions, and cross-tenant access at scale.

Mapping and sources: [T1199 Trusted Relationship](https://attack.mitre.org/techniques/T1199/), [T1550.001 Application Access Token](https://attack.mitre.org/techniques/T1550/001/), and [cross-tenant access overview](https://learn.microsoft.com/entra/external-id/cross-tenant-access-overview). Enhanced with explicit application-owner and resource-tenant evidence.

### Illicit Consent Grants (slide 37)

Attackers deceive users or administrators into authorizing a malicious application. Hunt new high-risk scopes, consent without business justification, and non-interactive access immediately after consent.

Mapping and sources: [T1528 Steal Application Access Token](https://attack.mitre.org/techniques/T1528/), [T1550.001 Application Access Token](https://attack.mitre.org/techniques/T1550/001/), and [application permission audit logs](https://learn.microsoft.com/entra/identity/enterprise-apps/app-perms-audit-logs). Separated deceptive principal consent from app-only administrator permission grants.

### Cloud Resource Enumeration (slide 38)

Attackers list resources, identities, roles, and configuration through APIs or management interfaces before acting. Hunt bursts of `List` and `Get` operations across resource types and identities.

Mapping and sources: [T1580 Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580/), [T1059.009 Cloud API](https://attack.mitre.org/techniques/T1059/009/), and [AzureActivity](https://learn.microsoft.com/azure/azure-monitor/reference/tables/azureactivity). Expanded from isolated operations to a rapid multi-provider enumeration burst.

### Cloud Data Collection / Non-Mail (slide 39, scenario)

Attackers collect SharePoint, OneDrive, and storage data through legitimate APIs or application access. Hunt repeated file access, application-only retrieval, high volume, and behavior inconsistent with user or service norms.

Mapping and sources: [T1530 Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/), [T1213.002 SharePoint](https://attack.mitre.org/techniques/T1213/002/), and [download driveItem content](https://learn.microsoft.com/graph/api/driveitem-get-content). Clarified collection impact separately from generic API execution.

## Implemented TTP, table, and flag matrix

This is an instructor answer key. Do not distribute this section with the trainee query pack.

The 19 challenges span 11 unique tables. Each challenge uses two or three tables, which enforces one or two pivots without turning the exercise into an unbounded search. Every expected flag is globally unique and occurs once in its declared final table and column.

| Category | TTP | Required path | Flag location | Expected flag |
| --- | --- | --- | --- | --- |
| Email | Mailbox Email Forwarding | `OfficeActivity` -> `CloudAppEvents` -> `AADServicePrincipalSignInLogs` | `UserAgent` | `FLAG:{SilentMailRelay}` |
| Email | Malicious Inbox Rules | `OfficeActivity` -> `SigninLogs` -> `AADNonInteractiveUserSignInLogs` | `AuthenticationDetails` | `FLAG:{InboxShadowRule}` |
| Email | Delegated Mailbox Permissions | `OfficeActivity` -> `CloudAppEvents` -> `AADNonInteractiveUserSignInLogs` | `AuthenticationDetails` | `FLAG:{DelegateShadow}` |
| Identity | Suspicious Sign-In Patterns | `SigninLogs` -> `EntraIdSignInEvents` | `AuthenticationProcessingDetails` | `FLAG:{UnfamiliarAccess}` |
| Identity | Token Abuse | `SigninLogs` -> `AADNonInteractiveUserSignInLogs` | `AuthenticationDetails` | `FLAG:{GhostSession}` |
| Identity | OAuth / App Consent Abuse | `AuditLogs` -> `CloudAppEvents` -> `AADServicePrincipalSignInLogs` | `UserAgent` | `FLAG:{ConsentPhantom}` |
| Identity | Privileged Role Abuse | `AuditLogs` -> `SigninLogs` -> `AADNonInteractiveUserSignInLogs` | `AuthenticationDetails` | `FLAG:{RoleCrown}` |
| Identity | Service Principal Privilege Escalation | `AuditLogs` -> `AADServicePrincipalSignInLogs` -> `GraphAPIAuditEvents` | `RequestUri` | `FLAG:{AppAdminAscend}` |
| Identity | Conditional Access Policy Abuse | `AuditLogs` -> `CloudAppEvents` -> `SigninLogs` | `AuthenticationDetails` | `FLAG:{MfaExclusion}` |
| Identity | Directory Reconnaissance | `IdentityQueryEvents` -> `SigninLogs` -> `GraphAPIAuditEvents` | `RequestUri` | `FLAG:{DirectoryCartographer}` |
| Identity | Session Persistence / Continuous Access | `SigninLogs` -> `CloudAppEvents` -> `AADNonInteractiveUserSignInLogs` | `AuthenticationDetails` | `FLAG:{SessionAfterglow}` |
| Identity | Cross-Tenant / B2B Identity Abuse | `AuditLogs` -> `SigninLogs` -> `CloudAppEvents` | `RawEventData` | `FLAG:{GuestBackdoor}` |
| Identity | Identity to Infrastructure Access | `SigninLogs` -> `AzureActivity` -> `DeviceProcessEvents` | `ProcessCommandLine` | `FLAG:{ControlPlaneShell}` |
| Application | API Access Abuse | `AuditLogs` -> `AADServicePrincipalSignInLogs` -> `GraphAPIAuditEvents` | `RequestUri` | `FLAG:{GraphApiSweep}` |
| Application | Application Impersonation / OBO Abuse | `SigninLogs` -> `AADNonInteractiveUserSignInLogs` -> `GraphAPIAuditEvents` | `RequestUri` | `FLAG:{BorrowedIdentity}` |
| Application | Cross-Tenant / B2B Application Impersonation | `AADServicePrincipalSignInLogs` -> `GraphAPIAuditEvents` -> `CloudAppEvents` | `RawEventData` | `FLAG:{ForeignAppProxy}` |
| Application | Illicit Consent Grants | `AuditLogs` -> `CloudAppEvents` -> `AADNonInteractiveUserSignInLogs` | `AuthenticationDetails` | `FLAG:{ConsentLatch}` |
| Application | Cloud Resource Enumeration | `AzureActivity` -> `SigninLogs` -> `AADNonInteractiveUserSignInLogs` | `AuthenticationDetails` | `FLAG:{CloudMapBurst}` |
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
