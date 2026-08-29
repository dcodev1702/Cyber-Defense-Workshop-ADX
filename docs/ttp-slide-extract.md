# MarkItDown extract: cloud adversary TTPs

Generated from the local source deck by scripts/Convert-TtpDeckToMarkdown.ps1.
This artifact contains slides 16-39. See docs/ttp-cyber-range.md for the reviewed
catalog, selected integrations, telemetry paths, flags, and validation workflow.
<!-- Slide number: 16 -->

# Hunting Cloud-Specific Adversary Tradecraft (TTPs)

<!-- Slide number: 17 -->

Email-Based Adversary Tradecraft

How attackers abuse Exchange Online for persistence, access, and evasion

Email is a high-value target for surveillance and data access
Many techniques rely on legitimate features, not malware
These techniques often persist without alerts or user awareness

<!-- Slide number: 18 -->

Attackers configure mailbox email forwarding to maintain persistent access to a user’s communications without requiring continued authentication or malware.

This technique abuses legitimate Exchange Online functionality and is commonly used for long-term surveillance and data collection.

TTP: Mailbox Email Forwarding

Mailbox forwarding is often persistence, not noise.
 Absence of alerts does not imply absence of compromise.

Why This Matters
Start Here
Provides persistent visibility into sensitive communications over time
Often invisible to end users
May exist without alerts or obvious indicators
Frequently used after credential compromise or OAuth abuse
Microsoft Defender for Office 365 (MDO)
Focus on mailbox configuration and mail flow rather than message content alone.

Pivot Next

What to Hunt
Microsoft Entra ID
 Pivot on the affected user account
 → validate sign-ins, MFA activity, token usage, and session behavior
Defender for Cloud Apps (MDA)
 Determine whether mailbox access is occurring via OAuth apps or service principals

Mailboxes with forwarding enabled
External forwarding destinations
Forwarding configured without clear user intent
Forwarding changes that persist over time
Example Query

OfficeActivity
| where Operation in ("Set-Mailbox", "New-InboxRule", "UpdateInboxRules")
| where Parameters has_any ("ForwardingSmtpAddress", "RedirectTo", "ForwardTo")
Use this to identify when forwarding was configured and by whom.

*Unified Audit Log (Office 365 Activity Logs)

### Notes:
“Now we’re moving from theory into real cloud abuse patterns.”
“Mailbox forwarding is one of the most common — and most overlooked — persistence techniques in Microsoft 365.”
Pause here.
“This is not malware. This is configuration abuse.”

 Explain the TTP Clearly
“After gaining credentials — whether through phishing, token theft, or OAuth abuse — attackers often configure mailbox forwarding.”
Why?
They don’t need to log in again.
They don’t need malware.
They don’t trigger sign-in alerts.
They silently receive copies of all communications.
“This is long-term surveillance.”

Why This Matters (Talk Track Expansion)
Walk through these with added depth:
• Provides persistent visibility
“Every email — internal, legal, financial, executive — can be siphoned.”
• Often invisible to end users
“Most users never check their forwarding settings.”
• May exist without alerts
“There may be no high-severity alert tied to this.”
This is where you reinforce your core message:
“No alert does not mean no attacker.”
• Frequently used after credential compromise or OAuth abuse
“This is a post-compromise move — not initial access.”

 What to Hunt (Add Analyst Context)
Don’t just read the bullets — expand them:
Mailboxes with forwarding enabled
“Baseline your environment. Who normally has forwarding enabled?”
External forwarding destinations
“Forwarding to Gmail? Proton? Suspicious domains?”
Forwarding without user intent
“Was there a helpdesk ticket? Business justification?”
Changes that persist over time
“Temporary forwarding during PTO is normal. Long-term external forwarding is not.”

Start Here: MDO
“Notice this says focus on configuration and mail flow — not message content.”
That’s key.
“You’re not hunting phishing emails here.”
“You’re hunting configuration abuse.”

Pivot Next: Identity
Microsoft Entra ID
“Was the account compromised?”
Check:
Suspicious sign-ins
MFA satisfaction patterns
Impossible travel
Token reuse
Defender for Cloud Apps (MDA)
“Was this configured via OAuth or an app?”
Check:
App-based mailbox access
Consent grants
Service principal behavior

Example Query- How to Explain It
When showing the query:
“Notice we’re not searching email content.”
“We’re looking at configuration change operations.”
Break it down:
Set-Mailbox
New-InboxRule
UpdateInboxRules
Parameters containing:
ForwardingSmtpAddress
RedirectTo
ForwardTo
“This tells us who changed forwarding, when, and how.”
That is investigative gold.

 The Callout Box Point directly at this:
“Mailbox forwarding is often persistence, not noise.”
“This is the kind of activity that lives quietly for months.”
“Attackers love techniques that don’t generate noise.”
This reinforces your earlier “Alerts Are Optional” slide — beautifully consistent messaging.

Strong Closing Line for This Slide
You could end with:
“If you only look for malware, you will miss this.If you hunt configuration abuse, you will find it.”

<!-- Slide number: 19 -->

Attackers create or modify inbox rules to automatically move, delete, or redirect emails in order to hide security notifications, intercept sensitive messages, or enable long-term access while avoiding user awareness.

This technique abuses legitimate Exchange Online rule functionality and is commonly used to evade detection after initial access.

TTP: Malicious Inbox Rules
Inbox rules are often used to hide activity, not manage email.
 If alerts disappear, assume intent.

Why This Matters
Start Here
Allows attackers to hide evidence of compromise
Prevents users from seeing security alerts or warning emails
Enables selective surveillance of high-value communications
Often persists without generating alerts

Microsoft Defender for Office 365 (MDO)
Focus on mailbox rule configuration and message handling behavior rather than individual email content.

Pivot Next

What to Hunt
Microsoft Entra ID
 Pivot on the affected user account
 → validate sign-ins, MFA activity, token usage, and session behavior
Defender for Cloud Apps (MDA)
 Determine whether inbox rules were created via OAuth apps or automated access

Inbox rules that delete or move messages automatically
Rules targeting security-related keywords (e.g., “alert”, “password”, “MFA”)
Rules forwarding messages to external recipients
Rules created or modified without clear user intent
Rules that persist over time

Example Query

Use this to identify rule creation, modification, and the actions performed by those rules.
OfficeActivity
| where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| where Parameters has_any ("DeleteMessage", "MoveToFolder", "ForwardTo", "RedirectTo")

*Unified Audit Log (Office 365 Activity Logs)

### Notes:
Instructor Notes
Explain this as hiding evidence + selective surveillance
Reinforce that attackers don’t just collect—they control visibility
Key Point to Say:“This isn’t just about access—it’s about controlling what the user sees.”
Prompt Question:“What emails would an attacker want to hide?”

<!-- Slide number: 20 -->

Attackers grant delegated access to a mailbox, allowing another user or application to read, send, or manage email without compromising the mailbox owner’s credentials.

This technique abuses legitimate Exchange Online permission models and is commonly used for stealthy, long-term access to sensitive communications.

TTP: Delegated Mailbox Permissions

Delegated access shifts who is acting, not what is accessed.
 Always ask “Who is accessing this mailbox?”

Why This Matters
Start Here
Enables persistent mailbox access without repeated authentication
Access occurs under a different identity than the mailbox owner
Often invisible to the affected user
May bypass traditional mailbox or sign-in alerts

Microsoft Defender for Office 365 (MDO)
Focus on mailbox access patterns and message activity that does not align with the mailbox owner’s identity.

Pivot Next

What to Hunt
Microsoft Entra ID
 Pivot on the affected user account
 → validate sign-ins, MFA activity, token usage, and session behavior
Defender for Cloud Apps (MDA)
Determine whether mailbox access is occurring via OAuth apps or service principals rather than interactive users

Mailboxes with delegated permissions assigned
Delegates with FullAccess, SendAs, or SendOnBehalf rights
Delegation granted without clear business justification
Mailbox access occurring without corresponding user sign-ins
Delegation that persists over time

Example Query

Use this to identify when delegated permissions were added and who performed the action.
OfficeActivity
| where Operation in ("Add-MailboxPermission", "Set-MailboxPermission")
| where Parameters has_any ("FullAccess", "SendAs", "SendOnBehalf")

*Unified Audit Log (Office 365 Activity Logs)

### Notes:
Instructor Notes
This is often missed because activity happens under a different identity
Reinforce that access does not equal ownership
Key Point to Say:“Just because the mailbox belongs to one user doesn’t mean they’re the one accessing it.”
Prompt Question:“How would you detect access that doesn’t belong to the owner?”

<!-- Slide number: 21 -->

Identity-Based Adversary Tradecraft

How attackers abuse identity, authentication, and authorization to gain access and persist in cloud environments

Identity is the primary control plane in cloud-first environments
Many identity attacks rely on valid credentials, tokens, or permissions, not malware
These techniques often appear as successful or “normal” activity and persist without alerts

<!-- Slide number: 22 -->

Attackers leverage valid credentials to authenticate as legitimate users, often from unfamiliar locations, devices, or networks.  These sign-ins may succeed without triggering alerts and are frequently the first observable indicator of identity compromise.

This technique abuses normal authentication workflows and is commonly used after phishing, credential theft, or token acquisition.

TTP: Suspicious Sign-In Patterns

Identity compromise is about who is acting, not just whether authentication failed.
 A successful sign-in can be more dangerous than a blocked one.

Why This Matters
Start Here
Microsoft Entra ID
Focus on successful authentication events, not just failures.
Look for behavioral deviations rather than relying on risk labels alone.
Valid credentials bypass many traditional security controls
Successful sign-ins may appear “normal” without deeper context
Identity compromise enables access to email, apps, data, and devices
Often precedes persistence via tokens, roles, or OAuth abuse

Pivot Next

What to Hunt
Microsoft Defender for Cloud Apps (MDA)
Determine whether activity continues via OAuth apps, tokens, or automated access without additional sign-ins.
Microsoft Defender for Endpoint (MDE)
Validate whether the user’s identity is now associated with new or suspicious device activity.

Successful sign-ins from unusual geographies or IP ranges
New devices or browsers not previously associated with the user
Sign-ins without expected MFA challenges or enforcement
Authentication activity outside normal user behavior patterns
Identity activity that precedes non-user (app or service) access

Example Query
SigninLogs
| where ResultType == 0
| summarize
    Locations = make_set(Location),
    IPs = make_set(IPAddress),
    Devices = make_set(DeviceDetail.deviceId)
    by UserPrincipalName

Use this to identify users with successful sign-ins exhibiting behavioral deviations across location, IP, or device context

*Unified Identity Log (Microsoft Entra ID)

### Notes:
Instructor Notes
Focus on behavior, not alerts
Make it clear: successful sign-ins are often the first real indicator
Key Point to Say:“Most real compromises start with a successful login—not a failed one.”
Prompt Question:“What makes a ‘normal’ login abnormal?”

<!-- Slide number: 23 -->

Attackers steal or reuse authentication tokens to maintain access without repeated sign-ins or MFA challenges.  This allows continued access even after passwords are changed and often bypasses traditional authentication monitoring.

Token abuse commonly follows phishing, AiTM attacks, malicious OAuth apps, or compromised devices and is one of the hardest identity TTPs to detect because activity often appears legitimate.

TTP: Token Abuse

Token abuse is about session continuity, not credentials.
 If access survives password resets, assume token compromise.

Why This Matters
Start Here
Microsoft Entra ID
Focus on successful authentication events, not failures.
Look for session continuity and MFA satisfaction, not just credential use.

Tokens allow access without reauthentication
MFA can be bypassed once a token is issued
Activity often looks like normal user behavior
Password resets alone may not evict the attacker
Common persistence mechanism in modern cloud attacks

Pivot Next

What to Hunt
Microsoft Defender for Cloud Apps (MDA)
Determine whether access continues via OAuth apps, tokens, or automated sessions without additional sign-ins.
Microsoft Defender for Endpoint (MDE)
Validate whether token use is associated with new, unmanaged, or suspicious device activity.

Successful sign-ins without expected MFA prompts
Long-lived or reused sessions across locations or devices
Sign-ins using unfamiliar client apps or authentication methods
Activity continuing after password resets or risk remediation
Authentication patterns inconsistent with user behavior history

Example Query

SigninLogs
| where ResultType == 0
| summarize
    Locations = make_set(Location),
    ClientApps = make_set(ClientAppUsed),
    AuthMethods = make_set(AuthenticationDetails.authenticationMethod),
    MFARequired = make_set(AuthenticationDetails.authenticationRequirement)
  by UserPrincipalName

Use this to identify users with successful sign-ins exhibiting inconsistent authentication methods, client apps, or session behavior over time.

*Unified Identity Log (Microsoft Entra ID)

### Notes:
Instructor Notes
This is one of the hardest concepts for new analysts
Reinforce: no new login ≠ no attacker
Key Point to Say:“Once a token is issued, the attacker doesn’t need to log in again.”
Prompt Question:“What would you see if someone was active but never logging in?”

<!-- Slide number: 24 -->

Attackers abuse OAuth app registrations or user-granted permissions to obtain persistent access to cloud resources without requiring interactive sign-ins. This enables long-term access to mail, files, and APIs while bypassing MFA and traditional authentication monitoring.

OAuth abuse often follows phishing or token theft and is especially dangerous because access is delegated to applications that appear legitimate.

TTP: OAuth / App Consent Abuse

OAuth abuse shifts access from who logged in to what is allowed to act.
 If an app has permission, it doesn’t need to authenticate like a user.

Why This Matters
Start Here
Microsoft Entra ID
Focus on application activity and permission use, not user sign-ins.
Look for apps accessing data without user interaction.

OAuth access persists independently of user credentials
MFA and password resets do not revoke app permissions
Activity appears as legitimate application behavior
Enables silent, scalable access across users or tenants
Frequently overlooked during identity investigations

Pivot Next

What to Hunt
Microsoft Entra ID
Validate app registrations, consent grants, and permission scope.  Review who granted consent and when.
Microsoft Defender for Office 365 (MDO)
Determine whether OAuth abuse originated from phishing or consent-based social engineering.

New or modified app registrations with broad permissions
User-consented apps accessing mail, files, or directory data
Apps granted permissions inconsistent with business need
Activity performed by service principals rather than users
Access continuing without corresponding interactive sign-ins

Example Query

Use this to identify new or modified application permissions and consent activity that may enable persistent, non-interactive access.
AuditLogs
| where OperationName in ("Add service principal", "Consent to new app", "Add delegated permission grant")
| project TimeGenerated, InitiatedBy, TargetResources, OperationName, ResultReason

*Entra ID Audit Logs

### Notes:
Instructor Notes
Emphasize user-approved access becomes attacker access
Many analysts assume apps are safe—challenge that
Key Point to Say:“The user may have granted access themselves—that’s what makes this dangerous.”
Prompt Question:“What happens if the app is trusted, but shouldn’t be?”

<!-- Slide number: 25 -->

Attackers assign or activate privileged Entra ID roles to elevate access, bypass security controls, and maintain administrative persistence. This enables broad control over identities, applications, and security configurations without deploying malware.

Privileged role abuse often follows credential compromise, OAuth abuse, or token theft and represents a critical transition from access to control.

TTP: Privileged Role Abuse

Privilege abuse is about what someone can now do, not how they logged in.
 Always ask: “What changed after this role was granted?”

Why This Matters
Start Here
Microsoft Entra ID
Focus on role assignments, PIM activations, and role usage, not just sign-ins.
Look for elevation events that don’t align with normal admin behavior.

Privileged roles grant broad access across the tenant
Role assignments often persist longer than tokens or sessions
Abuse may occur via PIM activation, not permanent assignment
Activity can appear legitimate if role use aligns with permissions
Enables follow-on actions like disabling security controls or creating backdoors

Pivot Next

What to Hunt
Microsoft Defender for Cloud Apps (MDA)
Determine whether privileged actions are being executed via OAuth apps, tokens, or non-interactive access.
Microsoft Defender for Endpoint (MDE)
Validate whether newly privileged identities are associated with suspicious or unmanaged devices.

New or modified privileged role assignments
PIM activations outside expected timeframes or justification
Roles assigned without corresponding administrative sign-ins
Privileged roles granted to service principals or apps
Repeated or persistent elevation across multiple users

Example Query

AuditLogs
| where OperationName in (
    "Add member to role",
    "Add eligible member to role",
    "Activate eligible role"
)
| project TimeGenerated, InitiatedBy, TargetResources, OperationName

Use this to identify new or activated privileged roles, who granted or activated them, and whether elevation aligns with expected administrative activity.

*Entra ID Audit Logs

### Notes:
Instructor Notes
This is the shift from access → control
Highlight impact over detection
Key Point to Say:“This is where the attacker stops exploring and starts controlling.”
Prompt Question:“What could someone do if they had this role?”

<!-- Slide number: 26 -->

Attackers abuse service principals by granting elevated permissions or directory roles, enabling persistent, non-interactive access to cloud resources. Unlike user accounts, service principals do not require MFA or interactive sign-ins, making this technique stealthy and difficult to detect.

Service principal privilege escalation often follows OAuth consent abuse or token theft and allows attackers to operate indefinitely under the guise of legitimate application activity.
TTP: Service Principal Privilege Escalation

Service principals don’t log in, they act.
 If an app gains privilege, assume persistence until proven otherwise.

Why This Matters
Start Here
Microsoft Entra ID
Focus on service principals, role assignments, and API permissions, not user activity.
Look for privilege changes that shift what an application is allowed to do.
Service principals operate without user sign-ins or MFA
Permissions persist independently of user credentials
Activity often appears as normal application behavior
Privileged service principals can modify identities, apps, and security controls
Commonly overlooked during identity-focused investigations

Pivot Next

What to Hunt
Microsoft Defender for Cloud Apps (MDA)
Determine whether service principals are accessing mail, files, or directory data at scale or outside expected usage patterns.
Microsoft Defender for Endpoint (MDE)
Assess whether service principal abuse originated from compromised devices, automation tooling, or developer environments.

Service principals granted directory roles (e.g., Global Admin, App Admin)
Apps with newly assigned high-risk API permissions
Privileges granted without corresponding app registration changes
Service principals performing administrative actions
Persistent or expanding permissions over time
Example Query

AuditLogs
| where OperationName in (
    "Add service principal to role",
    "Add member to role",
    "Add delegated permission grant",
    "Add app role assignment"
)
| project TimeGenerated, InitiatedBy, TargetResources, OperationName

Use this to identify service principals that were granted elevated permissions or directory roles, who authorized the change, and when application privilege boundaries shifted.

*Entra ID Audit Logs

### Notes:
Instructor Notes
Reinforce: this is non-user activity
Many new analysts ignore apps entirely
Key Point to Say:“This is access that doesn’t belong to a person.”
Prompt Question:“How would you detect activity that isn’t tied to a user?”

Service Principal (Application Identity)

What is it?
An identity for an application (not a person)
User = human identity
Service Principal = application identity

Why it exists
Applications need to:
Access APIs
Read/write data
Automate tasks
Instead of using human accounts → they use a service principal

How it works
App Registration (blueprint)⬇️Service Principal (active identity in tenant)

What it can do
Just like a user, it can:
Authenticate
Be assigned roles/permissions
Access resources (Key Vault, Storage, Graph, etc.)

How it authenticates
Client Secret (like a password)
Certificate (more secure)
Managed Identity (best practice in Azure)

Security Risk ⚠️
No MFA
Often over-permissioned
Long-lived credentials
Harder to detect
➡️ Frequently abused for:
Persistence
Privilege escalation
Stealthy access

Simple Analogy
A service principal = a robot with a badge
If compromised → attacker gets quiet, persistent access

Key Takeaway
Service principals are powerful non-human identities and a major target in cloud attacks.

<!-- Slide number: 27 -->

Attackers modify or create Conditional Access (CA) policies to weaken or bypass enforcement of security controls such as MFA, device compliance, or location restrictions. This allows continued access while activity still appears policy-compliant.

Conditional Access abuse often follows elevated identity compromise and is especially dangerous because it silently disables defensive controls across the environment.

TTP: Conditional Access Policy Abuse

Conditional Access defines what is allowed.
 If enforcement changes, assume intent until validated.

Why This Matters
Start Here
Microsoft Entra ID
Focus on Conditional Access policy creation, modification, and exclusions.
Review who changed enforcement, not just who is signing in.
Conditional Access is a primary enforcement layer for Zero Trust
Small policy changes can have organization-wide impact
Exclusions are often trusted and rarely reviewed
MFA enforcement can be bypassed without alerting
Policy abuse enables persistence without malware or tokens

Pivot Next

What to Hunt
Microsoft Defender for Cloud Apps (MDA)
Determine whether risky access patterns increase after policy changes (OAuth apps, legacy auth, non-interactive access).
Microsoft Defender for Endpoint (MDE)
Assess whether CA policy changes align with suspicious device activity or administrative actions from unmanaged endpoints.

New or modified Conditional Access policies
Policies with broad user, app, or location exclusions
Changes disabling MFA or device compliance requirements
Policies applied to “All Users” or “All Cloud Apps”
CA changes performed by non-interactive identities (apps/SPs)
Example Query

AuditLogs
| where OperationName in (
    "Add conditional access policy",
    "Update conditional access policy",
    "Delete conditional access policy"
)
| project TimeGenerated, InitiatedBy, TargetResources, OperationName

Use this to when CA policies were created, modified, or removed, who initiated the change, and which enforcement controls were altered or excluded

*Entra ID Audit Logs

### Notes:
Instructor Notes
Explain this as changing the rules of the environment
Tie to IA/compliance folks directly
Key Point to Say:“The attacker isn’t bypassing security—they’re changing how it works.”
Prompt Question:“What happens if MFA is still ‘enabled’ but no longer enforced?”

<!-- Slide number: 28 -->

Attackers query directory services to identify users, roles, group memberships, and privilege relationships within the environment.

This activity enables targeting, privilege escalation, and access expansion.

TTP: Directory Reconnaissance

Before escalation comes discovery.
 Understanding identity structure is key to expanding access.

Why This Matters
Start Here
Microsoft Entra ID / Defender for Identity
Focus on directory queries and identity lookup behavior.
Reveals privileged accounts and access paths
Supports targeted escalation and persistence
Often blends with legitimate administrative activity
Enables mapping of identity relationships
Typically low-noise and difficult to detect

Pivot Next

What to Hunt
AuditLogs
Identify role or permission changes following discovery
SigninLogs
Validate identity context and authentication behavior

Enumeration of users, groups, or roles
Queries targeting privileged identities
Repeated directory lookup activity
Access to identity metadata at scale
Discovery without clear administrative context

Example Query

Use this to identify identities performing directory reconnaissance or mapping privilege relationships.
AuditLogs
| where OperationName contains "List"
 or OperationName contains "Get"
| summarize count() by InitiatedBy, OperationName

### Notes:
Instructor Notes
Tie this to finding privilege paths
Not just “looking at users”
Key Point to Say:“They’re not just looking at users—they’re looking for power.”
Prompt Question:“Who would you look for if you wanted more access?”

<!-- Slide number: 29 -->

TTP: Session Persistence / Continuous Access
Attackers maintain access through persistent sessions that continue across services without requiring repeated authentication.

This allows ongoing activity that appears legitimate and is not tied to new sign-in events.

No new sign-in does not mean no activity.
 Session-based access can persist silently.

Why This Matters
Start Here
SigninLogs + CloudAppEvents correlation
Identify the last successful sign-in for a user, then compare it to activity across services.
Look for:
Activity occurring without a new sign-in
Access continuing across time or services
Mismatch between authentication timing and activity

Activity may continue without new authentication logs
MFA is not repeatedly enforced after initial access
Access persists across multiple services
Behavior appears consistent with normal usage
Often overlooked when focusing only on sign-in events

What to Hunt
Activity across services without new sign-ins
Long-lived sessions across timeframes
Consistent access patterns without authentication events
Activity continuing after remediation actions
Service-to-service access tied to prior authentication

Pivot Next
Microsoft Defender for Cloud Apps (MDA)
Identify continued access patterns and session usage
AuditLogs
Determine persistence mechanisms enabling access

Example Query

Use this to identify continued access patterns that are not tied to new authentication events.
SigninLogs
| where ResultType == 0
| project UserPrincipalName, TimeGenerated

### Notes:
Instructor Notes
Reinforce timeline thinking
This is where correlation matters most
Key Point to Say:“No new login doesn’t mean no activity.”
Prompt Question:“What should happen before activity—and what if it doesn’t?”

<!-- Slide number: 30 -->

Attackers abuse Microsoft Entra B2B and cross-tenant trust relationships to gain persistent access through guest accounts. By leveraging external identities, attackers can bypass internal monitoring assumptions and maintain access without compromising a native user account.

Cross-tenant abuse is especially dangerous because activity often appears legitimate, originates from trusted partners, and persists independently of internal password resets or MFA enforcement.

TTP: Cross-Tenant / B2B Identity Abuse

External identities don’t behave like insiders.
 If a guest has long-term access, assume intent until validated.

Why This Matters
Start Here
Microsoft Entra ID
Focus on guest users, external identities, and cross-tenant access settings.
 Review who granted access, what permissions were assigned, and how external users authenticate.
Guest and external users are often trusted by default
B2B access frequently bypasses internal security baselines
Identity monitoring often focuses on internal users only
External identities can persist long after initial compromise
Commonly overlooked during incident response and cleanup

Pivot Next

What to Hunt
Microsoft Defender for Cloud Apps (MDA)
Determine whether guest users are accessing data at unusual volume, frequency, or scope compared to typical external collaboration patterns.
Microsoft Defender for Endpoint (MDE)
Assess whether guest identity access correlates with suspicious device activity, unmanaged endpoints, or abnormal session behavior.

Guest users with access to sensitive apps or data
External users assigned directory roles or group memberships
Guest accounts accessing mail, SharePoint, or Teams at scale
External users authenticating without strong MFA enforcement
Cross-tenant access that persists over time without clear business need
Example Query

Use this to identify external or guest identities that were invited, granted access, or added to groups, and to determine who authorized cross-tenant access and whether permissions align with business intent.
AuditLogs
| where OperationName in ("Add member to group", "Add user", "Invite external user")
| where TargetResources has "Guest"
| project TimeGenerated, InitiatedBy, TargetResources, OperationName

*Entra ID Audit Logs

<!-- Slide number: 31 -->

Attackers leverage identity-based access to interact with compute and infrastructure resources through cloud management interfaces.

This enables execution, persistence, or expansion without traditional malware delivery.

TTP: Identity to Infrastructure Access

Attackers don’t need to log into a system to control it.
 They can act on the system through the cloud platform itself.

Why This Matters
Start Here
Azure Activity Logs / Defender for Cloud
Focus on actions taken against resources such as virtual machines, storage accounts, or network components. Look at what actions were performed and who performed them.
Identity compromise can extend directly into infrastructure control
Cloud management actions can initiate execution without malware
Activity may appear administrative rather than adversarial
Enables persistence and expansion within the environment
Bridges identity abuse and infrastructure impact

Pivot Next

What to Hunt
Microsoft Defender for Endpoint (MDE)
Check if those actions resulted in processes running on the system
Microsoft Entra ID
Validate the identity performing the action and their normal behavior

Resource actions tied to user or service identities
Command execution via management interfaces
Resource creation, modification, or configuration changes
Administrative actions without clear operational need
Activity linking identity events to infrastructure operations

Example Query

Use this to identify identity-driven interaction with compute or infrastructure resources.
AzureActivity
| where OperationName contains "RunCommand"
 or OperationName contains "Create"
 or OperationName contains "Update"
| project TimeGenerated, Caller, OperationName, ResourceId

### Notes:
Instructor Notes
This is the “this is real now” moment
Tie identity directly to system impact
Key Point to Say:“They didn’t log into the system—they acted on it.”
Prompt Question:“What can you do to a system without ever logging into it?”

<!-- Slide number: 32 -->

Identity vs Application:
A Cloud Mental Model
Understanding who is acting versus what is acting
Identity
Application

Represents who is authorized
Includes users, guests, and non-human identities
Enforced through authentication, authorization, and policy
May act without a device (tokens, apps, automation)

Represents what is authorized to act
Includes OAuth apps, service principals, APIs, automation
Operates using delegated or application permissions
Acts without user interaction or sign-ins

Think: Who has permission?

Think: What is allowed to act?

Key takeaway: In the cloud, access is granted to identities and applications, not devices.

<!-- Slide number: 33 -->

Application-Based Adversary Tradecraft
How attackers abuse cloud applications, APIs, and automation to access data and persist without interactive users

Applications operate with delegated or application-level permissions
Many attacks leverage legitimate apps rather than compromised users
Activity often appears as normal service behavior, not malicious actions
Application access frequently persists beyond password resets and MFA changes

<!-- Slide number: 34 -->

Attackers abuse application API permissions or service principals to directly access cloud resources through APIs without interactive user sign-ins. This enables large-scale, automated access to mail, files, and directory data while activity appears as legitimate application behavior.

API abuse commonly follows OAuth consent or service principal compromise and is difficult to detect because it bypasses traditional authentication controls.

TTP: API Access Abuse

APIs don’t authenticate like users do.
 If an app can call it, it can take it.

Why This Matters
Start Here
Microsoft Defender for Cloud Apps (MDA)
Focus on application activity, API calls, and non-interactive access patterns.
Look for apps accessing data at scale or without user context.
API access bypasses user sign-ins, MFA, and device checks
Activity often blends in with normal application traffic
Enables scalable data access across users or tenants
Frequently persists after password resets or account remediation

Pivot Next

What to Hunt
Microsoft Entra ID
Review app registrations, API permissions, and service principal sign-ins.
Validate what permissions were granted, by whom, and when.
Microsoft Defender for Endpoint (MDE)
Assess whether API abuse is associated with compromised devices, automation tooling, or developer environments.

Applications making high-volume or unusual API calls
API access without corresponding interactive sign-ins
Service principals accessing mail, files, or directory data
Activity outside expected application usage patterns
API permissions broader than business requirements

Example Query

AuditLogs
| where OperationName in (
    "Add delegated permission grant",
    "Add app role assignment",
    "Consent to new app"
)
| project TimeGenerated, InitiatedBy, TargetResources, OperationName

Use this to identify applications that were granted API permissions enabling persistent, non-interactive access to cloud resources.

*Entra ID Audit Logs

### Notes:
Instructor Notes
Emphasize scale + automation
This is where activity becomes less human
Key Point to Say:“This is how attackers go from one account to many.”
Prompt Question:“What would large-scale access look like without a user?”

<!-- Slide number: 35 -->

Attackers abuse the OAuth On-Behalf-Of (OBO) flow to impersonate users through applications, allowing actions to be performed as the user without direct user interaction. This enables access to mail, files, and APIs while activity appears to originate from a legitimate application acting for a valid user.

OBO abuse is especially dangerous because it blends identity compromise with application trust, making actions appear user-authorized and policy-compliant.

Application Impersonation (On-Behalf-Of Abuse)

If an app can act as a user,
 it inherits everything that user can do.

Why This Matters
Start Here
Microsoft Defender for Cloud Apps (MDA)
Focus on delegated application activity acting as users.
Look for apps accessing data under user context without corresponding sign-ins.
Actions appear to be performed as the user, not the app
Bypasses MFA once a valid token exchange occurs
Activity often looks indistinguishable from legitimate user behavior
Enables targeted access to high-value users without endpoint compromise
Frequently missed during investigations focused only on sign-in logs

Pivot Next

What to Hunt
Microsoft Entra ID
Review OAuth delegated permission grants and token issuance events.
Validate which apps are allowed to act on behalf of users and with what scopes.
Microsoft Defender for Endpoint (MDE)
Assess whether the impersonated user context aligns with expected device activity or if access occurs without a trusted endpoint.

Applications acting on behalf of users without recent interactive sign-ins
Token exchanges where an app requests delegated permissions for users
User activity attributed to apps rather than devices
OBO flows involving sensitive scopes (Mail.Read, Files.Read, Directory.Read)
Repeated delegated access across multiple users

Example Query

Use this to identify applications performing delegated authentication flows that allow actions to be taken as users without interactive sign-ins.
SignInLogs
| where AuthenticationDetails has "On-Behalf-Of"
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, AppDisplayName, AuthenticationDetails, IPAddress

*Entra ID Audit Logs

### Notes:
Instructor Notes
This is confusing—keep it simple:→ “App acts as the user”
Key Point to Say:“The system thinks it’s the user—but it’s not.”
Prompt Question:“How would you tell the difference between a user and an app acting as one?”

<!-- Slide number: 36 -->

Attackers abuse cross-tenant trust relationships and B2B application permissions to impersonate users or applications across organizational boundaries. By leveraging delegated permissions, service principals, or trusted tenants, attackers gain access to data and APIs while appearing as a legitimate external partner or application.

This technique is especially dangerous because activity originates from trusted tenants, bypassing many identity and network-based controls.

TTP: Cross-Tenant / B2B Application Impersonation

Trust doesn’t stop at the tenant boundary,
 attackers know that too.

Why This Matters
Start Here
Microsoft Defender for Cloud Apps (MDA)
Focus on cross-tenant application activity and external app access.
Look for apps or identities accessing data from outside your tenant trust boundary.
Cross-tenant access inherits implicit trust
Activity often bypasses Conditional Access assumptions
MFA enforcement may not apply as expected across tenants
Appears as legitimate partner or vendor activity
Enables long-term access without malware or user compromise

Pivot Next

What to Hunt
Microsoft Entra ID
Review cross-tenant access settings, B2B trust policies, and external app consent. Validate which tenants, apps, or users are allowed access and why.
Microsoft Defender for Endpoint (MDE)
Assess whether cross-tenant access aligns with known business workflows or correlates with suspicious device or automation activity.

External apps accessing internal resources via delegated permissions
Service principals from external tenants with broad API access
Guest users/apps performing actions w/out corresponding interactive sign-ins
Cross-tenant access to mail, files, or directory data at scale
Token usage originating from foreign tenants or unexpected issuer IDs

Example Query

Use this to identify successful authentication or token usage where access originates from an external tenant acting on internal resources.
SignInLogs
| where ResultType == 0
| where HomeTenantId != ResourceTenantId
| project TimeGenerated, UserPrincipalName, AppDisplayName, HomeTenantId, ResourceTenantId, IPAddress

*Entra ID Audit Logs

<!-- Slide number: 37 -->

Attackers trick users or administrators into granting OAuth permissions to malicious or deceptive applications, enabling access to mail, files, or directory data without further interaction.

Illicit consent grants are dangerous because access is explicitly authorized, often persists through password resets, and blends in as legitimate application activity.

TTP: Illicit Consent Grants

If a user approves it once, the app doesn’t need to log in again.

Why This Matters
Start Here
Microsoft Entra ID
Focus on consent grants, permission scopes, and who authorized access.
Look for applications accessing data without ongoing user interaction.
Consent grants create access without credential theft
Permissions persist until explicitly revoked
Activity appears as legitimate application behavior
Often the entry point to OAuth abuse or service principal escalation
Common in phishing and AiTM campaigns

Pivot Next

What to Hunt
Microsoft Defender for Cloud Apps (MDA)
Determine whether the app is actively accessing data at scale or behaving abnormally.
Microsoft Defender for Endpoint (MDE)
Assess whether the consent event originated from phishing, malicious links, or compromised devices.

Newly granted OAuth permissions with high-risk scopes
User-consented apps accessing mail, files, or directory data
Consent grants not aligned with business use
Apps granted permissions without corresponding user activity
Consent events followed by non-interactive access

Example Query

AuditLogs
| where OperationName in (
    "Consent to new app",
    "Add delegated permission grant"
)
| project TimeGenerated, InitiatedBy, TargetResources, OperationName

Use this to identify OAuth consent events where applications were granted delegated permissions that may enable persistent, non-interactive access.

*Entra ID Audit Logs

<!-- Slide number: 38 -->

Attackers enumerate cloud resources, identities, roles, and configurations to understand what access they have and where to move next.

This activity is typically performed through APIs or management interfaces and generates low-noise, high-value intelligence about the environment.

TTP: Cloud Resource Enumeration

Enumeration is often the first signal of intent, not compromise.
 What an actor queries reveals what they plan to access next.

Why This Matters
Start Here
Azure Activity Logs / Defender for Cloud
Look for actions where users or identities are viewing or listing resources, not modifying them.
Enables attackers to map the environment and identify targets
Often occurs without triggering alerts
Provides visibility into roles, permissions, and resource relationships
Supports privilege escalation and lateral movement decisions
Common precursor to all follow-on activity

Pivot Next

What to Hunt
Microsoft Entra ID
Validate which identities are performing discovery and their privilege levels.
Microsoft Defender for Cloud Apps (MDA)
Determine scope and frequency of discovery activity across services

Repeated “List” or “Get” operations across resources
Enumeration of users, roles, groups, or applications
Access to multiple resource types in short timeframes
API-driven discovery activity
Resource queries without clear operational purpose

Example Query

AzureActivity
| where OperationName contains "List" or OperationName contains "Get"
| summarize count() by Caller, OperationName

Use this to identify identities performing broad or repeated discovery across cloud resources.

### Notes:
Instructor Notes
This is recon in the cloud
Often ignored because it looks harmless
Key Point to Say:“Before attackers act, they look.”
Prompt Question:“What are they trying to learn?”

<!-- Slide number: 39 -->

Attackers access data stored in cloud platforms such as SharePoint, OneDrive, and storage services using legitimate APIs or application access.

This allows collection of sensitive information without relying on traditional file downloads or endpoint activity.

TTP: Cloud Data Collection (Non-Mail)

Email is only one data source.
 Cloud storage often holds the highest-value information.

Why This Matters
Start Here
OfficeActivity / Defender for Cloud Apps (MDA)

Focus on file access, sharing, and retrieval activity rather than message content.
Expands beyond email into broader data exposure
Often appears as normal user or application activity
Can occur at scale through APIs
Supports long-term collection without detection
Frequently overlooked when investigations focus on email only

Pivot Next

What to Hunt
Microsoft Entra ID
Validate identity or application context behind data access
Microsoft Defender for Endpoint (MDE)
Determine if access aligns with expected device activity

File access across multiple users or locations
High-volume or repeated file access activity
Access without clear business justification
Data access via applications or service principals
Patterns inconsistent with normal user behavior

Example Query

OfficeActivity
| where Operation in ("FileAccessed", "FileDownloaded")
| summarize count() by UserId, Operation
Use this to identify patterns of data access across cloud storage platforms and services.

### Notes:
Instructor Notes
Expand their mindset beyond email
Many will default to inbox thinking
Key Point to Say:“Email is just one place—data is everywhere.”
Prompt Question:“Where else would sensitive data live?”
