# Cyber Defense KQL Workshop: Investigating a Hybrid Identity Intrusion with XDR Telemetry

**Author:** Lorenzo J. Ireland

**Date:** May 14, 2026

## Abstract

Modern intrusions rarely stay inside a single telemetry source. A phishing email that carries no malicious link at all can become a valid cloud token, an OAuth persistence problem, a Microsoft Graph collection path, an endpoint credential-access investigation, a hybrid identity lateral-movement case, and finally a data-exfiltration incident. This hands-on workshop teaches defenders how to investigate that full chain using Kusto Query Language (KQL) in Azure Data Explorer (ADX), backed by realistic synthetic Microsoft security telemetry rather than live production data.

Participants investigate a MIDNIGHT BLIZZARD-inspired scenario against a notional hybrid AD and Microsoft Entra ID environment, structured as thirteen acts. It opens with delivery rather than mid-intrusion: a device-code phishing message whose lure points at the *genuine* `microsoft.com/devicelogin`, so URL reputation never fires and the victim completes real MFA against real Microsoft infrastructure. The attacker redeems the resulting token from unfamiliar infrastructure on an unmanaged device. A deliberately benign twin runs alongside it — a legitimate device-code sign-in from a compliant, corporate-joined device — so any detection keyed on the protocol alone flags the wrong user. From that foothold the intrusion moves through suspicious OAuth consent, service-principal credential abuse, Microsoft Graph collection, endpoint staging and credential harvesting, Kerberoasting, and a service-account pivot to an Entra Connect server. It then establishes impact and closes the loop: storage key listing and mailbox access that show data actually moving, a threat-intelligence join against the indicators students found by hand, and SOC incident grouping in Microsoft Defender XDR. Optional Linux telemetry adds Ubuntu MDE, SSH, sudo, package vulnerability, and Oracle access pivots for teams that want broader endpoint realism.

The lab is built for repeatable delivery: 79 Microsoft Learn-derived table schemas, synthetic NDJSON telemetry, ADX table creation, ingestion scripts, student access helpers, dashboards, instructor guidance, and a validated instructor answer key are included. Students work across Defender for Office 365 mail, Defender XDR device, identity, cloud app, Graph, sign-in, alert, threat-intelligence, and vulnerability-management tables, then correlate events into a defensible incident timeline mapped to MITRE ATT&CK.

Attendees leave with practical KQL investigation patterns, a clearer understanding of which Microsoft telemetry sources answer which defender questions, a worked example of separating malicious activity from legitimate activity that looks nearly identical, and a reusable model for building safe, high-fidelity cyber defense training without exposing real environments or sensitive logs.

## Session Details

- Format: Hands-on workshop or instructor-led technical session
- Length: 120 minutes
- Audience: SOC analysts, detection engineers, incident responders, threat hunters, security architects, and instructors building cyber defense labs
- Skill level: Intermediate; basic familiarity with Microsoft security portals, identity concepts, and query languages is helpful

## Learning Outcomes

By the end of this session, participants will be able to:

1. Use KQL to orient across ADX tables modeled after Microsoft Defender for Office 365, Microsoft Defender XDR, Microsoft Entra ID, Microsoft Graph, CloudAppEvents, threat intelligence, and alert telemetry.
2. Reconstruct a device-code phishing chain from the delivered mail through the URL click to the resulting cloud sign-in.
3. Separate a malicious device-code sign-in from a legitimate one that looks nearly identical, and explain why protocol-only detections fail.
4. Correlate sign-in, OAuth, Graph, endpoint, identity, exfiltration, vulnerability, and alert evidence into a single attack timeline.
5. Recognize credential-access and hybrid identity tradecraft and map observed behaviors to MITRE ATT&CK.
6. Explain which telemetry sources are most useful for investigating phishing delivery, risky sign-ins, OAuth abuse, service-principal persistence, endpoint credential harvesting, Kerberos activity, lateral movement, and cloud data movement.
7. Reuse the lab design pattern to deliver safe, synthetic, repeatable cyber defense training in ADX.

## Suggested Track Tags

- Cloud Security
- Detection Engineering
- Incident Response
- Threat Hunting
- Identity Security
- Microsoft Security
- KQL
- Purple Team / Training Lab

## Workshop Topology

![Cyber Defense Workshop ADX topology](../images/cyber-defense-workshop-adx-topology-enhanced-v7.png)

This SOC dashboard is useful because it gives analysts a shared operational view of the same hybrid identity intrusion they investigate in the workshop, bringing alert volume, affected users, risky sign-ins, endpoint evidence, cloud activity, and timeline pivots into one place. For SOCs, that matters because cyber defense depends on quickly moving from isolated signals to correlated decisions: which identity is compromised, which device or service principal matters, what evidence confirms the scope, and where responders should hunt next. By grounding those decisions in Azure and XDR backed telemetry and KQL-driven views, the dashboard helps teams triage faster, preserve investigative context, and practice the same detection, correlation, and response habits they need during real incidents.

![ADX SOC overview dashboard](../images/adx-soc-overview-dashboard.png)
