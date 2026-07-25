# Instructor guide

> **Primary delivery path:** Use the containerized class lab and [Shared Class Credential Guide](cloudflare_adx_access.md) for security conferences with mixed or random participants. Distribute the temporary shared credential and student proxy script, have students connect through `http://127.0.0.1:8080`, and verify the `kusto-readonly-gateway` service is healthy.
>
> **Secondary delivery path:** Use managed Azure ADX plus B2B participant setup only when the event requires per-person identity governance, tenant access policy, and managed ADX database authorization.

## Primary conference setup checklist

1. Start the Docker host with `docker compose up --detach --wait kusto` for the initial setup.
2. Run `scripts\Copy-StudentAdxToLocalKusto.ps1 -ForceRecreate` to build and validate the local Student snapshot.
3. Run `scripts\Start-CloudflareAdxTunnel.ps1 -Apply` to create the temporary shared Service Auth route and start the connector.
4. Confirm `kusto-readonly-gateway` is healthy with `docker compose ps` and validate a pilot student proxy connection.
5. Distribute only `student-access.env`, `Start-StudentAdxProxy.ps1`, and the student lab instructions through the temporary class channel.
6. Load `dashboards\cyber-defense-workshop-dashboard.kql` in the query editor, and keep `docs\instructor_answer_key.kql` open in a second tab for yourself.

Before an intentional Kustainer replacement, run `docker compose stop kusto`, `scripts\Backup-LocalKustoSnapshot.ps1`, and `docker compose start kusto`; copy the resulting ZIP to secure storage.

## Secondary managed Azure checklist

1. Confirm the ADX cluster exists.
2. Run `scripts\Initialize-Workshop.ps1` to create the database, tables, mappings, generated data, and ingestion.
3. Create or confirm the participant security group and B2B access package described in `user_creation\README.md`.
4. Grant the participant group ADX database viewer access using `scripts\Grant-StudentAdxAccess.ps1` or an equivalent Kusto management command.
5. Share the ADX dashboard with the participant group using dashboard `Can view` permission.
6. Open the ADX Web UI URL with a pilot participant account and confirm the database, dashboard, and query results are visible.
7. Load `dashboards\cyber-defense-workshop-dashboard.kql` in the query editor, and keep `docs\instructor_answer_key.kql` open in a second tab for yourself.

## Instructor storyline

Start with the sign-in. Students should find a high-risk interactive sign-in for `victor.alvarez@usag-cyber.local` from `185.225.73.18`, followed by OAuth consent, service-principal credential creation, app-only Microsoft Graph access, and Graph enumeration/collection. The endpoint pivot is `WIN11-04.usag-cyber.local`. The credential-access chain begins with PowerShell staging and progresses through registry credential discovery, SAM hive save, browser database copy, Kerberoasting, LSASS dump, password-store harvesting, and Mimikatz-style credential dumping. Keep the tool names visible because they cover the required screenshot vectors, but frame them as follow-on credential expansion after the Midnight Blizzard-style identity/OAuth foothold. The identity pivot is the service account `svc_sql`, which is later used against `AADCONNECT01`. `SecurityIncident` should be introduced as the SOC incident queue: incident titles are generic and analyst-friendly, while `AlertIds` and `AdditionalData` tie the incidents back to the scenario evidence and supporting TVM tables.

Use the Ubuntu branch as an optional comparison pivot after the Windows path is understood. Students should see that `UBUNTU-03.usag-cyber.local` emits MDE device telemetry, not MDI telemetry: SSH/PAM logons in `DeviceLogonEvents`, `sudo` and shell execution in `DeviceProcessEvents`, audit artifacts in `DeviceEvents` and `DeviceFileEvents`, Linux `.so` image loads in `DeviceImageLoadEvents`, CUPS/IPP network context in `DeviceNetworkEvents`, and Linux package/CVE context in TVM tables. The additive Oracle branch stages a synthetic Python helper and Go binary on `UBUNTU-03`, connects to Oracle TNS on `UBUNTU-05:1521`, and creates a synthetic sensitive export under `/tmp/.oracle`.

## Pacing and scope control

![Pacing and scope control for the ADX workshop](../images/Pacing_Scope_Control_ADX_Modern_v2.svg)

## Expected key findings

![Expected key findings for the ADX workshop](../images/expected-findings-adx-modern.svg)

## Instructor-only alert answer key

Do not put these IDs on the student slides. The generated `AlertId` values are intentionally opaque so students learn to hunt by behavior, title, timestamp, entity, MITRE technique, `SecurityIncident.AlertIds`, and `AlertEvidence`, not by actor-branded IDs.

Use [`docs\instructor_answer_key.kql`](instructor_answer_key.kql) as the corresponding instructor-only query pack. It contains the static AlertId answer key plus the device-code phishing, cloud, endpoint, identity, incident, threat intelligence, exposure, and full-timeline pivots needed to tell the scenario story, along with a facilitation checklist of the questions students actually ask.

Two things to know before you present from it. The AlertIds in that file are stable across regeneration, but the timestamps are not, because the generator anchors the scenario to the moment it runs. Query 00 derives the scenario window dynamically for exactly that reason, so run it first. Every query in the file has been executed against a live Kusto engine, and the ones whose tables are newer than the local snapshot were validated against their schemas.

![SOC alert timeline correlation for the ADX workshop](../images/SOC_Alert_Timeline_Correlation_ADX_Modern_v3.svg)

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
