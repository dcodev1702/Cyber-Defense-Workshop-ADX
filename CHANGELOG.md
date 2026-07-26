# Changelog

## Unreleased

- Stopped field profiles from carrying tenant data. Suppressing identity and free-text columns by name missed columns whose values embed tenant identifiers, such as `SourceAgentId`, which carries Azure resource IDs containing a live subscription GUID; a scan of the committed profiles found 70 such columns. Captured vocabularies are now dropped when any value contains an embedded GUID, a subscription, resource group or tenant path, a UPN, an address, a bearer token or JWT, or a long hex string. Version columns are exempt from the address test so product versions are not mistaken for an IP. `scripts/Test-FieldProfileSafety.ps1` enforces this and now reports clean, with 762 of the original 819 vocabularies retained.
- Made the generator consume the real field profiles: columns that production populates but that carry no safe vocabulary now receive a shape-matching synthetic value at the observed fill rate, and columns empty in production are cleared on ambient rows unless listed in the new `metadata/profile-overrides.json`, which the generator and the quality gate both read.
- Removed the fallback record that seeded every table lacking scenario evidence with a fabricated `WorkshopBaseline` action and application plus endpoint and identity columns most tables do not declare. Every table now reaches its row count through the normal generator.
- Rebuilt `AgentsInfo`, which had no generator branch and emitted 32 of its 39 columns empty. It now generates a declared-agent inventory with model, endpoint, MCP server, skill, permission, guardrail, trigger, data source, and owner detail, with instruction and tool fill rates tracking the real inventory at 52 and 40 percent.
- Added `scripts/Test-SyntheticDataQuality.ps1`, which scores generated tables against the real field profiles and reports sparse, overfull, and out-of-vocabulary columns.
- Added `scripts/Export-WorkshopTelemetryProfiles.ps1`, which derives per-column field profiles for every workshop table from real telemetry so the synthetic generator can reproduce production shape instead of inventing values. Rows are merged from three sources: the curated captures in `sample/`, Log Analytics workspace `DIBSecCom`, and Defender XDR advanced hunting for the tables that exist only in XDR. Profiles record fill rate, cardinality, weighted value vocabulary, detected format pattern, and numeric or length bounds, and they explicitly mark columns that are empty in production so the generator can leave them empty by design rather than by oversight.
- Generated field profiles for 69 of the 79 tables from real telemetry. The remaining 10 emit no data anywhere in the tenant and are driven from their documented Microsoft Learn schemas instead.
- Replaced `DeviceTvmBrowserExtensionsKB` with `AppGenAIContent` in the table manifest, schemas, and parallel generator. The new table is grounded in Log Analytics `DIBSecCom` and reconciles exactly with `sample/AppGenAIContent-RealTelemetry.csv` and the published schema at 214 rows and 24 columns. The package remains at 79 tables.

- Rewrote the instructor storyline around Acts 0-12 so it opens on the device-code phish and the benign twin instead of the risky sign-in, and added the closing exfiltration, threat-intel, and XDR incident beats.
- Made `STUDENT-GUIDES/dashboard-CYBER-DEFEND-V4.json` the single authoritative dashboard across the README and instructor guide; the older schema-20 export is marked superseded.
- Refreshed `docs/diagrams.md` prose and re-sequenced all three diagrams for the current scenario: the attack storyline now opens on the device-code phish and closes on cloud exfiltration, the investigation pivots start at the phish and end on exfiltration plus the threat-intel join, and the hybrid topology gets the real `usag-cyber.local` domain, 79 tables, a 5-100 student range, and a student file that still exists.
- Made the student lab setup guide cross-platform end to end: Windows, MacOS, and GNU/Linux in the intro and prerequisites, a `curl` variant for non-Windows, and a PowerShell 7 note for the proxy script.
- Aligned the shared credential lifetime to `720h` (30 days) in Terraform and all documentation, matching the value applied to the live token.
- Added the device-code phish, URL click, token redemption, and benign twin to the generated scenario summary, using the generator's real offsets.
- Added phase and per-file progress output to `Test-WorkshopPackage.ps1`, which previously ran for minutes with no indication it was working.
- Regenerated `docs/conference_abstract.pdf` from the updated abstract.
- Rewrote the conference abstract for the current device-code phishing emulation: thirteen acts, the benign twin, cloud exfiltration, threat-intel correlation, XDR incident grouping, 79 tables, and a fixed 120-minute length.
- Removed `;Fed=false` from every ADX connection instruction across the README, student guide, class guide, IaC setup, gateway, and infra docs; the student connection URI is now `http://127.0.0.1:8080`.
- Added a collapsible GNU/Linux Debian install path to step 1 of the student lab setup guide, using Cloudflare's apt repository with a direct `.deb` fallback.
- Made the MacOS install path in step 1 of the student lab setup guide a collapsible section, added `brew update` before the `cloudflared` install, and added sparing section emojis.
- Split step 1 of the student lab setup guide into Windows (`winget`) and macOS (Homebrew) installation paths, including how to install Homebrew for students who do not have it.
- Corrected deck slide 3 from 60 to 120 minutes and rebalanced its five segments to 10/40/30/35/5, matching the flow diagram; its second segment now reads Acts 2-5 instead of double-counting the orientation acts.
- Renumbered the acts in `docs/instructor_answer_key.kql` onto the deck's Act 0-12 scheme, with answer-key-only material continuing at Acts 13-16, so the key and the deck can be cross-referenced.
- Refreshed the `workshop_design.md` scenario prose and table families for the device-code phish opening, the benign twin, cloud exfiltration, threat-intel correlation, and the 79-table package.
- Re-cut the workshop flow diagram and the `workshop_design.md` agenda around the Act 0-12 scenario, keeping the two-hour total while rebalancing to 10/20/20/30/20/15/5 minutes so the device-code phish, benign twin, cloud exfiltration, and threat-intel beats are visible.
- Added Microsoft Defender for Office 365 and Microsoft Sentinel + Azure panels to the key-tables diagram, and corrected the package table count from 47/48 to the actual 79.
- Replaced the README lab topology diagram with the kill-chain ribbon variant `images/adx-lab-topology-A-ribbon.png`.
- Made the Docker Kustainer, Cloudflare Service Auth, and read-only gateway route the primary conference delivery model; repositioned managed Azure ADX and Microsoft Entra B2B material as the secondary governed option.
- Pinned `kusto-defaultdb-cleaner`, `kusto-readonly-gateway`, and `cloudflared` to 1 GiB memory and 1 GiB swap in Compose and the Terraform-generated override.
- Added `Backup-LocalKustoSnapshot.ps1` to archive the local Kustainer state, recovery directories, and newest verified NDJSON export with a SHA-256 checksum.
- Replaced the hard-coded student Service Token command in the setup guide with the generated, untracked `student-access.env` workflow.
- Clear stale internal `NetDefaultDB` metadata before Kustainer starts so the default-database cleaner no longer causes a restart loop after a normal stop/start cycle.
- Replaced the manual local Kusto and Cloudflared container workflow with Docker Compose, keeping Kusto bound to `127.0.0.1:8080` and routing the tunnel over an internal Compose network.
- Updated the Cloudflare Tunnel launcher to provision the remote resources, create an ignored connector-token environment file, and support a one-time migration from legacy containers.
- Added a shared 48-hour-minimum Cloudflare Service Auth credential and read-only KQL gateway for classroom access without per-student Cloudflare seats.
- Documented `Fed=false` for student Kustainer connection URIs so ADX clients do not attempt Microsoft Entra authentication against the local emulator.
- Added ADX web UI CORS and private-network preflight support to the read-only gateway for browser connections through the local student proxy.
- Updated class, instructor, managed-access, and troubleshooting documentation for the shared 168-hour Service Token, `Fed=false` connection URI, read-only gateway, and ADX browser CORS/private-network recovery path.
- Added a continuous Kustainer cleaner that removes `NetDefaultDB` and its persistent state after the Student snapshot database is available.
- Added a dedicated gateway reference describing its read-only policy, browser support, cleaner lifecycle, configuration, and security boundary.
- Configured Kustainer for a graceful `SIGINT` shutdown so the mounted Student snapshot remains available across normal Compose stop/start cycles.
- Added a source-of-truth workflow that copies the live Student ADX database into a persistent local Kusto emulator and verifies table row counts.
- Increased the Terraform-managed Kustainer profile from 16 GiB to 24 GiB of memory and swap while retaining 4 vCPUs, with a Terraform-generated Compose override and in-place runtime synchronization that preserves the Student snapshot.
- Added a Cloudflare provider v5 Terraform module and secure environment-driven connector launcher for `adx.tier1-cyberdefense.ai`.
- Added browser-authorized Cloudflared DNS routing for restricted API tokens and made tunnel launcher reruns preserve a healthy connector.
