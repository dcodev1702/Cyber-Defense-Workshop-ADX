# Repository Evaluation — Work Summary

**Date:** 2026-07-26
**Source:** `REPO-EVALUATION-2026-07-26.md` ("Suggested order of work")
**Repo:** Cyber Defense KQL Workshop (ADX) — `cyber_conf_wiesbaden`
**Executed on:** Fable (claude-fable-5) — the entire pass completed on Fable; no Opus switch was needed.

---

## Summary

Work proceeded straight down the evaluation's "Suggested order of work," in value-per-effort
order. Everything was verified where a runner exists:

- **55 / 55** gateway tests pass (`node --test`) — 52 from this pass, 4 added afterwards for the ADX
  web UI handshake and the `.show cluster` decision (**56** as of the operational pass)
- **Pre-class go/no-go**: `scripts/Test-WorkshopReadiness.ps1` — 7 checks green against the live
  stack, and verified to turn red when the network boundary is dropped
- All PowerShell files **parse clean** with **0 lint errors** (PSScriptAnalyzer; 312 pre-existing
  style warnings remain, documented below)
- `Test-WorkshopPackage.ps1` **exits 0 on a clean clone** (no `sample/`, no generated data)
- `Test-RepositorySafety.ps1` exercised against a purpose-built fixture repo (5 scenarios)
- `compose.yaml` and all five workflows validate (`docker compose config`, YAML parse)

**48 files** were changed or created. All non-`.github/` files were written back to the machine.
The 6 files under `.github/` were blocked by the device bridge's protection on that folder and were
delivered separately as a zip. **That step is now complete** — all six are in place and tracked, and
a seventh workflow was added later (see "After the evaluation pass").

---

## What was completed

### Before next delivery (all done)

- **C1** — The gateway no longer dies on a `null` request body. A body of the four bytes `null`
  parsed successfully and then dereferenced `null.csl` inside an `async` handler with no `catch`,
  which Node turns into a process-ending unhandled rejection (a one-curl class outage under
  `restart: unless-stopped`). The handler body is now wrapped so every failure path answers with a
  status, non-object JSON bodies (`null`, `true`, `42`) are rejected `400`, and
  `process.on('unhandledRejection')` / `process.on('uncaughtException')` are installed as a second
  layer.
- **H1a** — The forwarded body is rebuilt from the validated fields (`csl`, `db`, an allowlisted
  subset of `properties.Options`) instead of forwarding the client's raw bytes, killing the
  parser-differential bypass between V8's `JSON.parse` and Kustainer's .NET deserializer.
- **H5** — One `-TelemetryEndTime` is captured in the parallel driver and passed to every worker, so
  staggered worker starts no longer anchor each process to a different "now"; reruns are reproducible
  again, honoring the driver's own docstring.
- **H10** — The Cloudflare service-token secret moved from a command-line argument (visible in the
  process table to any local user) to the `TUNNEL_SERVICE_TOKEN_SECRET` env var, cleared in a
  `finally`.
- **M3** — `Invoke-WorkshopAdxManagementCommand` now uses
  `-TimeoutSec 300 -MaximumRetryCount 3 -RetryIntervalSec 5`, and the access token is cached to its
  real expiry instead of re-acquired on every call.
- **M4** — `$LASTEXITCODE` is checked on the `az account get-access-token` path so garbage stdout is
  never returned as a bearer token.
- **L1, L2, L3** — README footer 629K → 624K; class size 20-40 → 5-100 (matching the diagrams and IaC
  docs); all three misleading "48-table snapshot" notes in the instructor answer key rewritten to the
  79-table reality.
- **L12** — `Get-MgUser` added to the `New-WorkshopStudents.ps1` preflight (it is used in the loop but
  was missing, so the script failed mid-loop after creating the group).

### This iteration (all done)

- **H2** — Per-source token bucket + global in-flight cap on the gateway; over-budget clients get
  `429` with `Retry-After`. Client `Options` are clamped: unknown keys dropped (so `notruncation` and
  unbounded `servertimeout` cannot be set), `servertimeout` bounded, `query_language` forced to `kql`.
- **H3** — `.show` replaced with a metadata-read allowlist (`.show version`, `schema`, `databases`,
  `databases schema`, `tables`, `table <t> schema`/`cslschema`, `functions`/`function <f>`). Blocks
  `.show queries`, `commands-and-queries`, `journal`, `... principals`, `ingestion failures`, etc.
- **H1b (proxy-side)** — Raw-text deny-scan for `externaldata`, `evaluate` code/request plugins, and
  `cluster(`; forced `request_readonly = true` (env-toggle `KUSTO_FORCE_READONLY`, default on per the
  chosen option); and a database allowlist (`KUSTO_ALLOWED_DATABASES`, set to
  `CyberDefendStudentSnapshot`).
- **H8** — Compose split into `edge` (cloudflared + gateway) and `backend` (gateway + kusto), so
  `kusto` no longer resolves for cloudflared and a hostname-based tunnel ingress rule cannot reach
  the emulator.

  > **Correction.** This entry originally claimed the connector "cannot reach `kusto:8080` no matter
  > what the dashboard-managed tunnel ingress says — the one-click bypass is now architecturally
  > impossible." Testing later the same day disproved that. Publishing Kustainer's `8080` makes
  > Docker insert a firewall accept **above** its own cross-bridge isolation which is not restricted
  > by source network, so an ingress rule naming the backend IP still reached the engine. The split
  > blocks the realistic misconfiguration, not a deliberate one. Closed separately — see "After the
  > evaluation pass" below.
- **M8 / M10** — Dockerfile: pinned base tag (was moving `node:24-alpine`), `USER node`,
  `HEALTHCHECK`, `ENV NODE_ENV=production`, `npm ci` + lockfile, `.dockerignore`. Compose:
  `init: true` on every service, `security_opt: [no-new-privileges:true]`, JSON log size limits, and
  a pinnable Kustainer tag via `KUSTO_IMAGE_TAG`.
- **M1** — 65 `Join-Path` calls with embedded backslashes fixed across 25 files (a literal `\` breaks
  path resolution on Linux, blocking any PowerShell gate in CI); rewritten to the multi-segment idiom
  already used correctly in `Test-FieldProfileSafety.ps1`. All files still parse cleanly.
- **H4** — `Test-WorkshopPackage.ps1` passes on a clean clone: the `sample/*-Real.csv` header checks
  sit behind a `-WithRealSamples` switch, and a missing default `data/generated` is a skip rather than
  an error. Static validation wired into CI.
- **M9** — Added `scripts/Test-RepositorySafety.ps1` as the single enforcement point that both
  `.githooks/pre-commit` and `.github/workflows/telemetry-safety.yml` call, so the hook and CI cannot
  drift. It enforces the forbidden-path rules (nothing under `sample/`, no `students/*.csv`, no
  `samples/*.csv`, nothing under `data/generated/`) and the field-profile tenant scan. In `-Staged`
  mode it materializes the staged blob contents and scans those, closing the "git add, then edit"
  gap. The hook previously did not check `students/` at all.
- **CI workflows** — Added `gateway-tests.yml`, `powershell-lint.yml`, `iac-validate.yml`,
  `package-validation.yml`, plus cross-cutting edits to every workflow including the existing one:
  SHA-pinned `actions/checkout`, `concurrency` with `cancel-in-progress`, and `timeout-minutes`.
- **§3.7 governance** — Added `LICENSE` (MIT), `.gitattributes`, `SECURITY.md`, and
  `.github/dependabot.yml`.
- **Bonus** — Gateway structured audit log (part of L19), gateway README + CORS-is-UX-not-a-control
  note (part of L18), and every change documented in `CHANGELOG.md` in the repo's house style.

---

## After the evaluation pass

Three defects found the same day by *exercising* the workshop rather than reading it. All three are
the same shape as the ones the evaluation caught: an artifact produced, never exercised, assumed
good — and in each case the check that should have caught it reported success.

- **The hardened gateway was not the gateway that was running.** `kusto-readonly-gateway` is a
  Compose `build:` service, so `docker compose up -d` reuses the last image built on the host and
  never consults the source. After H2/H3/H1b landed, the running container was still a five-day-old
  pre-hardening build: `.show queries` answered `200`. `docker compose ps` and the container health
  check reported healthy throughout, because the health check only proves the process answers on
  `/healthz`. `README.md` and the instructor checklist now require an explicit
  `docker compose up -d --build kusto-readonly-gateway` and a policy probe (`.show tables` → 200,
  `.show queries` → 403) rather than a health check.
- **The database allowlist locked out the client the workshop exists to serve.** H1b's
  `KUSTO_ALLOWED_DATABASES` required every request to name a permitted database, but the ADX web
  UI's opening calls carry none — discovering which databases exist is what they are for. **Add
  connection** at `dataexplorer.azure.com` failed with a bare "Request failed with status code 403",
  at the first step every student must complete. Database-less cluster-scoped discovery is now
  permitted on the management endpoint only, and `/v1/rest/auth/metadata` is forwarded instead of
  answered `404`. Diagnosed in one line from the structured audit log added in this pass. Three
  regression tests added (52 → 55): every earlier test and probe had supplied an explicit database,
  so the one path the real client always takes was the one path never exercised.
- **The connector could route around the gateway** — the H8 correction above. Closed with
  `scripts/Set-WorkshopNetworkIsolation.ps1`, which inserts a `DOCKER-USER` DROP between the two
  bridges. It derives the networks from the running containers rather than from names and clears its
  own stale rules first, because Docker names a bridge after the network ID: any `docker compose
  down` yields new bridge names and leaves a dead rule that still reads as protection.
  `scripts/Test-WorkshopNetworkIsolation.ps1` proves the boundary by sending packets rather than
  reading rules — six assertions against the live stack, and a `-SelfTest` mode on throwaway networks
  for CI (`network-isolation.yml`). Wired into `Start-CloudflareAdxTunnel.ps1 -Apply`, which fails
  the run if the boundary does not hold. **The rule is host firewall state and does not survive a
  Docker engine restart** — Terraform cannot own it.

Also completed the same day, outside the evaluation's scope: the local backup shipping a stale
48-table / 358,621-row payload while the live database held 79 tables / 623,832 rows, and the new
`Restore-LocalKustoSnapshot.ps1` that makes restoring a proven operation rather than one
reconstructed under pressure. Both are recorded in `CHANGELOG.md`.

Commits: `704d6ef`, `54ed23b`, `705b0f5` (backup/restore), `cdd0332` (gateway handshake),
`a62ab4f` (network boundary), `658e898` (assets).

---

## What remains

### Before Wiesbaden — operational, not code ✅ DONE

All four are now settled.

- **Emulator image — decided: stay on `latest`.** A digest pin was added and then deliberately
  reversed. This instance runs indefinitely rather than for a single event, so it tracks the current
  emulator and picks up Microsoft's fixes as they ship. The trade is stated in `compose.yaml` rather
  than left to be rediscovered: Kustainer writes its persistent database in the format of the build
  that created it, so when the image moves, the snapshot in `data/local-kusto` does not come with
  it. That is recoverable and rehearsed — the NDJSON payload is what restores, via
  `Import-GeneratedDataToKustainer.ps1`. `KUSTO_IMAGE` accepts a full reference, so pinning for a
  specific delivery is one environment variable away.

  Reversing the pin also removed the container recreate it introduced:
  `docker compose up -d --dry-run` reports `kusto` as `Running` again, so the persistent database
  registration is no longer one `up` away from being destroyed.

  `Test-WorkshopReadiness.ps1` reports the running build rather than asserting it — asserting a
  fixed build would turn every legitimate update into a red preflight, which trains people to ignore
  preflights. The gate is the table and row count, which is what actually catches a version move.

- **Isolation rule surviving a restart — done.** `scripts/Test-WorkshopReadiness.ps1` reapplies it
  (idempotent, clears its own stale rules first) and then proves it by sending packets. No standing
  privileged container was added; the isolation script spawns a short-lived helper only when it
  writes the rule, which is unavoidable from Windows. Verified both ways: removing the rule turns
  the verdict red with the exact remedy, and a normal run repairs it and turns it green.
- **Gateway rebuild on pull — done.** Tracked `.githooks/post-merge` rebuilds the gateway whenever a
  pull touches `tools/kusto-readonly-gateway`, then probes the policy (`.show tables` → 200,
  `.show queries` → 403) rather than trusting the health check. Requires
  `Install-WorkshopGitHooks.ps1` to have been run in the clone; `CDW_SKIP_GATEWAY_REBUILD=1` opts
  out. Written LF — a shell hook with CRLF fails as `unexpected end of file`, which it did on the
  first attempt.
- **`.show cluster` — decided: stays blocked.** Locked in with a test asserting `.show cluster`,
  `.show cluster principals`, and `.show cluster policy caching` are all refused, so it is not
  quietly reverted. Students connect and query normally; clicking into cluster-level detail returns
  `403`. Noted in the instructor guide so the question is expected. Suite is 56 tests.

### Resolved since this summary was first written

- The **6 `.github/` files** are in place and tracked; the zip step is no longer outstanding. A
  seventh, `workflows/network-isolation.yml`, was added afterwards. Dependabot has since opened and
  merged four bumps against them (`actions/checkout` 7.0.1, `actions/setup-node` 7.0.0,
  `hashicorp/setup-terraform` 4.0.1, and the gateway base image to `node:25.2.1-alpine3.21`), which
  is the SHA-pinning working as intended. `gateway-tests.yml` was also corrected to read the Node
  version from the Dockerfile, after CI went green against a Node the container never runs.
- The **line-ending renormalization** is done. Verified: no file is stored with CRLF in the index,
  so the one-time `git add --renormalize .` is not outstanding.
- **`iac-validate.yml`** has now run in CI rather than only being authored.

### Not started — the evaluation's "Next iteration" (better candidates for an Opus pass)

- **H11 / H12 / H13 / M11 / M12 / M13 / L20** — the metadata + `sample/` consistency pass: the
  `IdentityInfo` schema/profile split (Defender XDR vs Sentinel UEBA), the 32 missing source CSVs, the
  two load-bearing `New query (N).csv` files, the two profile formats sharing a `.profile.json`
  suffix, the coverage funnel (79 → 69 → 68), and the schema/profile column-count disagreements.
  Needs answers to the evaluation's §6 questions first.
- **M2** — consolidate the ~400 duplicated lines into `AdxWorkshop.Common.psm1`.
- **M7** — Bicep hardening (`diagnosticSettings`, `allowedFqdnList`, `parent:` on child resources,
  managed identity in IaC, parameter `@description`/constraints).
- **§3.5** — split the 8,135-line `New-SyntheticTelemetry.ps1` along the two clean seams (extract the
  ~40 data catalogs to JSON; split `New-NormalTelemetryValues`).
- **M14** — retire one dashboard copy and add the `.kql`↔`.json` tile-parity check to CI.
- **Pester suite** for the module's pure functions (escaping, determinism, response parsing, type
  mapping).

### Partial / deferred

- **H4 (CI, data half)** — static package validation is wired; wiring `Test-SyntheticDataQuality` and
  `Test-WorkshopIdentityInvariants` behind a fixture generation is **not** — the generator needs its
  full profile input set, and a tiny fixture run could not be made green from the sandbox without
  risking a red pipeline.
- **H1c** — the string-smuggling trick is closed via the raw-text deny-scan (fails closed), but
  backslash / `@`-verbatim string handling was **not** added inside the lexer itself.
- **H7 / H9 / M5 / M6** and the remaining LOW items — untouched; several (H7 public-repo identifiers,
  H9 student-teardown script) need a decision first.
- **`Test-MetadataConsistency.ps1`** (item 19's regression guard) — not written, because the metadata
  pass it would guard has not been done.

---

## Notes

- **Line endings** were written as **CRLF** to match the Windows tree (so diffs show real content
  changes, not a line-ending flip), except `.githooks/pre-commit`, written as **LF** to fix L7.
  `.gitattributes` is committed and the tree is normalized — verified 2026-07-26, zero files stored
  with CRLF in the index.
- **PSScriptAnalyzer** reported **312 warnings**, all pre-existing documented debt (Write-Host,
  missing `ShouldProcess` = M5, plaintext-password params = H9/H10, the unapproved verb = L9). The
  lint job surfaces them as annotations but only fails on error severity, of which there are none.
- **Gateway read-only option** — per the chosen configuration, `request_readonly` is forced by default
  with a `KUSTO_FORCE_READONLY=false` escape hatch in case a Kustainer build rejects the option during
  rehearsal.

---

## Files changed or created (48)

Gateway: `server.mjs`, `server.test.mjs`, `Dockerfile`, `README.md`, `.dockerignore`,
`package-lock.json`.

Compose / infra: `compose.yaml`.

PowerShell (module + scripts): `AdxWorkshop.Common.psm1`, `New-SyntheticTelemetryParallel.ps1`,
`Start-StudentAdxProxy.ps1`, `New-WorkshopStudents.ps1`, `Test-WorkshopPackage.ps1`,
`Test-RepositorySafety.ps1` (new), `Test-WorkshopIdentityInvariants.ps1`, `Initialize-AdxTables.ps1`,
`Export-LogAnalyticsSamples.ps1`, `Import-SyntheticTelemetry.ps1`, `Import-GeneratedDataToKustainer.ps1`,
`Add-CloudflareAdxDnsRoute.ps1`, `New-WorkshopDeck.ps1`, `Export-WorkshopTelemetryProfiles.ps1`,
`New-WorkshopDashboard.ps1`, `Backup-LocalKustoSnapshot.ps1`, `Restore-LocalKustoSnapshot.ps1`,
`Copy-StudentAdxToLocalKusto.ps1`, `Start-CloudflareAdxTunnel.ps1`, `New-SyntheticTelemetry.ps1`,
`Initialize-Workshop.ps1`, `Export-TenantTelemetrySamples.ps1`, `Test-SyntheticDataQuality.ps1`,
`tools/Build-SchemasFromMicrosoftLearn.ps1`, `tools/Build-SchemaFromLiveTable.ps1`,
`adx_db_backupNrestore/Restore-AdxDatabaseBackup.ps1`, `adx_db_backupNrestore/Backup-AdxDatabase.ps1`,
`adx_db_backupNrestore/Initialize-AdxBackupStorage.ps1`.

Hook / docs: `.githooks/pre-commit`, `docs/instructor_answer_key.kql`, `README.md`, `CHANGELOG.md`.

Governance: `LICENSE` (new), `.gitattributes` (new), `SECURITY.md` (new).

`.github/` (originally delivered via zip — bridge-protected; **now in place and tracked**):
`dependabot.yml` (new), `workflows/telemetry-safety.yml` (edited), `workflows/gateway-tests.yml`
(new), `workflows/powershell-lint.yml` (new), `workflows/iac-validate.yml` (new),
`workflows/package-validation.yml` (new).

Added after this pass: `scripts/Set-WorkshopNetworkIsolation.ps1`,
`scripts/Test-WorkshopNetworkIsolation.ps1`, `.github/workflows/network-isolation.yml`.
