# Repository Evaluation — Cyber Defense KQL Workshop (ADX)

**Reviewed:** 2026-07-26 · **Branch:** `main` @ `705b0f5` · **Reviewer:** Claude (read-only audit)

---

## 0. Ground rules honored in this review

- **Nothing in the repository was modified.** This file is the only artifact produced.
- **No credentials were changed, rotated, redacted, or flagged as defects.** The Cloudflare Service Token pair in `STUDENT-GUIDES/STUDENT-LAB-SETUP-GUIDE.md:120` is treated as intentional and correct per your instruction. It is mentioned exactly once below, as an operational dependency note only, not as a finding.
- **The examples in the student guide are treated as correct.** No suggestions touch them.
- `.venv/` was excluded from review (correctly gitignored, 0 tracked files).

**What was read:** all 267 tracked files' worth of structure; in full — `README.md`, `CHANGELOG.md`, `IaC-CFT-TF-Setup.md`, all 6 `.tf` files, `compose.yaml`, `.github/workflows/telemetry-safety.yml`, `.githooks/pre-commit`, `docs/*.md` (all 8), `STUDENT-GUIDES/STUDENT-LAB-SETUP-GUIDE.md`, `infra/cloudflare-adx/README.md`, `tools/kusto-readonly-gateway/*`, all three `.bicep` files, all 31 PowerShell files, `metadata/tables.manifest.json`, and representative samples across `schemas/`, `metadata/field-profiles/`, `sample/`, `dashboards/`, `data/`.

---

## 1. Verdict

This is a well-above-average repository. It is not "pretty solid now" in the sense of being adequate — the engineering discipline in several places is better than what I see in production infrastructure repos. Three things in particular are rare:

**The comments explain why, not what.** `scripts/Backup-LocalKustoSnapshot.ps1:94-96` says *"This is the check that was missing when a 48-table export was backed up against a 79-table database without anything reporting a problem."* That is a comment that cites the incident it prevents. `scripts/New-SyntheticTelemetry.ps1:136-149` explains that real telemetry repeats SHA256 hashes at a ratio of 0.069 and naive per-row hashing produces ~1.0 — which justifies the entire profile-grounding layer. `scripts/New-SyntheticTelemetryParallel.ps1:142-143` documents a PowerShell footgun at the exact site it bites. Do not let anyone "clean up" these comments.

**Verification-after-mutation is a real pattern, not decoration.** `Copy-StudentAdxToLocalKusto.ps1:315-325` counts source rows before *and* after export and fails if either disagrees with the exported count. `Restore-LocalKustoSnapshot.ps1:241-246` reconciles restored rows and table count against the archive. `Initialize-AdxTables.ps1:102-107` re-reads `.show tables`. Most repos assert nothing.

**The tenant-data safeguard is enforced, not documented.** Three layers — `Test-FieldProfileSafety.ps1`, `.githooks/pre-commit`, `.github/workflows/telemetry-safety.yml` — and `Install-WorkshopGitHooks.ps1:16-18` honestly states that the local hook is bypassable and CI is not. I verified the outcome independently: I scanned every `topValues` entry in all 69 tracked profiles for email and IPv4 patterns and got 4 hits, all false positives (software version strings). The control works.

**Where it is weakest:** the security-critical component (the read-only gateway) has the thinnest test coverage and zero CI enforcement, and there is one confirmed remote crash. Beyond that, the issues are consistency drift, a genuinely non-runnable validator, and missing repo-governance scaffolding. Details below.

---

## 2. Findings

Severity is relative to *this repository's* purpose: a conference lab that must survive 20-40 curious security people for two hours.

### 🔴 CRITICAL — verified by execution

#### C1. One HTTP request kills the class gateway

**File:** `tools/kusto-readonly-gateway/server.mjs:349-358`

```js
let payload;
try { payload = JSON.parse(body.toString('utf8')); }
catch { writeJson(response, 400, {...}); return; }

const validation = validateKql(payload.csl, endpoint);   // ← line 358
```

The `try/catch` wraps only `JSON.parse`. A body of the literal four bytes `null` **parses successfully** to `null`, then line 358 evaluates `null.csl`. The handler is `async` (line 298), so this becomes an unhandled promise rejection. Node ≥15 terminates the process on unhandled rejections by default. There is no `process.on('unhandledRejection')`, no `uncaughtException` handler, no `server.on('clientError')`, and no try/catch around the handler body anywhere in the file.

**I confirmed this empirically** by running `createGatewayServer()` on a scratch port and POSTing `null` to `/v1/rest/query`:

```
UNHANDLED REJECTION: TypeError Cannot read properties of null (reading 'csl')
```

`restart: unless-stopped` (`compose.yaml:77`) turns a single curl into a restart loop if repeated. Any student with a terminal — and every one of them has one open for the tunnel — can do this in one line, accidentally or not.

**Fix is two lines:** guard the handler body in try/catch and add the two `process.on` handlers. This is the single highest-value change in the repository.

---

### 🟠 HIGH

#### H1. The gateway's read-only guarantee has three structural bypasses

The policy boundary is genuinely thoughtfully built — `splitTopLevelStatements` (`server.mjs:20-97`) is a real quote-and-comment-aware lexer, not a naive `split(';')`, and `trimLeadingComments` (`:99-120`) closes the comment-hiding trick with a regression test at `server.test.mjs:34-37`. `getEndpoint` (`:250-268`) is a fail-closed exact-match allowlist of four routes. That is a better starting point than most.

But three gaps let a determined student through:

**H1a — Validate-one-thing, forward-another.** Line 364 forwards the **original raw bytes**, not a re-serialization of what was validated. The gateway's view of `csl` comes from V8's `JSON.parse`; Kustainer's comes from .NET. Newtonsoft matches members case-insensitively with last-wins on duplicates. A body like `{"csl":".show tables","Csl":".drop table SecurityIncident"}` may read as `.show tables` in the gateway and as the `.drop` downstream. Any parser disagreement — duplicate keys, key casing, `\uXXXX`-escaped key names, BOM, trailing content — is a full policy bypass. **Fix: build `JSON.stringify({db, csl, properties})` from the validated fields and forward that.**

**H1b — "Does not start with a dot" ≠ read-only.** `validateKql` at `:151-158` only rejects statements whose first token is a management verb. KQL *query* language has egress and code-execution primitives that never start with `.`:

| Primitive | Effect |
| --- | --- |
| `externaldata (x:string) ["http://169.254.169.254/..."]` | Arbitrary outbound HTTP from the container — SSRF, IMDS probing, exfil channel |
| `evaluate http_request` / `http_request_post` | Outbound requests with attacker-supplied targets |
| `evaluate sql_request` / `mysql_request` / `cosmosdb_sql_request` | Outbound DB connections with attacker-supplied connection strings |
| `evaluate python(...)` / `R(...)` | Sandbox plugin code execution where enabled |
| `cluster('other.kusto.windows.net').database('x')` | Lateral pivot using the cluster's own identity — directly relevant to the ADX path |

Related: **`payload.db` is never inspected** (`:358`). A student can target `$systemdb`, `KustoMonitoringPersistentDatabase`, or any other database. There is no database allowlist.

**H1c — Lexer parity trick hides a statement inside a "string".** `:47-65` toggles quote state on every `'`/`"` and models `''`/`""` doubling, but **not** backslash escapes and **not** `@`-verbatim strings. Kusto's non-verbatim strings accept `\"`. Given `print x = "\""; .drop table T`:

- Kusto reads: string is `"`, then `;`, then a second statement.
- Gateway reads: `"` opens → `\` ignored → `"` closes → `"` **re-opens** → the `;` and `.drop` are now "inside a string" → one statement starting with `print` → **allowed**, and the raw body is forwarded.

The reverse error (over-splitting) fails closed, which is fine. This direction does not.

**Recommended mitigations, in order of value per line of code:**

1. Re-serialize the forwarded body (kills H1a).
2. Force `Options.request_readonly = true` and `query_language = 'kql'` server-side; reject any client-supplied `Options` key you have not allowlisted. `payload.properties` is currently forwarded untouched, so a student can also set `notruncation: true` and an unbounded `servertimeout`.
3. Add a `KUSTO_ALLOWED_DATABASES` env check against `payload.db`.
4. Case-insensitive deny-scan for `externaldata`, `evaluate <plugin>`, `cluster(`, `http_request`, `sql_request`. On the ADX path, also set `allowedFqdnList` on the cluster so the block is platform-enforced rather than proxy-enforced.
5. Handle `\` escapes and `@"..."` in the lexer — or simply reject any `csl` with unbalanced quotes outright.

> **Question for you:** Is `request_readonly: true` deliberately not forced? Setting it would shrink H1b dramatically in one line. Was it omitted because Kustainer does not honor it?

#### H2. No rate limiting, no concurrency cap, one shared credential

Nothing in `server.mjs` limits requests per client, in-flight requests, or query cost. One `range i from 1 to 10000000000 step 1 | ...` wedges the shared 4-CPU / 24 GiB Kustainer for the entire classroom. Because all students share one Service Token, there is no attribution and no way to revoke a single abuser mid-class — you can only rotate for everyone.

A token bucket plus an in-flight cap (5 concurrent, N/min per source) plus a `servertimeout` clamp is maybe 40 lines and removes the whole class of "one student accidentally DoS'd the lab" incidents.

#### H3. `.show` is blanket-allowed on the management endpoint

`server.mjs:141` permits any single statement whose first verb is `show`. `.show` is read-only with respect to *data* but not with respect to *secrets and privacy*:

`.show cluster principals` · `.show database principals` · `.show queries` and `.show commands-and-queries` (other students' query text) · `.show journal` (full command history) · `.show ingestion failures` (can echo SAS/URI fragments) · `.show external tables` (connection targets) · `.show cluster identity`

On the managed ADX path this discloses real tenant principals. Replace the single-verb check with an explicit subcommand allowlist: `.show tables`, `.show table ... schema`, `.show databases`, `.show functions`, `.show version`.

> **Question:** Was `.show` intended as a blanket allow, or as "safe metadata reads"? `.show queries` and `.show tables` are different classes of thing.

#### H4. `Test-WorkshopPackage.ps1` cannot pass on a clean clone, and is not in CI

`scripts/Test-WorkshopPackage.ps1:153-190` requires ten `sample/*-Real.csv` files and calls `Add-TestError` when they are absent. `.gitignore:3` excludes `sample/*.csv` **by design**. So the repository's broadest validator — 611 lines — fails immediately for anyone who is not you, on the very first clone, and the CI workflow never invokes it. A gate that only one machine can run is not a gate.

**Suggestion:** put the `-Real.csv` header checks behind a `-WithRealSamples` switch so the other ~420 lines can run in CI.

#### H5. Parallel generation is not deterministic, contrary to its own documentation

`scripts/New-SyntheticTelemetryParallel.ps1:12-15` claims *"every table produces identical rows regardless of which worker handled it."* That holds for the RNG (`New-SyntheticTelemetry.ps1:6270-6274` reseeds per table from `RandomSeed -bxor tableSeed`) but **not for timestamps**:

- `New-SyntheticTelemetry.ps1:43` — `[datetime]$TelemetryEndTime = (Get-Date).ToUniversalTime()`
- `:1895-1899` — `New-WorkshopNormalTime` anchors every ambient row to `$script:TelemetryEndTime`
- `New-SyntheticTelemetryParallel.ps1:188-199` — the worker argument list **omits `-TelemetryEndTime`**

Workers launch at staggered times, so each process anchors to a different "now". Tables from later workers are shifted relative to earlier ones, and reruns are not reproducible. **One-line fix:** capture `$TelemetryEndTime` once in the driver and pass it to every worker.

Related: the parallel path uses a flat `-RowsPerTable 8000` while the single-process path randomizes between `NormalMinRowsPerTable 5000` and `NormalMaxRowsPerTable 10000`, so the two paths produce different row counts for the same seed.

#### H6. Parallel generation silently discards `data/scenario-summary.json`

`New-SyntheticTelemetryParallel.ps1:194` sends each worker's `-SummaryPath` to `$logRoot\summary-N.json`; `:266` deletes `$logRoot` on success. Nothing merges them and nothing writes `data/scenario-summary.json` — which `.gitignore:21-23` explicitly keeps *tracked* because "it documents the scenario". Anyone who regenerates via the parallel path leaves a stale tracked summary behind. The single-process path (`:2460-2461, 8135`) does write it.

#### H7. Live tenant identifiers hardcoded in script and Terraform bodies

Not secrets, but live environment identifiers as constants with no parameter override, in a repository whose entire CI theme is keeping tenant identifiers out of a public repo (`telemetry-safety.yml:3-8`) and whose `Test-FieldProfileSafety.ps1` explicitly hunts subscription GUIDs in *other* files:

| Location | Value |
| --- | --- |
| `azure-data-explorer/restore-cyber-defend-database.ps1:11-18` | subscription GUID, two cluster URIs, storage account name, UAMI object ID |
| `infra/cloudflare-adx/variables.tf:4` | `cloudflare_account_id` default = live account ID |
| `infra/cloudflare-adx/variables.tf:16` | `zone_name` default = `tier1-cyberdefense.ai` |
| `azure-data-explorer/backup-storage-private-endpoint.bicep:5` | live subscription GUID as a parameter default |
| `azure-data-explorer/README.md:7-8, 19-21, 74-77` | tenant ID, subscription IDs, UAMI object ID |
| `scripts/Export-WorkshopTelemetryProfiles.ps1:46` | `$WorkspaceId = '7e9298ab-...'` as a parameter default |
| `scripts/Copy-StudentAdxToLocalKusto.ps1:24-26` | cluster/database defaults |

> **Question:** Is this repository public (`github.com/dcodev1702/Cyber-Defense-Workshop-ADX` is referenced in `IaC-CFT-TF-Setup.md:16`)? If so, is this consistent with the bar the telemetry-safety workflow enforces? A `terraform.tfvars` / `.env` pattern with no defaults would close it without changing behavior for you.

#### H8. Flat Compose network + dashboard-managed ingress = one click from full bypass

`compose.yaml:117-122` puts `cloudflared`, `kusto-readonly-gateway`, and `kusto` on a single `adx-internal` network. `infra/cloudflare-adx/main.tf:33` sets `config_src = "cloudflare"`, meaning the ingress rule that enforces "students hit the gateway, never Kustainer" lives in a **dashboard, outside version control and outside review**.

Changing the ingress service from `tcp://kusto-readonly-gateway:8081` to `tcp://kusto:8080` — a dashboard edit, a Terraform drift, an account compromise — routes students straight to an unauthenticated Kustainer with full management rights.

**Two networks make that architecturally impossible:** `edge` (cloudflared + gateway) and `backend` (gateway + kusto). Then `cloudflared` cannot reach `kusto:8080` no matter what the ingress says.

> **Question:** Is `config_src = "cloudflare"` deliberate, and is anything watching it for drift? Also, why `tcp://` rather than `http://` ingress? HTTP mode would let you use Cloudflare's WAF and rate-limiting rules, and would let the gateway see `Cf-Access-Jwt-Assertion`.

#### H9. Plaintext passwords and TAP values persist in the working tree

`scripts/New-WorkshopStudents.ps1`:
- `:29` — `[string]$InitialPassword`, so it lands in `Get-History`, the PSReadLine history file, and any transcript. Should be `[SecureString]`.
- `:114-115` — password and TAP added to every roster row.
- `:122` — `Export-Csv` to `..\students\students.csv` with no ACL restriction.

`.gitignore` covers `students/*.csv`, so this is not a *commit* risk. But 20 live Entra credentials sit unprotected on disk indefinitely; `Grant-StudentAdxAccess.ps1:49` re-reads that same file, and nothing ever deletes or expires it. `docs/student_access.md:65` says "delete it after the event" — the advice exists, the automation does not.

> **Question:** Would a `Remove-WorkshopStudents.ps1` that deletes the Entra users *and* shreds the CSV be worth adding? It would pair naturally with the existing `-RotateStudentCredential` flag.

#### H10. Service token secret passed as a command-line argument

`scripts/Start-StudentAdxProxy.ps1:62-66` passes `--service-token-secret $ServiceTokenSecret` to `cloudflared`. Command-line arguments are visible in the process table to any local user (`ps`, Task Manager details, `Get-CimInstance Win32_Process`). `cloudflared` accepts `TUNNEL_SERVICE_TOKEN_SECRET` as an environment variable — and the script **already reads that env var at `:43`**, so it could simply set it and drop the flag. `:14` also types it `[string]` rather than `[SecureString]`.

This runs on *student* machines, which is exactly where you have the least control over who else is logged in.

*(This is the one place the shared credential is mentioned. Per your instruction, the credential itself and its presence in the student guide are treated as intentional and correct — this finding is purely about the local process-table exposure on student laptops, which is independent of that decision.)*

#### H11. Two data-integrity problems in the metadata layer

**`sample/20260724T000000Z/_export-summary.json` has been clobbered.** The directory holds 68 table exports and 68 matching profiles — a clean 1:1. The summary that is supposed to describe them reads `"tableCount": 1, "exportedCount": 0`, with a single `ExposureGraphEdges` row at `"Status": "Error"` and an HttpClient 300-second timeout. Its `capturedUtc` (07-25T06:18) is *later* than the per-table values (07-25T02:28), confirming a one-table retry overwrote the full-run manifest rather than merging.

**`IdentityInfo` schema and profile describe two different tables that share a name.** `schemas/IdentityInfo.schema.json` uses Defender XDR advanced-hunting naming (`AccountUpn`, `CloudSid`, `OnPremSid`, `CriticalityLevel`, `PrivilegedEntraPimRoles`) and the manifest cites the defender-xdr doc URL. `metadata/field-profiles/IdentityInfo.profile.json` uses Sentinel/UEBA naming (`AccountUPN`, `AccountCloudSID`, `AccountSID`, `InvestigationPriority`, `IsMFARegistered`, `IsServiceAccount`). Only ~32 of 46/56 columns overlap, and the differences are casing-variant duplicates of the same concept.

In a teaching workshop this is the worst failure mode available: students learn column names that do not match the documentation the manifest cites, and `docs/threat-actor-midnight-blizzard.md:93` explicitly tells them to "hunt `IdentityInfo` for stale enabled accounts."

> **Question:** Is the workshop teaching the Defender XDR table or the Sentinel UEBA table? Which wins, and should the loser become a separately-named table?

#### H12. 32 of 69 profiles cite provenance CSVs that no longer exist

Every profile carries `sources: ["sample:<file>.csv"]`, but 32 of those files are absent from `sample/`. Examples: `AADGraphActivityLogs-RealTelemetry.csv`, `EmailEvents-RealTelemetry.csv`, `SecurityEvent-RealTelemetry.csv`, `ThreatIntelIndicators-RealTelemetry.csv`, `StorageBlobLogs.csv`, `IntuneDevices.csv`. Because `sample/` is gitignored (correctly), the provenance chain for nearly half the tracked profiles is unverifiable and unreproducible by anyone but you.

Special case: `DeviceTvmInfoGathering.profile.json` cites `DeviceTvmInfoGathering-RealTelemetry.csv`, but what is on disk is the typo'd `sample/DeviceTVMInfoGrathering-Real.csv` — and `scripts/Test-WorkshopPackage.ps1:156` hardcodes that same typo'd path. Three simultaneous spellings for one table, one of them load-bearing in a validator.

**Suggestion:** record a content hash + capture date in `sources` instead of a path that will never resolve. Then publish the dated export to blob/Azure Files and record the URI.

#### H13. `sample/New query (7).csv` and `(8).csv` are not junk — they are load-bearing

They are the recorded `sources` for `DeviceFileEvents.profile.json` and `DeviceLogonEvents.profile.json` respectively — while the correctly-named `sample/DeviceFileEvents.csv` and `sample/DeviceLogonEvents.csv` sit on disk **unreferenced**.

Anyone tidying up the obvious junk filenames would silently orphan two profiles and leave two stale CSVs looking authoritative. Flagging this specifically because "delete the files called `New query (7).csv`" is exactly the kind of cleanup that looks free and is not.

> **Question:** Were those hand-run KQL exports that superseded the properly-named files, or accidental captures the profiler picked up? Are the `DeviceFileEvents` / `DeviceLogonEvents` profiles built from the data you intended?

---

### 🟡 MEDIUM

#### M1. `Join-Path` with embedded backslashes — 57 occurrences across 25 of 31 scripts

`Join-Path $PSScriptRoot '..\schemas'` returns `/repo/scripts/..\schemas` on Linux — a literal backslash in the filename, so `Test-Path` fails. I counted **57 occurrences** of the `Join-Path … '..\…'` pattern across `scripts/`, `tools/`, and `adx_db_backupNrestore/`. Heaviest: `New-SyntheticTelemetry.ps1` ×7, `Backup-LocalKustoSnapshot.ps1` ×6, `Start-CloudflareAdxTunnel.ps1` ×6, `Import-GeneratedDataToKustainer.ps1` ×3, `Test-SyntheticDataQuality.ps1` ×3.

This matters concretely: CI runs on `ubuntu-latest`. The reason it passes today is that the *only* script CI invokes is `Test-FieldProfileSafety.ps1`, whose line 30 is the one place in the entire repo that gets it right:

```powershell
[string]$ProfileDirectory = (Join-Path $PSScriptRoot '..' 'metadata' 'field-profiles')
```

The correct idiom is already known here — it just was not applied anywhere else. **Any attempt to add another gate to CI will fail on path resolution, not on logic.** Fixing this is mechanical and unblocks §4.

#### M2. ~400 lines of module-shaped code living outside the module

`AdxWorkshop.Common.psm1` exports 6 functions in 340 lines. Duplicated elsewhere:

| Logic | Canonical | Copies |
| --- | --- | --- |
| Kusto response rows → objects | `AdxWorkshop.Common.psm1:307` | `Copy-StudentAdxToLocalKusto.ps1:136`; `azure-data-explorer/restore-cyber-defend-database.ps1:73` |
| SecureString → plaintext token | `AdxWorkshop.Common.psm1:23` | `restore-cyber-defend-database.ps1:22` (byte-for-byte identical BSTR dance) |
| Schema type → Kusto type | — | `Import-GeneratedDataToKustainer.ps1:44` and `Restore-LocalKustoSnapshot.ps1:96`, both named `ConvertTo-KustoType`, same 11 cases |
| `h@'...'` obfuscated literal | — | `Backup-AdxDatabase.ps1:105` and `Restore-AdxDatabaseBackup.ps1:45`, identical |
| Async operation poll-to-completion | — | `Backup-AdxDatabase.ps1:126-184` and `Restore-AdxDatabaseBackup.ps1:51-103` — ~130 duplicated lines, same seven terminal-state switch arms |
| `az` invoke + JSON-prefix scrape | — | `Backup-AdxDatabase.ps1:56`; `Initialize-AdxBackupStorage.ps1:52,99` |
| NDJSON line counting | — | five hand-rolled `StreamReader` loops |

#### M3. The module lacks timeouts and retries at the exact chokepoint

`AdxWorkshop.Common.psm1:278-305` `Invoke-WorkshopAdxManagementCommand`:

- `:304` — `Invoke-RestMethod` with **no `-TimeoutSec`**, no retry. A hung ADX connection hangs the script indefinitely. The `servertimeout` at `:294` is a server-side hint and does not bound the HTTP client. Ironically, `Copy-StudentAdxToLocalKusto.ps1:104` and `Restore-LocalKustoSnapshot.ps1:93` — which *bypass* the module — do set `-TimeoutSec`.
- `:287` — a fresh token on **every call**. `Import-SyntheticTelemetry.ps1:82-88` batches 500 rows, so a 32,000-row `DeviceProcessEvents` ingest triggers 64 token acquisitions.
- No transient-error retry. An ADX 429/503 during ingest fails the whole run.

The only correct retry logic in the repo is `Export-TenantTelemetrySamples.ps1:293-300`, which honors `Retry-After` on Graph 429s. Lift that into the module.

**Adding `-TimeoutSec 300 -MaximumRetryCount 3 -RetryIntervalSec 5` to line 304 is the single highest-leverage robustness change in the PowerShell layer.**

#### M4. `Get-WorkshopAdxAccessToken` ignores the CLI exit code

`AdxWorkshop.Common.psm1:69-74` runs `az account get-access-token ... 2>$null` and never checks `$LASTEXITCODE`. Garbage stdout would be returned as a bearer token, producing a confusing 401 far downstream instead of a clear "run az login". `Copy-StudentAdxToLocalKusto.ps1:53` and `Export-WorkshopTelemetryProfiles.ps1:104` both check it — the module is again the weakest version.

#### M5. No `SupportsShouldProcess` anywhere in 31 files

Zero occurrences, yet these scripts drop ADX databases (`Initialize-Workshop.ps1:129`), drop tables (`Initialize-AdxTables.ps1:72`), clear table data (`Import-SyntheticTelemetry.ps1:79`), `docker rm --force` (`Restore-LocalKustoSnapshot.ps1:117`), and `Remove-Item -Recurse -Force` (`Copy-StudentAdxToLocalKusto.ps1:301`). `-WhatIf` / `-Confirm` on the destructive six costs one attribute and one `if ($PSCmdlet.ShouldProcess(...))` each.

#### M6. Non-idempotent surprise: silent database renaming

`Initialize-Workshop.ps1:141-152` — if the target database exists and `-OverwriteDatabase` was not passed, the script invents `${DatabaseName}_20260726143000` and deploys *there* instead. It reports the rename at `:150` and `:267`, but a rerun of the "same" command produces a different database every time, and stale timestamped databases accumulate on the cluster with a 365-day hot cache (`:37`). Failing with a clear message is safer than silently succeeding against the wrong target.

#### M7. Bicep: security posture and one ordering bug

`azure-data-explorer/adx-dev-cluster.bicep`:
- `:18` `enablePublicNetworkAccess: true` with no IP allowlist and no private endpoint
- `:16-17` `enableDiskEncryption: false`, `enableDoubleEncryption: false` — will flag in Defender for Cloud / CIS
- `:19` `enablePurge: true` — hands irreversible `.purge` to anyone with database-admin, on a cluster holding tenant-derived data
- No `managedIdentities` block, though `azure-data-explorer/README.md:74-77` says the cluster uses `uami-adx-backup` — the identity assignment lives outside IaC
- **No `diagnosticSettings`** → no audit trail of student queries. That is both a governance gap and a missed lab exercise, in a workshop about telemetry
- No `allowedFqdnList` / `trustedExternalTenants` — this is the supported platform-level way to shut down the `externaldata` egress in H1b
- `:27` `output clusterResourceId = resourceId(...)` reconstructs the ID by hand instead of `cluster.outputs.resourceId`; it creates no implicit dependency
- No `@description`, `@allowed`, or length constraints on any parameter; `location` defaults to a literal `'northeurope'` rather than `resourceGroup().location`

`azure-data-explorer/cyber-defend-database.bicep`:
- `:9-11` child resource declared as `'${clusterName}/${databaseName}'` with **no `parent:` and no `dependsOn`** on an `existing` cluster reference — nothing orders this after the cluster module, so a combined deployment can race. Same pattern in `backup-storage-private-endpoint.bicep:9`.
- `:6-7` `hotCachePeriod` == `softDeletePeriod` == `P365D` on a `Dev(No SLA)_Standard_D11_v2` pins 100% of data to one small SSD node. Fine at 624k rows; a trap if it grows.
- The database name `cyber-defend-usagwsbdn-cys26` contains hyphens, forcing students into `database("...")` bracket syntax in every cross-database query.

`backup-storage-private-endpoint.bicep`: only the `dfs` group is created; ADX export/ingest paths frequently also need `blob`.

#### M8. Dockerfile runs as root on an unpinned base

`tools/kusto-readonly-gateway/Dockerfile` is 7 lines. `FROM node:24-alpine` is a moving tag, not digest-pinned. **No `USER node`** — so the internet-facing policy boundary runs as UID 0, and the same image runs `remove-netdefaultdb.mjs` with a read-write bind mount of `./data/local-kusto` (`compose.yaml:66-69`) doing a root `rm -rf`. Also missing: `HEALTHCHECK`, `ENV NODE_ENV=production`, `--init`/tini (node is PID 1 and ignores SIGTERM → 10s stall then SIGKILL on every `docker compose down`), `.dockerignore`, and a lockfile.

#### M9. Hook and CI do not enforce the same rules — in both directions

| Rule | `.githooks/pre-commit` | `telemetry-safety.yml` |
| --- | --- | --- |
| anything under `sample/` | blocked (`:18`) | **only `sample/*.csv`** (`:33`) |
| `students/*.csv` (gitignore says these hold *passwords or TAP values*) | **not checked** | checked (`:33`) |
| `samples/*.csv` | not checked | checked (`:33`) |
| `data/generated` tracked | **not checked** | checked (`:46`) |
| field-profile scan | only when a profile is staged (`:30-33`) | always |

The `students/` gap in the hook is the one that matters most given what that directory contains. Separately, `Test-FieldProfileSafety.ps1` scans the **working tree**, not the staged blobs — so `git add` followed by an edit passes the hook with different content than gets committed.

**Suggestion:** have both call one `scripts/Test-RepositorySafety.ps1` so parity is structural rather than maintained by hand.

#### M10. `compose.yaml` pins Kustainer to `:latest`

`:5` `mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest`, while `cloudflared` is correctly pinned to `2026.7.2` (`:100`). A workshop's reproducibility depends on the emulator version; `latest` can change between rehearsal and delivery. Also absent everywhere: `security_opt: ["no-new-privileges:true"]`, `cap_drop: [ALL]`, `read_only:` rootfs, `user:`, and log size limits. `cpus`/`pids_limit` are set only for `kusto` (`:17-20`).

`:108-110` `env_file: required: false` means a missing `cloudflared.env` starts the connector token-less and crash-loops under `restart: unless-stopped` rather than failing loudly.

Documented-but-not-set: `KUSTO_MAX_BODY_BYTES` is described as compose-configured in `tools/kusto-readonly-gateway/README.md:53-59` but does not appear in `compose.yaml`.

#### M11. Two incompatible artifact formats share the `*.profile.json` name

`metadata/field-profiles/` and `sample/20260724T000000Z/_field-profiles/` are **not** duplicates and not diverged copies — different schemas from different producers:

| | `metadata/field-profiles/` | `sample/.../_field-profiles/` |
| --- | --- | --- |
| keys | `sources`, `sampledRows`, `emptyInProd`, `generatedUtc` | `liveTableName`, `source`, `capturedUtc`, `lookbackDays`, `rowCount` |
| `columns` | object/map | array |
| per-column | `fillRate`, `pattern`, `sensitive`, `minLength` | `observedTypes`, `nullCount`, `nullRate`, `emptyCount` |
| `topValues` | `{value, weight}` | `{value, count}` |
| producer | `Export-WorkshopTelemetryProfiles.ps1` | `Export-TenantTelemetrySamples.ps1` |

Source of truth is unambiguously `metadata/field-profiles/` — `.gitignore:19-22` names it as the generator input, and it is tracked, redacted, and newer. But the shared suffix invites exactly the wrong conclusion. **Rename the second to `*.columnstats.json`, or move it to `_column-stats/`, and add a `"kind"` discriminator to both.**

#### M12. The coverage funnel narrows silently: 79 → 69 → 68

- 79 manifest entries ≡ 79 schema files, **set-equal in both directions, zero orphans** (verified). That reconciliation is excellent and CI already enforces it.
- 69 field profiles. Ten schemas have none: `AADProvisioningLogs`, `AADRiskyServicePrincipals`, `AADServicePrincipalRiskEvents`, `DeviceBaselineComplianceAssessment`, `DeviceBaselineComplianceProfiles`, `DeviceTvmBrowserExtensions`, `EmailPostDeliveryEvents`, `ExposureGraphNodes`, `IdentityEvents`, `OAuthAppInfo`.
- 68 tables in the dated export.

`CHANGELOG.md:33` explains the 10 are Learn-schema-driven, which is fine. But nothing in the *data* records that — it is inferred from missing files. Note that `OAuthAppInfo` and `EmailPostDeliveryEvents` are scenario-central: `docs/workshop_design.md:29` lists `OAuthAppInfo` as an Act 5 correlation table, and it is the natural pivot for the OAuth consent vector.

Also: `metadata/field-profiles/` has `ExposureGraphEdges` but not `Nodes`; the dated export has `Nodes` but not `Edges` (the clobbered summary in H11 shows `Edges` timing out). **Neither location has both.**

**Suggestion:** add `"generated": true|false` and `"omissionReason"` to each manifest entry so the funnel is declared rather than inferred.

#### M13. 28 of 69 schema/profile pairs disagree on column count, in both directions

Some deltas are benign (`AlertInfo` 8→12 is just `TenantId`/`TimeGenerated`/`Type`/`SourceSystem`). Others are not: `DeviceFileEvents` schema has 59 columns, profile has 47 — **no distribution for 14+ documented columns** including `FileOriginIP`, `FileOriginUrl`, `PreviousFileName`, `RequestAccountName`, `RequestSourceIP`, `AdditionalFields`. Whatever the generator emits for those is unprofiled. Similar gaps in `AADUserRiskEvents` (27→25), `IdentityAccountInfo` (49→47), `MicrosoftGraphActivityLogs` (35→33).

#### M14. Two dashboards, two schema versions, 40 hand-maintained queries each

`dashboards/cyber-defense-workshop-dashboard.json` and `STUDENT-GUIDES/dashboard-CYBER-DEFEND-V4.json` are the same dashboard at two schema versions. Identical 5 pages (same names, same order), identical 40 tiles, and all 32 query-bearing tiles have **byte-identical query text** after whitespace normalization. Same `dataSources` GUID, same cluster/database. They differ in title, `schema_version` (**20** vs **76**), and container shape — V4 uses the newer portal format with top-level `queries[]` + `baseQueries[]` + `embeddedApps[]`, while `dashboards/` inlines per tile.

No staleness today. But two hand-maintained copies of 40 KQL queries will drift on the next edit, and only V4 imports cleanly into a current ADX portal. `README.md:284` already declares V4 authoritative and the other "kept for reference only" — good, but the file is still a live editable copy.

**Genuine strength worth locking in:** `dashboards/cyber-defense-workshop-dashboard.kql` has 40 `// Tile:` sections and the JSON has 40 tiles, with **identical title sets and zero drift**. Add that parity check to CI before it rots.

> **Question:** Is `scripts/New-WorkshopDashboard.ps1` the generator for either JSON? If so, one of the two should be a build output, not checked-in source.

---

### 🟢 LOW

**L1 — README contradicts itself on row count.** `README.md:362` footer says **~629K rows**; `README.md:318`, `STUDENT-LAB-SETUP-GUIDE.md:265, 270, 299`, and `CHANGELOG.md:9` all say **~624,000 / 623,832**. `CHANGELOG.md:15` records the correction from 629,000 → 624,000 — the footer was missed.

**L2 — Class size disagrees across three documents.** `README.md:21` says **20 - 40 students**; `docs/diagrams.md:7` and `IaC-CFT-TF-Setup.md:185` say **5 to 100**. `CHANGELOG.md:38` records the 5-100 change; the README was missed.

**L3 — Stale "48 table snapshot" note in the instructor answer key, in three places.** `docs/instructor_answer_key.kql:27` (*"The 48 table local snapshot predates the email, SecurityEvent, cloud, and exposure tables"*), `:291` (*"If SecurityEvent returns nothing at all, the environment is the older 48 table…"*), and `:520` in the facilitation checklist (*"The 48 table local snapshot predates SecurityEvent. Use IdentityQueryEvents instead…"*). The package is 79 tables everywhere else, and `CHANGELOG.md:5` records the 48-table export as the *defect* that was fixed. All three will send you down a dead end mid-class — the `:520` one especially, because it tells you to change what you teach.

**L4 — Duplicated validation step.** `IaC-CFT-TF-Setup.md:255-265` — validation steps 1 and 2 are the same command with different framing ("Confirm Kusto answers locally before testing the tunnel" / "On the instructor host, confirm Kusto answers locally").

**L5 — README lists `.set` as blocked; the tested verb is `.set-or-append`.** `README.md:249` vs `server.test.mjs:17-22`. Both are blocked in practice (any `.`-prefixed verb on `/query`), but the doc and the test do not name the same thing.

**L6 — "screenshot attack vectors" is unexplained jargon.** Appears in `README.md:65` and `docs/workshop_design.md:17` ("the required screenshot attack vectors"). A reader who was not in the requirements conversation cannot parse it. Suggest "the required attack vectors" or naming the source requirement.

**L7 — No `.gitattributes`.** With a `/bin/sh` hook (`.githooks/pre-commit`) authored on Windows, a CRLF checkout breaks it with `bad interpreter` on WSL/macOS/Linux. Recommend `* text=auto`, `*.sh text eol=lf`, `.githooks/* text eol=lf`, and `*.ps1 text eol=crlf`. *(Note: when I read the Windows checkout from a Linux sandbox, git reported all 229 tracked text files as modified with 86,837 insertions and 86,837 deletions, and `git diff --ignore-all-space` returned empty — a pure line-ending diff. That specific symptom is a cross-platform-tooling artifact, not something wrong in your checkout, but it is exactly what `.gitattributes` exists to prevent.)*

**L8 — Dead script targeting a directory that does not exist.** `scripts/New-WorkshopDeck.ps1:22` defaults `-OutputPath` to `..\workshop\CyberDefenseKqlWorkshop.pptx` and `:32` falls back to `workshop\slide_deck_outline.md`. There is no `workshop/` directory. It also uses PowerPoint COM (`:29`) with no `Marshal.ReleaseComObject` and no `finally`, so a mid-script failure orphans a visible `POWERPNT.EXE` (`:35` sets `Visible = $true`).

**L9 — Unapproved verb.** `Start-CloudflareAdxTunnel.ps1:194` `Prepare-ComposeContainerMigration`. Everything else in the repo uses approved verbs; PSScriptAnalyzer would flag exactly this one file. `Initialize-` or `Confirm-` fits.

**L10 — `#Requires -Version 7` on only 7 of 31 files.** Missing from files that clearly need it. `New-SyntheticTelemetryParallel.ps1:60-62` hand-rolls the check instead. `Install-WorkshopGitHooks.ps1:57` uses `$IsWindows` — a PS6+ automatic variable that, under `Set-StrictMode -Version Latest` on Windows PowerShell 5.1, throws "variable not set" rather than a clean version error.

**L11 — Inconsistent failure signalling.** Most scripts `throw`; `Test-FieldProfileSafety.ps1:39/95/101`, `Test-SyntheticDataQuality.ps1:212`, `Test-WorkshopIdentityInvariants.ps1:100`, `Import-GeneratedDataToKustainer.ps1:147`, `Restore-LocalKustoSnapshot.ps1:261` use `exit 0/1`. The last one calls `exit 1` from inside a `try` with a `finally` — the `finally` still runs, but it deserves a comment. Suggest one documented convention: `throw` for library-ish scripts, `exit` only for CI gates.

**L12 — Missing preflight for a cmdlet that is used.** `New-WorkshopStudents.ps1:47` preflights five Graph cmdlets but `:75` calls `Get-MgUser`, which is not in the list. If `Microsoft.Graph.Users` is absent the script passes preflight and fails mid-loop, *after* creating the group at `:63`.

**L13 — `Compress-Archive` for a multi-GB payload.** `Backup-LocalKustoSnapshot.ps1:167`. Memory-hungry, historically >2 GB issues. `System.IO.Compression.ZipFile::CreateFromDirectory` is already `Add-Type`'d on the restore side (`Restore-LocalKustoSnapshot.ps1:69`), so it would also be the consistent choice.

**L14 — Unfriendly first-failure message.** `Backup-LocalKustoSnapshot.ps1:47` calls `Get-ChildItem -LiteralPath $databaseRoot -Directory` with no `-ErrorAction SilentlyContinue`, so a missing `data\local-kusto\dbs` throws a raw `ItemNotFoundException` instead of the curated message prepared at `:52`.

**L15 — Fragile HTML scraping with no pinning.** `tools/Build-SchemasFromMicrosoftLearn.ps1:63-127` parses Learn tables with `[regex]::Matches($Html, '<table.*?>.*?</table>')`. It degrades gracefully (`:57` warns and defaults to `string`) and `:172` skips existing files unless `-Force` — both good — but no content hash or "last verified" date, so a Learn restructure silently changes generated schemas.

**L16 — `remove-netdefaultdb.mjs` hardening.** `:8` `stateRoot` is not validated the way database names are at `:10-14`; `KUSTO_STATE_ROOT=/` would `rm -rf /dbs/NetDefaultDB`. `:56` `setInterval(check, 2000)` can overlap because `fetch` has no `AbortSignal`. The `rm` at `:43` runs unconditionally every 2s forever, long after the directory is gone. Zero tests — including on the regex guarding a `.drop database` interpolation.

**L17 — Ping route reads no body.** `server.mjs:326` forwards `Buffer.alloc(0)` with `content-length: 0` while leaving the client's body unconsumed on the socket. Not exploitable with Node's parser, but it is a proxy-desync smell and means `maximumBodyBytes` does not apply to `/v1/rest/ping`.

**L18 — CORS is not a control here, and the docs slightly imply otherwise.** `tools/kusto-readonly-gateway/README.md:34-49` foregrounds the origin allowlist, but students connect via `cloudflared access tcp` and speak raw HTTP — `curl`, Kusto.Cli, and the Python SDK all ignore CORS. It is a browser-UX feature only. Separately, `Access-Control-Allow-Credentials: true` (`server.mjs:179`) plus verbatim reflection of `Access-Control-Request-Headers` (`:190-194`) is loose, and there is no `Access-Control-Max-Age`, so every ADX query pays a preflight round-trip through the tunnel.

**L19 — No audit logging in the gateway.** One startup line (`server.mjs:372`) and nothing else. No request log, no record of blocked commands, no request ID. In a *cyber-defense* workshop this is both an operational gap and a missed teaching artifact — "here is the telemetry the thing you just attacked produced" is a free extra exercise.

**L20 — Naming chaos in `sample/`.** Four conventions across 46 CSVs: bare `Table.csv` (~20), `-Real.csv` (~12), `-RealTelemetry.csv` (~5), portal exports (`export-tvm-machine-software-inventory-*.csv`, 2, unreferenced), `New query (N).csv` (2). Six tables exist in two variants simultaneously with only one of each cited. `AADRiskUserEvents.csv` is a transposition of table `AADUserRiskEvents` — and that typo is now baked into `sample/_export-summary.csv` **and** `metadata/field-profiles/AADUserRiskEvents.profile.json`, so renaming breaks both. `sample/_export-summary.csv` is itself stale: 47 rows for a 79-table manifest, one row pointing at a file that no longer exists.

**L21 — `data/scenario-summary.json` casing and vocabulary.** Coherent and well-dated (7-day lookback, consistent `Offset` minutes, every table it names is in the manifest). Two snags: it uses `"Title"`/`"Technique"`/`"Offset"` PascalCase inside arrays while every sibling key is camelCase, and `metadata/mitre-attack-mapping.json` models the same attack chain with camelCase `attackVector`/`techniqueId`/`scenarioMinute`. Two files, one chain, two vocabularies, no join key.

**L22 — `summary` present on 31 of 79 schemas** with no visible rule (`AADRiskyUsers` has one, `AADUserRiskEvents` does not). And 20 of 2,997 columns lack a description — 0.7%, which is very good — all clustered in three files: `SigninLogs.schema.json` (15, including `TimeGenerated`, `RiskLevel`, `AppliedConditionalAccessPolicies`), `AuditLogs.schema.json` (4), `AADManagedIdentitySignInLogs.schema.json` (1).

**L23 — Inconsistent internal naming in the generator.** Most helpers use the `Workshop` infix (`Get-WorkshopRandomItem`, `New-WorkshopRecordObject`); `New-DefaultValue:78`, `New-StableGuid:93`, `New-StableHex:106`, `Add-Record:2081`, `Add-ProcessEvent:3761`, `Add-FileEvent:3795`, `Add-NetworkEvent:3821`, `New-NormalTelemetryValues:3853` do not. Cosmetic today; it will matter the moment the file is split.

**L24 — Hardcoded deprecated-table list.** `Initialize-AdxTables.ps1:51` — `foreach ($deprecatedTable in @('AADRiskyUsers'))` is a one-element loop with a magic name and no comment on when it can be removed.

**L25 — `.vscode/settings.json` has a machine-specific absolute path.** `python.analysis.extraPaths` hardcodes `c:\Users\lireland\.vscode\extensions\ms-security.ms-sentinel-2.3.0\python` — your Windows username and a pinned extension version. Confirmed gitignored **and untracked**, so nothing is exposed. Purely a note for if you ever decide to track editor config: use `${userHome}` and add a cross-platform `python.venvPath`.

---

## 3. Layout — what I would change and what I would leave alone

### Leave alone

The top-level layout is good and reads correctly to a newcomer: `docs/` for prose, `scripts/` for operations, `tools/` for build-time utilities, `infra/` for Terraform, `azure-data-explorer/` for Bicep, `schemas/` + `metadata/` for the data contract, `STUDENT-GUIDES/` for the handout. The README artifact index (lines 69-87) is the best thing in the repository for orientation — it maps *purpose* to *files* rather than just listing directories. Keep it and keep it current.

`.gitignore` is exemplary. The comments explain *why* each rule exists ("Produced by scripts/Export-TenantTelemetrySamples.ps1", "so the ~900 MB of NDJSON does not belong in the repository", "data/scenario-summary.json stays tracked because it documents the scenario"). Very few repos do this.

### Change

**1. `sample/` needs one naming rule: file basename == KQL table name.** Fix the typo, drop `-Real` / `-RealTelemetry` entirely (the whole tree is tenant telemetry, so the suffix carries no information), and move the two Defender portal exports to `sample/portal-exports/`. **Do this as one atomic pass** that also rewrites the `sources` field in the affected profiles and the `Path` column in `_export-summary.csv` — otherwise it breaks H12, H13, and L20.

**2. Split `sample/` by intent.** `sample/raw/` for portal/CSV captures, `sample/exports/<dtg>/` for script-produced. Both gitignored as now.

**3. Rename `sample/.../_field-profiles/` (M11)** so two incompatible formats stop sharing a suffix.

**4. Consider `metadata/mitre-attack-mapping.json` → next to `data/scenario-summary.json`.** It describes the *scenario*, not the table catalog that the rest of `metadata/` covers.

**5. Split `scripts/New-SyntheticTelemetry.ps1` along two seams — but only two.**

At 8,135 lines / 520 KB this is the largest single maintainability risk. It is monolithic but not carelessly so: `$victor`, `$win04`, `$aadc`, `$svcSql`, `$scenarioAlertIds` are threaded through process events (`:6310+`), registry events (`:6370`), file events (`:6394`), incidents (`:8000-8085`), and the summary (`:8093-8135`). A naive split creates a shared-mutable-state module, which is worse. The two clean seams:

- **Extract the ~40 data catalogs to `metadata/catalogs/*.json`.** I spot-checked `$securityAlertCatalog:3060-3075`, `$azureActivityCatalog:3079-3092`, and `$dnsQueryCatalog:3096-3110` — all static literals with no interpolation. There are 590 `[pscustomobject]@{...}` literals in the file. Moving them out likely removes 3,000-4,000 lines and lets a non-PowerShell contributor tune the alert mix without editing code. The repo already does exactly this with `metadata/profile-overrides.json` (`:742`) and the field profiles (`:175`). **Caveat: these blocks carry the highest-value provenance comments in the repository** — `:3057-3059` records the exact 552/307/126 provider split from the real sample. Those must move into the JSON as a `_provenance` field or the split is a net loss.
- **Split `New-NormalTelemetryValues` (`:3853-6222`).** A 2,370-line function with a 47-arm switch is the real problem — worse than the file length. Each arm is independent. A `Get-WorkshopTableGenerator -Table $t` dispatch returning a scriptblock, with arms in `scripts/generators/<Table>.ps1`, makes per-table changes reviewable in isolation. `Write-WorkshopTableData:6262` already isolates per-table state, so the seam exists.

**Keep together:** the scenario narrative (`:6307-8085`) and the fleet construction (`:2587-2950`). Those genuinely are one thing.

Practical note beyond code quality: at 520 KB this file is at the edge of what editors, `git diff`, and review tooling handle, and it exceeds most LLM/IDE context windows in one piece.

**6. Promote `AdxWorkshop.Common.psm1` to a module folder with a `.psd1` manifest** declaring `RequiredModules`, `PowerShellVersion = '7.0'`, and `FunctionsToExport`. That replaces the 8 scattered `Import-Module ... -Force` calls and the ad-hoc `Get-Command` preflights, and gives the ~400 lines from M2 a home.

**7. Add repo-governance files that are simply absent:** `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `.github/CODEOWNERS`, `.github/dependabot.yml`, `.gitattributes`. For a public security-education repo the `LICENSE` gap is the notable one — without it, nobody can legally reuse the workshop you built for people to reuse.

---

## 4. GitHub Actions — recommended additions

Today: **one workflow, two jobs.** `telemetry-safety.yml` is well-scoped, well-commented (`:3-8` explains *why* CI exists rather than just the hook), correctly sets `permissions: contents: read`, and the manifest↔schema reconciliation (`:59-94`) is a genuinely non-obvious integrity gate. Keep it as-is and add siblings, so each concern fails independently.

| Workflow | Contents | Closes |
| --- | --- | --- |
| `gateway-tests.yml` | `setup-node@v4` (Node 24) → `npm test` in `tools/kusto-readonly-gateway`, `paths:`-filtered | **H7 in the original triage — the single highest-value addition.** The one security-critical code path has a test file and an npm script that nothing ever runs |
| `powershell-lint.yml` | PSScriptAnalyzer over `scripts/`, `tools/`, `adx_db_backupNrestore/` | 25 scripts, zero linting today. Catches L9 immediately and flags the `[string]`-typed secrets in H9/H10 |
| `iac-validate.yml` | `az bicep build --stdout` + `az bicep lint` on `azure-data-explorer/*.bicep`; `terraform fmt -check -recursive`, `terraform init -backend=false`, `terraform validate`, `tflint` on `infra/cloudflare-adx` | Neither IaC tree is validated today |
| `container-scan.yml` | `hadolint` on the Dockerfile, `docker compose config --quiet`, Trivy on the built image | Would auto-flag M8 (root user, unpinned base) |
| `codeql.yml` | CodeQL `javascript-typescript`, weekly + on PR | Free static analysis on the gateway |
| `secret-scan.yml` | `gitleaks` or TruffleHog, full history | Directly complements the telemetry-safety theme. **Configure an allowlist for the intentional student-guide credential** so it does not fight your delivery model |
| `docs-consistency.yml` | Assert the row count, table count, and class-size figures agree across README / student guide / diagrams; assert dashboard `.kql` tile titles == `.json` tile titles; assert every markdown relative link resolves | Would have caught L1, L2, and locks in the M14 parity that is correct today. *(All markdown links currently resolve — I checked all of them, zero broken.)* |
| `metadata-consistency.yml` | Extend the existing `package-integrity` job: every profile has a schema; every profile `sources` path resolves or carries a hash; profile columnCount == schema columnCount modulo a declared allowlist of LA housekeeping columns | Catches H12, M12, M13 automatically |

**Cross-cutting edits to every workflow, including the existing one:**

- SHA-pin `actions/checkout` (currently `@v4` tag-pinned at `:24` and `:57`) — for a security-teaching repo, pin to commit SHA and let Dependabot bump it.
- Add `concurrency: { group: ${{ github.workflow }}-${{ github.ref }}, cancel-in-progress: true }`.
- Add `timeout-minutes: 10` to each job.
- Replace `Write-Host -ForegroundColor Red` with `::error::` annotations and `$GITHUB_STEP_SUMMARY` — red text produces no annotation in the Actions UI, so failures are currently buried in log output.
- Add `actionlint` as a step.

**Prerequisite:** M1 (the `Join-Path` backslashes) must be fixed before `Test-SyntheticDataQuality.ps1` or `Test-WorkshopIdentityInvariants.ps1` can run on `ubuntu-latest`. Both are already gate-shaped — they exit 0/1 correctly and have real thresholds (`-MinimumScore 0.80`; single-tenant GUID, ≤25 subscriptions, no `11111111-` placeholders). They just need a fast fixture path (`-NormalRowsPerTable 50`) so CI does not have to build 900 MB.

---

## 5. Concepts that require code that does not exist

Ordered by how likely you are to feel the absence.

**1. No Pester. No unit tests anywhere in the PowerShell layer.** Zero `*.Tests.ps1`, zero Pester references. Every "test" is an integration check against a fully generated ~900 MB dataset. The functions that would benefit most are pure and trivially testable with no Azure and no fixtures:

- `ConvertTo-WorkshopKustoIdentifier` / `ConvertTo-WorkshopKustoStringLiteral` — escaping, which is both a correctness *and* an injection concern
- `New-StableHex` / `New-StableGuid` — determinism, which the whole reproducibility claim rests on
- `ConvertFrom-WorkshopAdxResponseRows` — empty tables, missing `Rows`, the `ColumnName` vs `Name` fallback at `:324`
- `ConvertTo-KustoType` — the 11-case mapping duplicated in two files
- `Get-WorkshopTargetRowCount` — the override precedence at `:6232-6259` is non-obvious with three interacting flags

`Test-WorkshopPackage.ps1:90-103` runs `Parser::ParseFile` over every script, which catches syntax errors only — not the runtime failures StrictMode produces.

**2. No student-lifecycle teardown.** `New-WorkshopStudents.ps1` creates users, a group, TAPs, and a plaintext roster. Nothing removes them. `docs/student_access.md:65-66` says to delete the roster and confirm the group is empty; that is a checklist item, not a script. A `Remove-WorkshopStudents.ps1` closes H9.

**3. No gateway audit log.** L19. Also the natural raw material for a bonus exercise.

**4. No ADX diagnostic settings in Bicep.** M7. Same shape of gap: a workshop about telemetry that produces none about itself.

**5. No merge step for parallel generation summaries.** H6.

**6. No metadata-consistency validator.** The reconciliation logic exists for manifest↔schemas in CI but stops there. A `Test-MetadataConsistency.ps1` extending it to profiles and sources catches H12/M12/M13 in one place. `Test-WorkshopPackage.ps1` is the natural home.

**7. No dashboard build step.** M14 — two hand-maintained copies of 40 queries. If `New-WorkshopDashboard.ps1` can emit V4-format JSON, one of the two files should become a build output.

**8. No `.dockerignore` and no `package-lock.json`** in `tools/kusto-readonly-gateway/`, so `npm ci` is not possible and the build context includes everything.

**9. No `workshop/` directory** for `New-WorkshopDeck.ps1` (L8) — either restore it or delete the script.

---

## 6. Questions for you

Grouped so you can answer in batches.

### Scenario and data

1. **`IdentityInfo` (H11):** Defender XDR table or Sentinel UEBA table? Which naming wins, and should the loser become a separately-named table?
2. **`New query (7)/(8).csv` (H13):** hand-run exports that superseded the properly-named files, or accidental captures the profiler picked up? Are those two profiles built from the data you intended?
3. **The 32 missing source CSVs (H12):** deleted deliberately after profiling, or lost?
4. **The ten profile-less schemas (M12):** intentional "documented but not generated", or a backlog? `OAuthAppInfo` and `EmailPostDeliveryEvents` look scenario-relevant given Acts 2 and 5.
5. **`ExposureGraphEdges`:** the export timed out at 300 s. Larger timeout, paged export, or drop it from the generated set?
6. **The dated export (`sample/20260724T000000Z/`, 160 MB):** one-off capture you still need, or reproducible? It is fully gitignored, so nobody else can regenerate the profiles that depend on it.
7. **Which dashboard is canonical (M14)?** Is `dashboard-CYBER-DEFEND-V4.json` a frozen student handout, or the live one `dashboards/` should be regenerated from? Is `New-WorkshopDashboard.ps1` the generator for either?

### Generator

8. **`-TelemetryEndTime` omission (H5):** intentional? If timestamps are meant to be reproducible, the driver needs to capture one value and pass it to every worker.
9. **Row-count divergence (H5):** parallel uses flat `-RowsPerTable 8000`, single-process randomizes 5000-10000 for the same seed. Deliberate?
10. **Scenario summary in parallel mode (H6):** merge the per-worker summaries, or re-run the single-process generator once for the scenario tables?
11. **Catalog extraction (layout §5):** if the ~40 catalogs moved to `metadata/catalogs/*.json`, do you want the provenance comments (e.g. `:3057-3059`, the 552/307/126 provider split) preserved as JSON fields? I would not want them dropped in a mechanical move.

### Gateway and runtime

12. **Is `request_readonly: true` deliberately not forced?** Was it omitted because Kustainer does not honor it?
13. **Does the Kustainer REST handler bind JSON case-insensitively / last-wins?** That determines whether H1a is theoretical or live. Re-serializing removes the question either way.
14. **Is `externaldata` / `evaluate <plugin>` reachable from your Kustainer build, and is outbound network from the `kusto` container blocked at the host?** If the container has egress, H1b is exploitable today.
15. **Is `.show` intended as a blanket allow (H3), or as "safe metadata reads"?**
16. **Why `tcp://` tunnel ingress rather than `http://` (H8)?** HTTP would give you Cloudflare WAF/rate-limiting and let the gateway see `Cf-Access-Jwt-Assertion`.
17. **One shared service token for the whole class:** intentional simplicity, or would per-student tokens be feasible? It is the difference between "revoke the abuser" and "rotate for everyone mid-class."
18. **`config_src = "cloudflare"` (H8):** deliberate, and is anything watching the dashboard-managed ingress for drift?

### Repo and platform

19. **Is the repository public?** If yes: the `LICENSE` gap (§3.7) and the hardcoded tenant identifiers (H7) are both worth a decision.
20. **`enablePurge: true` and `enablePublicNetworkAccess: true`** on the student cluster (M7) — required by an exercise, or defaults never revisited?
21. **Is `azure-data-explorer/restore-cyber-defend-database.ps1` still live,** or superseded by `adx_db_backupNrestore/`? It duplicates two module helpers, hardcodes five live identifiers, and is the only file in the repo without StrictMode or a help block.
22. **`Test-WorkshopPackage.ps1` and `sample/` (H4):** should the `-Real.csv` checks become opt-in behind `-WithRealSamples` so the rest can run in CI?
23. **`New-WorkshopDeck.ps1` (L8):** delete, or restore the `workshop/` directory?
24. **Is there a reason `students/` is not in the pre-commit hook (M9),** given the gitignore comment says those files carry passwords and TAP values?

---

## 7. Suggested order of work

Sequenced by value per unit of effort, not by severity.

### Before the next delivery (hours)

1. **C1** — guard the gateway handler and add the two `process.on` handlers. Two lines, removes a one-curl class outage.
2. **H1a** — re-serialize the forwarded body. Removes a whole class of parser-differential bypass.
3. **H5** — pass `-TelemetryEndTime` through to workers. One line.
4. **H10** — set `TUNNEL_SERVICE_TOKEN_SECRET` as an env var in `Start-StudentAdxProxy.ps1:62-66` instead of a CLI flag. The script already reads it at `:43`.
5. **M3** — add `-TimeoutSec 300 -MaximumRetryCount 3 -RetryIntervalSec 5` to `AdxWorkshop.Common.psm1:304`, and cache the token. Removes 64 redundant token calls per large ingest.
6. **L1, L2, L3** — three stale numbers in three docs. `README.md:362` (629K → 624K), `README.md:21` (20-40 → 5-100), and the "48 table snapshot" note in the answer key that will mislead you mid-class.
7. **M4** — check `$LASTEXITCODE` in `AdxWorkshop.Common.psm1:70`.
8. **L12** — add `Get-MgUser` to the `New-WorkshopStudents.ps1:47` preflight.

### This iteration (a day or two)

9. **`gateway-tests.yml`** — the security-critical component gets CI. Add tests for the C1 crash, `db` handling, path variations, and the `403`/`404`/`405`/`413` paths, which are entirely untested today.
10. **H2** — token bucket, in-flight cap, and forced `Options` clamp on the gateway.
11. **H3** — `.show` subcommand allowlist.
12. **H8** — split `adx-internal` into `edge` and `backend` networks. Makes the worst-case bypass architecturally impossible instead of policy-dependent.
13. **M8** — `USER node`, digest-pinned base, `--init`, `HEALTHCHECK`, `.dockerignore`, lockfile.
14. **M1** — global `Join-Path` fix. Mechanical, and it unblocks everything in §4.
15. **H4** — `-WithRealSamples` switch, then wire `Test-WorkshopPackage`, `Test-SyntheticDataQuality`, and `Test-WorkshopIdentityInvariants` into CI behind a small fixture run.
16. **M9** — one shared `Test-RepositorySafety.ps1` called by both the hook and CI; add `students/` to the hook; scan staged blobs rather than the working tree.
17. **`powershell-lint.yml`** and **`iac-validate.yml`**.
18. **§3.7** — `LICENSE`, `.gitattributes`, `SECURITY.md`, `dependabot.yml`.

### Next iteration

19. **H11, H12, H13, M11, M12, M13, L20** — the metadata/`sample/` consistency pass, done atomically with the `sources` rewrites, plus `Test-MetadataConsistency.ps1` so it cannot regress.
20. **M2** — consolidate the ~400 duplicated lines into the module (`Wait-WorkshopAdxOperation`, `ConvertTo-WorkshopKustoObfuscatedLiteral`, `ConvertTo-WorkshopKustoType`, `Get-WorkshopNdjsonLineCount`, `Invoke-WorkshopAzCli`).
21. **Pester suite** for the module's pure functions. Fast, no Azure, no fixtures.
22. **M7** — Bicep: `diagnosticSettings`, `allowedFqdnList`, `parent:` on the child resources, `@description` on parameters, managed identity in IaC.
23. **§3.5** — split `New-SyntheticTelemetry.ps1` along the two seams, carrying the provenance comments across.
24. **M14** — retire one dashboard copy; add the `.kql`↔`.json` parity check to CI while they are still in sync.

---

## 8. One closing note

The pattern I would most want preserved through all of the above is the one visible in `CHANGELOG.md`. Entries like *"Stopped the restore script reporting work it had not done"* and *"Fixed a backup that silently shipped a stale, incomplete database"* describe the defect, the consequence, and the reasoning — including the observation that *"misleading output and silently discarded options are both worth treating as defects in a tool someone reaches for when the workshop is already broken."*

That standard is why the repository is in the shape it is in. Most of the findings above are places where that standard has not yet been applied, rather than places where it was applied badly.

---

<sub>Read-only evaluation · no repository files were modified · credentials left untouched as instructed</sub>
