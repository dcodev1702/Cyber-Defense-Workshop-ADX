# Kusto Read-Only Gateway

## Purpose

This component is the policy boundary for the primary Docker-first conference route between classroom tunnel traffic and the Kustainer emulator.

Kustainer has no native authentication or authorization. Cloudflare Service Auth protects the public tunnel, while this gateway limits what an authenticated student can send to Kustainer. It is not a replacement for a managed Azure Data Explorer cluster or for host-level administrator controls.

```text
Student ADX Web UI
    -> local cloudflared TCP proxy
    -> Cloudflare Service Auth
    -> Cloudflare Tunnel
    -> Kusto read-only gateway
    -> Kustainer
```

The Compose tunnel route targets `tcp://kusto-readonly-gateway:8081`; it never routes student traffic directly to Kustainer.

## Request Policy

| Route | Allowed behavior |
| --- | --- |
| `/healthz` | Returns gateway health without contacting Kustainer. |
| `/v1/rest/query` and `/v2/rest/query` | Accepts KQL query statements, `let` bindings, and `externaldata`. Rejects every Kusto management command and the remaining query-language egress primitives listed below. |
| `/v1/rest/mgmt` | Accepts exactly one read-only `.show` command from a metadata-read allowlist. |
| `/v1/rest/ping` and `/v2/rest/ping` | Proxies Kustainer ping requests. |
| Any other route | Returns HTTP `404`. |

The gateway returns HTTP `403` before forwarding KQL that begins with a management command on the query endpoint, or any management command other than one allowlisted `.show` command on the management endpoint. This includes `.drop`, `.add`, `.create`, `.alter`, `.delete`, `.ingest`, `.set`, and multi-statement management requests.

The KQL statement splitter handles semicolons inside quoted strings and ignores leading line and block comments before evaluating a statement.

### Beyond dot-prefixed commands

"Does not start with a dot" is not the same as read-only. The gateway permits `externaldata` so exercises can query approved public data feeds. It still rejects, on the raw request text, the following query-language primitives that reach outside the database even though they never begin with `.`:

- `evaluate python(...)` / `R(...)` — sandbox code execution where enabled.
- `evaluate http_request` / `sql_request` / `mysql_request` / `cosmosdb_sql_request` and related request plugins — outbound connections with attacker-supplied targets.
- `cluster(...)` — cross-cluster pivots using the host's own identity.

Because the remaining deny scan runs on the raw text rather than the lexed statements, a primitive hidden inside a string literal is rejected too: over-blocking here fails closed, which is the correct direction for a policy boundary.

### `.show` metadata-read allowlist

`.show` is read-only for *data* but not for *secrets*: `.show queries` and `.show commands-and-queries` echo other students' query text, `.show journal` is the full command history, and on the managed ADX path `.show cluster principals` / `.show database ... principals` disclose real tenant identities. The management endpoint therefore permits only the metadata reads the ADX web UI and the exercises actually use: `.show version`, `.show schema`, `.show databases`, `.show databases schema`, `.show tables`, `.show table <t> schema` / `cslschema`, and `.show functions` / `.show function <f>`.

### Canonical forwarding

The gateway rebuilds the forwarded body from the fields it validated (`csl`, `db`, an allowlisted subset of `properties.Options`) instead of forwarding the client's raw bytes. This closes the parser-differential bypass where the gateway's V8 `JSON.parse` and Kustainer's .NET deserializer disagree about which of two duplicate/case-variant keys wins. As part of that rebuild the gateway forces `query_language = 'kql'`, clamps `servertimeout` to `KUSTO_MAX_SERVER_TIMEOUT_SECONDS`, drops every `Options` key it does not allowlist (so `notruncation` and unbounded timeouts cannot be set), and — unless `KUSTO_FORCE_READONLY=false` — sets `request_readonly = true`.

### Rate limiting and concurrency

Each source address gets a token bucket (`KUSTO_RATE_BURST`, `KUSTO_RATE_PER_MINUTE`), and the gateway caps concurrent in-flight upstream queries (`KUSTO_MAX_IN_FLIGHT`). A client over the budget receives `429` with `Retry-After`. Behind the TCP-mode tunnel every student shares the connector's source address, so the in-flight cap is the control that actually stops one runaway `range i from 1 to 10000000000 | ...` from wedging the shared emulator for the whole class.

### Audit log

The gateway emits one structured JSON line per decision (`forwarded`, `blocked-kql`, `blocked-database`, `rate-limited`, `at-capacity`, `unknown-route`, `handler-error`) to stdout, so a class incident can be answered from `docker compose logs kusto-readonly-gateway`.

## Browser Compatibility

The Azure Data Explorer web UI is served from `https://dataexplorer.azure.com` and connects from a browser to the student's loopback proxy. The gateway:

- Allows that origin through CORS.
- Reflects the ADX web UI's requested `x-ms-*` and authorization headers during preflight.
- Returns `Access-Control-Allow-Private-Network: true` when the browser requests loopback private-network access.
- Passes Kusto response headers while removing upstream CORS headers so the gateway remains the CORS authority.

CORS is a browser-UX feature here, **not** a security control. Students who connect with `cloudflared access tcp` and speak raw HTTP — `curl`, Kusto.Cli, the Python SDK — never send an `Origin` header and are unaffected by the origin allowlist. The controls that actually bound what a client can do are the statement/allowlist checks, the canonical forwarding, the database allowlist, and the rate limits above.

The proxy connection URI is:

```text
http://127.0.0.1:8080
```

Cloudflare Service Auth has already authenticated the tunnel connection before traffic reaches the gateway, so the Kusto client does not authenticate again.

## Configuration

The gateway is configured by `compose.yaml`.

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `KUSTO_UPSTREAM_URL` | `http://kusto:8080` | Private Kustainer endpoint to proxy. |
| `KUSTO_ALLOWED_ORIGINS` | `https://dataexplorer.azure.com` | Comma-separated browser origins allowed through CORS. |
| `KUSTO_MAX_BODY_BYTES` | `1048576` | Maximum Kusto request body size. |
| `KUSTO_ALLOWED_DATABASES` | *(unset — all allowed)* | Comma-separated database allowlist checked against `payload.db`. Unset means no database restriction. |
| `KUSTO_FORCE_READONLY` | `true` | Forces `request_readonly = true` on forwarded queries. Set to `false` only if a Kustainer build rejects the option during rehearsal. |
| `KUSTO_MAX_SERVER_TIMEOUT_SECONDS` | `240` | Upper bound the gateway clamps `servertimeout` to. |
| `KUSTO_RATE_BURST` | `60` | Token-bucket burst per source address. |
| `KUSTO_RATE_PER_MINUTE` | `300` | Token-bucket refill rate per source address. |
| `KUSTO_MAX_IN_FLIGHT` | `8` | Maximum concurrent upstream queries. |

The gateway does not publish a host port. Only the Cloudflare connector can reach it through the private Compose network.

## Container Limits

Docker Compose and the Terraform-generated override pin this gateway, `kusto-defaultdb-cleaner`, and `cloudflared` to 1 GiB memory and 1 GiB swap each. Kustainer has its own independent capacity profile.

## Default Database Cleaner

`remove-netdefaultdb.mjs` runs as the `kusto-defaultdb-cleaner` Compose service. Once `CyberDefendStudentSnapshot` is present, it:

1. Drops `NetDefaultDB` if Kustainer created it.
2. Removes the residual `/kustodata/dbs/NetDefaultDB` persistent state directory.

The cleaner waits on a fresh emulator until the Student import has created `CyberDefendStudentSnapshot`. This keeps the Kustainer bootstrap/import path working while ensuring the default database does not remain after the workshop snapshot is ready.

Kustainer retains ephemeral default-database metadata beneath `/kusto/tmp`. The Compose startup wrapper removes only the stale `NetDefaultDB` metadata before invoking the image's original startup script, so the cleaner does not cause a restart loop after a normal `docker compose stop kusto` and `docker compose start kusto` cycle. It does not touch the Student snapshot under `/kustodata`.

## Operations

Run the focused tests:

```powershell
Push-Location .\tools\kusto-readonly-gateway
npm test
Pop-Location
```

Check the services:

```powershell
docker compose ps kusto-readonly-gateway kusto-defaultdb-cleaner
```

Check the gateway logs:

```powershell
docker compose logs --follow kusto-readonly-gateway
docker compose logs --follow kusto-defaultdb-cleaner
```

Use the class guide for student proxy setup, Service Token rotation, browser diagnostics, and the expected connection URI: [docs/cloudflare_adx_access.md](../../docs/cloudflare_adx_access.md).

## Security Boundary

The gateway protects only requests that traverse the Cloudflare tunnel. A local host administrator can still send unrestricted management commands directly to Kustainer at `http://127.0.0.1:8080`.

Do not treat this component as a general-purpose KQL sandbox for untrusted code. It enforces the workshop's read-only query and metadata workflow; managed Azure Data Explorer with Microsoft Entra roles remains the appropriate option for production authorization requirements.
