# Kusto Read-Only Gateway

## Purpose

This component is the policy boundary between classroom tunnel traffic and the Kustainer emulator.

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
| `/v1/rest/query` and `/v2/rest/query` | Accepts KQL query statements and `let` bindings. Rejects every Kusto management command. |
| `/v1/rest/mgmt` | Accepts exactly one read-only `.show` command. |
| `/v1/rest/ping` and `/v2/rest/ping` | Proxies Kustainer ping requests. |
| Any other route | Returns HTTP `404`. |

The gateway returns HTTP `403` before forwarding KQL that begins with a management command on the query endpoint, or any management command other than one `.show` command on the management endpoint. This includes `.drop`, `.add`, `.create`, `.alter`, `.delete`, `.ingest`, `.set`, and multi-statement management requests.

The KQL statement splitter handles semicolons inside quoted strings and ignores leading line and block comments before evaluating a statement.

## Browser Compatibility

The Azure Data Explorer web UI is served from `https://dataexplorer.azure.com` and connects from a browser to the student's loopback proxy. The gateway:

- Allows that origin through CORS.
- Reflects the ADX web UI's requested `x-ms-*` and authorization headers during preflight.
- Returns `Access-Control-Allow-Private-Network: true` when the browser requests loopback private-network access.
- Passes Kusto response headers while removing upstream CORS headers so the gateway remains the CORS authority.

The proxy connection URI is:

```text
http://127.0.0.1:8080;Fed=false
```

`Fed=false` prevents the Kusto client from attempting Microsoft Entra authentication against Kustainer. Cloudflare Service Auth has already authenticated the tunnel connection before traffic reaches the gateway.

## Configuration

The gateway is configured by `compose.yaml`.

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `KUSTO_UPSTREAM_URL` | `http://kusto:8080` | Private Kustainer endpoint to proxy. |
| `KUSTO_ALLOWED_ORIGINS` | `https://dataexplorer.azure.com` | Comma-separated browser origins allowed through CORS. |
| `KUSTO_MAX_BODY_BYTES` | `1048576` | Maximum Kusto request body size. |

The gateway does not publish a host port. Only the Cloudflare connector can reach it through the private Compose network.

## Default Database Cleaner

`remove-netdefaultdb.mjs` runs as the `kusto-defaultdb-cleaner` Compose service. Once `CyberDefendStudentSnapshot` is present, it:

1. Drops `NetDefaultDB` if Kustainer created it.
2. Removes the residual `/kustodata/dbs/NetDefaultDB` persistent state directory.

The cleaner waits on a fresh emulator until the Student import has created `CyberDefendStudentSnapshot`. This keeps the Kustainer bootstrap/import path working while ensuring the default database does not remain after the workshop snapshot is ready.

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

Use the class guide for student proxy setup, Service Token rotation, browser diagnostics, and the expected `Fed=false` connection URI: [docs/cloudflare_adx_access.md](../../docs/cloudflare_adx_access.md).

## Security Boundary

The gateway protects only requests that traverse the Cloudflare tunnel. A local host administrator can still send unrestricted management commands directly to Kustainer at `http://127.0.0.1:8080`.

Do not treat this component as a general-purpose KQL sandbox for untrusted code. It enforces the workshop's read-only query and metadata workflow; managed Azure Data Explorer with Microsoft Entra roles remains the appropriate option for production authorization requirements.
