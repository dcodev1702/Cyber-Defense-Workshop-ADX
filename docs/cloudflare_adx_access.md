# Primary Conference Delivery: Shared Class Credential for the Containerized ADX Lab

## Purpose

Use this guide for the primary conference delivery model: the containerized Azure Data Explorer (ADX) lab at `adx.tier1-cyberdefense.ai`. Students share one short-lived Cloudflare Service Auth credential, run a local Cloudflared TCP proxy, and connect ADX to that local proxy.

This is the preferred route for time-boxed workshops with random or mixed-tenant attendees. The managed Azure ADX deployment and its Microsoft Entra B2B access described in [student_access.md](student_access.md) are the secondary route for programs that require governed per-person access.

## What This Solves

- One shared class credential works for 20-35 attendees.
- Students do not need Cloudflare accounts, One-Time PIN email, or individual Cloudflare Access seats.
- The shared credential is valid for at least 48 hours.
- A private gateway allows read-only KQL and blocks data-changing management commands before they reach Kustainer.

## Architecture

```text
Student device
    -> cloudflared access tcp with shared Service Token
    -> Cloudflare Access Service Auth
    -> Cloudflare Tunnel
    -> read-only Kusto gateway
    -> Kustainer
```

| Item | Value |
| --- | --- |
| Tunnel hostname | `adx.tier1-cyberdefense.ai` |
| Tunnel origin | `tcp://kusto-readonly-gateway:8081` |
| Student Kusto connection URI | `http://127.0.0.1:8080` |
| Local database | `CyberDefendStudentSnapshot` |
| Credential lifetime | `168h` default, `48h` enforced minimum |
| Credential type | Shared Cloudflare Service Token Client ID and Client Secret |
| Supporting-service limit | Cleaner, gateway, and Cloudflared are each pinned to 1 GiB memory and 1 GiB swap |

## Read-Only Boundary

The Kusto emulator has no native authentication or authorization. The read-only gateway is therefore the enforcement point for tunnel traffic.

| Request type | Gateway behavior |
| --- | --- |
| Query endpoint | Allows KQL queries, including `let` statements. |
| Management endpoint | Allows one read-only `.show` command. |
| Data/control commands | Rejects `.drop`, `.add`, `.create`, `.alter`, `.delete`, `.ingest`, `.set`, and every other management command with HTTP `403`. |

> ⚠️ The restriction applies to traffic through the Cloudflare tunnel. The instructor can still administer Kustainer locally through `http://127.0.0.1:8080`.

For the gateway's complete request policy, CORS behavior, cleaner lifecycle, and security boundary, see [tools/kusto-readonly-gateway/README.md](../tools/kusto-readonly-gateway/README.md).

## Instructor Setup

Apply the Cloudflare route, Service Auth application, shared credential, read-only gateway, and connector from the repository root:

```powershell
.\scripts\Start-CloudflareAdxTunnel.ps1 -Apply
```

The launcher writes two ignored files beneath `infra\cloudflare-adx`:

| File | Purpose |
| --- | --- |
| `cloudflared.env` | Tunnel connector token for the Docker host only. |
| `student-access.env` | Shared class Service Token and hostname. Distribute this only through the temporary class channel. |

Do not commit either file. The Service Token is a shared lab password in two parts: a Client ID and Client Secret.

### Verify the host

Run the fast local Kusto probe:

```powershell
curl.exe -fsS http://127.0.0.1:8080/v1/rest/ping
```

Expected output includes `"ApplicationHealthState":"Healthy"`.

Confirm the gateway is running:

```powershell
docker compose ps
```

The `kusto-readonly-gateway` service must report `healthy` before students connect.

The Compose `kusto-defaultdb-cleaner` service keeps the database list clean: after `CyberDefendStudentSnapshot` exists, it removes `NetDefaultDB` and its persistent state directory. This does not affect the Student snapshot.

## Back Up Before Replacement

Use the local backup command before an intentional Kustainer replacement or before copying the database off the host. Stop and start the existing container directly; do not use `docker compose up` to wait after a Compose change because that can replace Kustainer.

```powershell
docker compose stop kusto
.\scripts\Backup-LocalKustoSnapshot.ps1
docker compose start kusto
```

The command writes a timestamped ZIP and SHA-256 hash under `data\backups\local-kusto`. Copy that ZIP to the destination of your choice, such as Google Drive, and keep it out of source control.

## Student Setup

Give each attendee these two files through your temporary class channel:

1. [scripts/Start-StudentAdxProxy.ps1](../scripts/Start-StudentAdxProxy.ps1)
2. The generated, untracked `student-access.env` file.

On each student device:

1. Install Cloudflared:

   ```powershell
   winget install --id Cloudflare.cloudflared --exact
   ```

2. Open PowerShell in the folder containing both files and start the local proxy:

   ```powershell
   .\Start-StudentAdxProxy.ps1 -CredentialFile .\student-access.env
   ```

   Leave this terminal open for the lab.

3. Sign in to the Azure Data Explorer web UI with Microsoft Entra ID.

4. Add or select this cluster connection URI:

   ```text
   http://127.0.0.1:8080
   ```

   The Cloudflare shared credential is already handled by the local proxy, so Azure Data Explorer does not need to authenticate again against Kustainer.

5. Select `CyberDefendStudentSnapshot` and run a query:

   ```kusto
   SecurityIncident
   | take 10
   ```

The Microsoft Entra sign-in authenticates the ADX web UI. Cloudflare Service Auth gates the tunnel connection with the shared lab credential.

## Browser Connection Compatibility

The Azure Data Explorer web UI runs at `https://dataexplorer.azure.com` and connects from the browser to the local student proxy. The read-only gateway is configured to allow that origin, the ADX web UI's `x-ms-*` headers, and the browser private-network preflight required for loopback access.

If the ADX **Add connection** dialog shows a failure while the proxy terminal says it is listening:

1. Keep the proxy terminal open.
2. Verify the proxy on the student device:

    ```powershell
    $body = @{ csl = '.show cluster' } | ConvertTo-Json -Compress
    Invoke-WebRequest -UseBasicParsing -Method Post `
       -ContentType 'application/json' `
       -Body $body `
       -Uri 'http://127.0.0.1:8080/v1/rest/mgmt'
    ```

    This must return HTTP `200`.

3. Use the URI `http://127.0.0.1:8080`.
4. Hard-refresh the ADX web UI with `Ctrl+F5`, close the failed dialog, and add the connection again.

The CORS/private-network fix is hosted in the read-only gateway. Students do not need a new Cloudflare account or an individual credential for this browser step.

To diagnose browser preflight from the student device, run this while the proxy is listening:

```powershell
$requestedHeaders = 'authorization,content-type,x-ms-activity-id,x-ms-client-request-id,x-ms-app,x-ms-client-version,x-ms-user-id,x-ms-user-authentication'
$preflight = Invoke-WebRequest -UseBasicParsing -Method Options `
   -Headers @{
      Origin = 'https://dataexplorer.azure.com'
      'Access-Control-Request-Method' = 'POST'
      'Access-Control-Request-Headers' = $requestedHeaders
      'Access-Control-Request-Private-Network' = 'true'
   } `
   -Uri 'http://127.0.0.1:8080/v1/rest/query'

[pscustomobject]@{
   Status = $preflight.StatusCode
   AllowedOrigin = $preflight.Headers['Access-Control-Allow-Origin']
   PrivateNetworkAllowed = $preflight.Headers['Access-Control-Allow-Private-Network']
} | Format-List
```

Expected values are HTTP `204`, `AllowedOrigin=https://dataexplorer.azure.com`, and `PrivateNetworkAllowed=true`.

## Validate the Student Path

With the student proxy running, this should return HTTP `200`:

```powershell
$body = @{ csl = '.show cluster' } | ConvertTo-Json -Compress
Invoke-WebRequest -UseBasicParsing -Method Post `
  -ContentType 'application/json' `
  -Body $body `
  -Uri 'http://127.0.0.1:8080/v1/rest/mgmt'
```

The direct public hostname does not accept requests without the shared Service Token. A request without the local proxy should return HTTP `403`.

## Rotate After Class

Run this immediately after the class, or before the next class, to replace the shared credential. The previous Client ID and Client Secret become invalid after Terraform replaces the Service Token.

```powershell
.\scripts\Start-CloudflareAdxTunnel.ps1 -Apply -RotateStudentCredential
```

The launcher overwrites the ignored `student-access.env` file with the new pair. Do not distribute the replacement unless another class needs access.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| `curl.exe -fsS http://127.0.0.1:8080/v1/rest/ping` fails on the instructor host | Kusto is not healthy. Run `docker compose ps` and `docker compose logs kusto`. |
| Student proxy cannot bind port `8080` | Another local service owns the port. Start the proxy with `-LocalPort 18080` and use `http://127.0.0.1:18080` in ADX. |
| Student sees HTTP `403` through the local proxy | The shared credential was rotated, expired, malformed, or not passed to Cloudflared. Obtain the current `student-access.env` from the instructor. |
| Student can query but `.drop` or `.create` returns HTTP `403` | Expected. The read-only gateway is blocking mutable Kusto management commands. |
| ADX says it cannot connect while the local proxy is listening | Use `http://127.0.0.1:8080`, not the public tunnel hostname. |
| ADX still says it cannot connect after entering the local URI | Run the local management test in **Browser Connection Compatibility**. If it returns `200`, hard-refresh ADX with `Ctrl+F5`; the gateway already allows ADX CORS headers and private-network preflight. |
| Database is absent | The instructor should start the existing Kusto container with `docker compose start kusto`. If Kustainer was replaced, retain the backup ZIP and rebuild the mounted snapshot with `Copy-StudentAdxToLocalKusto.ps1 -ForceRecreate`. |

## References

- [Cloudflare Service Tokens](https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/)
- [Cloudflare arbitrary TCP access](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/non-http/cloudflared-authentication/arbitrary-tcp/)
- [Azure Data Explorer web UI](https://dataexplorer.azure.com)
