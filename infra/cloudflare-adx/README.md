# Shared Credential Cloudflare Tunnel for Local ADX

This module publishes the local Kusto emulator through `adx.tier1-cyberdefense.ai` using a remotely managed Cloudflare Tunnel. It is the primary delivery path for short security conferences with random participants. Docker Compose owns the Kusto emulator, a read-only KQL gateway, and the tunnel connector. Cloudflare Access uses one shared Service Auth credential, so a class can connect without per-student Cloudflare identities or seats.

## Access Boundary

The Terraform provider reads `CLOUDFLARE_API_TOKEN` from the current process environment. No API key, R2 credential, tunnel token, or Terraform state belongs in Git. The launcher writes the connector token only to the ignored `cloudflared.env` file, which Docker Compose supplies to the connector.

The published route is `tcp://kusto-readonly-gateway:8081` on the private Compose network. The gateway allows query requests and a single `.show` command on the management endpoint. It rejects all other Kusto management commands before they reach Kustainer.

> ⚠️ Kustainer has no native authentication or authorization. The read-only rule protects only traffic entering through the Cloudflare tunnel. A local administrator with access to `127.0.0.1:8080` can still administer the emulator.

The detailed gateway contract is documented in [tools/kusto-readonly-gateway/README.md](../../tools/kusto-readonly-gateway/README.md).

For ongoing operation, the API token needs Account `Cloudflare Tunnel` and `Cloudflare One Connector` read/write, `Access: Apps and Policies` read/write, and `Access: Service Tokens` read/write. Zone `DNS` read/write for `tier1-cyberdefense.ai` remains optional; when it is unavailable, use the DNS helper below.

## Configure

For direct Terraform use, copy [terraform.tfvars.example](terraform.tfvars.example) to `terraform.tfvars` and set the Cloudflare zone ID. `terraform.tfvars` is ignored by Git. The deployment script uses browser-authorized DNS routing by default, so it does not require a zone ID.

Before running it, set the API token in the current terminal environment; do not paste it into chat or files. This uses a masked PowerShell prompt and avoids adding the value to command history.

```powershell
$secureToken = Read-Host 'Cloudflare API token' -AsSecureString
$tokenPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
try {
  $env:CLOUDFLARE_API_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($tokenPointer)
}
finally {
  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($tokenPointer)
}
.\scripts\Start-CloudflareAdxTunnel.ps1 -Apply
Remove-Item Env:CLOUDFLARE_API_TOKEN
```

The launcher starts the Compose `kusto` service, waits for its management-query health check on `http://127.0.0.1:8080`, applies the shared Service Auth route, writes `cloudflared.env` when the connector needs a token, writes `student-access.env` with the class credential, and starts the Compose `cloudflared` service. The connector forwards the public hostname to `tcp://kusto-readonly-gateway:8081` over the private `cyber-conf-wiesbaden-adx` Docker network. Only Kusto has a host port, and that mapping is limited to `127.0.0.1:8080`.

Terraform persists the local Kustainer profile by generating the ignored repository-root `compose.override.yaml`. Its default is 4 CPUs with 24 GiB for memory and swap; set `kusto_cpu_limit` or `kusto_memory_limit` in `terraform.tfvars` to override it. The cleaner, read-only gateway, and Cloudflared connector are all pinned to 1 GiB memory and 1 GiB swap in both Compose and the generated override. On an `-Apply` run, the launcher uses `docker update` to synchronize an existing Kustainer container without replacing the snapshot-holding container.

For a one-time migration from the previous manually created containers, run:

```powershell
.\scripts\Start-CloudflareAdxTunnel.ps1 -Apply -MigrateLegacyContainers
```

This removes only the legacy containers with the fixed workshop names. It preserves the bind-mounted recovery files under `data\local-kusto`, but replacing a Kustainer container requires a fresh Student snapshot import:

```powershell
.\scripts\Copy-StudentAdxToLocalKusto.ps1 -ForceRecreate
```

If the API token does not have Zone DNS permission, create the public CNAME once through the local browser-authorized Cloudflared client:

```powershell
& 'C:\Program Files (x86)\cloudflared\cloudflared.exe' tunnel login
.\scripts\Add-CloudflareAdxDnsRoute.ps1
```

After the initial provisioning, use Docker Compose for the normal runtime lifecycle:

```powershell
docker compose stop
docker compose start
docker compose logs --follow cloudflared
```

> ⚠️ Keep the existing `kusto` container when the local Student snapshot matters. Kustainer's persistent-database registration is retained across a clean stop/start of that container, not a Compose container replacement. Do not use `docker compose down`, `docker compose rm`, `docker compose up` after a Compose configuration change, or `docker compose up --force-recreate kusto`; rebuild with `Copy-StudentAdxToLocalKusto.ps1 -ForceRecreate` after any intentional replacement.

`kusto-defaultdb-cleaner` watches the local Kustainer endpoint. Once `CyberDefendStudentSnapshot` exists, it drops `NetDefaultDB` and removes the corresponding `data\local-kusto\dbs\NetDefaultDB` directory. The cleaner deliberately waits on a fresh emulator until the Student import has created the retained database.

Before an intentional Kustainer replacement, create a portable local backup and copy the generated ZIP from `data\backups\local-kusto` to secure storage:

```powershell
docker compose stop kusto
.\scripts\Backup-LocalKustoSnapshot.ps1
docker compose start kusto
```

Subsequent calls to `Start-CloudflareAdxTunnel.ps1 -Apply` leave the existing connector token and healthy Compose connector in place. Use `-ReplaceExistingConnector` only when you intentionally need a new connector token and container.

## Student Connection

The shared credential defaults to `168h`, and Terraform rejects a duration below `48h`. Distribute the ignored `student-access.env` file only for the class, together with [scripts/Start-StudentAdxProxy.ps1](../../scripts/Start-StudentAdxProxy.ps1).

On each student device, install Cloudflared and start the local TCP proxy:

```powershell
winget install --id Cloudflare.cloudflared --exact
.\Start-StudentAdxProxy.ps1 -CredentialFile .\student-access.env
```

Leave the proxy running and connect the Azure Data Explorer web UI to `http://127.0.0.1:8080`. Select `CyberDefendStudentSnapshot`.

Use the Kusto connection URI `http://127.0.0.1:8080`. The Cloudflare Service Token has already authenticated the tunnel proxy, so the client does not authenticate again against Kustainer.

## Browser Compatibility

The read-only gateway allows requests only from `https://dataexplorer.azure.com`. It reflects the ADX web UI's required `x-ms-*` request headers during CORS preflight and returns `Access-Control-Allow-Private-Network: true` for browser requests to the local student proxy.

If the ADX **Add connection** dialog reports a failure while the proxy is listening:

1. Confirm the student proxy answers locally:

   ```powershell
   $body = @{ csl = '.show cluster' } | ConvertTo-Json -Compress
   Invoke-WebRequest -UseBasicParsing -Method Post `
     -ContentType 'application/json' `
     -Body $body `
     -Uri 'http://127.0.0.1:8080/v1/rest/mgmt'
   ```

2. Use `http://127.0.0.1:8080` as the connection URI.
3. Hard-refresh the ADX web UI with `Ctrl+F5`, then add the connection again.

The local management request should return HTTP `200`. If it does not, the issue is the proxy or credential rather than the ADX browser.

For the exact CORS/private-network preflight diagnostic and expected `204` response, use the **Browser Connection Compatibility** section in [docs/cloudflare_adx_access.md](../../docs/cloudflare_adx_access.md).

The credential is shared, so it must be rotated after class:

```powershell
.\scripts\Start-CloudflareAdxTunnel.ps1 -Apply -RotateStudentCredential
```
