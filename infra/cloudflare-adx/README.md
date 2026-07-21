# Cloudflare Tunnel for Local ADX

This module publishes the local Kusto emulator through `adx.tier1-cyberdefense.ai` using a remotely managed Cloudflare Tunnel and protects it with Cloudflare Access. The Access policy permits the explicit local email allow-list. Docker Compose owns both the Kusto emulator and the tunnel connector.

Cloudflare One-Time PIN login is provisioned alongside the existing Cloudflare identity provider. An allowed user can choose One-Time PIN on the Access page, enter their listed email address, and authenticate with the code delivered to that mailbox; they do not need a Cloudflare account.

## Security Boundary

The Terraform provider reads `CLOUDFLARE_API_TOKEN` from the current process environment. No API key, R2 credential, tunnel token, or Terraform state belongs in Git. The launcher writes the connector token only to the ignored `cloudflared.env` file, which Docker Compose supplies to the connector. The API token must have these minimum permissions:

- Account: `Cloudflare Tunnel` and `Cloudflare One Connector` read/write.
- Account: `Access: Apps and Policies` read/write.

Zone `DNS` read/write for `tier1-cyberdefense.ai` is optional. When it is unavailable, authorize `cloudflared tunnel login` in a browser and use the DNS helper below.

## Configure

For direct Terraform use, copy [terraform.tfvars.example](terraform.tfvars.example) to `terraform.tfvars` and set the Cloudflare zone ID. `terraform.tfvars` is ignored by Git. The deployment script uses browser-authorized DNS routing by default, so it does not require a zone ID.

The deployment command reads `infra/cloudflare-adx/allowed-emails.txt` by default. Add one email address per line, including `dcodev1702@gmail.com` if it should retain access. This file is ignored by Git, so it is appropriate for the 40 additional workshop addresses. The launcher derives the ignored `allowed-emails.auto.tfvars.json` Terraform input file from that list on each run.

If your users have email security filtering, allowlist `noreply@notify.cloudflare.com` so One-Time PIN messages are not delayed, quarantined, or consumed by link scanners.

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

The launcher starts the Compose `kusto` service, waits for its management-query health check on `http://127.0.0.1:8080`, applies the Cloudflare resources, writes `cloudflared.env` when the connector needs a token, and starts the Compose `cloudflared` service. The connector forwards its Cloudflare route to `tcp://kusto:8080` over the private `cyber-conf-wiesbaden-adx` Docker network. Only Kusto has a host port, and that mapping is limited to `127.0.0.1:8080`. The Access session duration is one week (`168h`).

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

> ⚠️ Keep the existing `kusto` container when the local Student snapshot matters. Kustainer's persistent-database registration is retained across a clean stop/start of that container, not a Compose container replacement. Do not use `docker compose down`, `docker compose rm`, or `docker compose up --force-recreate kusto`; rebuild with `Copy-StudentAdxToLocalKusto.ps1 -ForceRecreate` after any intentional replacement.

Subsequent calls to `Start-CloudflareAdxTunnel.ps1 -Apply` leave the existing connector token and healthy Compose connector in place. Use `-ReplaceExistingConnector` only when you intentionally need a new connector token and container.

## Client Connection

Cloudflare Access protects the public HTTPS hostname. A collaborator using Kusto Explorer should run `cloudflared access tcp --hostname adx.tier1-cyberdefense.ai --url localhost:8080` locally, complete the browser-based Access login, then connect Kusto Explorer to `http://localhost:8080`.
