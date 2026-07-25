# Cyber Defense Workshop — ADX (Primary Docker Conference Delivery)

## End-to-End Walkthrough

Primary local ADX in Docker, Shared Cloudflare Service Auth, and Terraform IaC.

**Prepared for:** Lorenzo Ireland — Sr. Cloud Solution Architect, Microsoft
**Version:** 1.1 · July 2026

---

## 1. Overview

This walkthrough documents the primary conference lab: it spins up the **Cyber-Defense-Workshop-ADX** repository inside Docker on your Ubuntu 26.04 host, then publishes the local Azure Data Explorer instance through a Cloudflare Tunnel protected by one shared Service Auth credential. The Cloudflare resources are defined in **Terraform** so the route and short-lived class credential are version-controlled and reproducible. Managed Azure ADX plus Microsoft Entra B2B remains a secondary delivery option for events that require governed individual identities.

Reference repository: <https://github.com/dcodev1702/Cyber-Defense-Workshop-ADX>

| Component | Purpose |
| --- | --- |
| Ubuntu 26.04 host | Docker engine host running ADX + supporting services |
| Cyber-Defense-Workshop-ADX | KQL / ADX workshop content packaged for local lab use |
| Kusto emulator | Persistent local ADX-compatible query engine, capped at 4 vCPUs and 24 GiB RAM by default |
| Cleaner, gateway, and Cloudflared | Supporting services, each pinned to 1 GiB memory and 1 GiB swap |
| Cloudflare Tunnel (`cloudflared`) | Outbound-only tunnel from your host to Cloudflare's edge — no inbound ports |
| Shared class credential | One 48-hour minimum Cloudflare Service Token used by all students without individual Access seats |
| Read-only KQL gateway | Blocks mutable management commands before tunnel traffic reaches Kustainer |
| Terraform | Declarative, version-controlled Tunnel + Service Auth + DNS configuration |

> **Design principle:** No inbound ports are opened on your host. All traffic is initiated outbound by `cloudflared`. Students share one temporary Service Token and connect through a local TCP proxy; they do not need individual Cloudflare Access seats.

### Placeholders used throughout

| Placeholder | Example |
| --- | --- |
| `<YOUR_DOMAIN>` | `example.com` (a zone you own in Cloudflare) |
| `<HOSTNAME>` | `adx.example.com` |
| `<CF_ACCOUNT_ID>` | From Cloudflare dashboard → Overview |
| `<CF_ZONE_ID>` | Per-zone ID from the Overview page |

---

## 2. Prepare the Ubuntu 26.04 Host

### 2.1 Base packages

```bash
sudo apt update && sudo apt -y upgrade
sudo apt -y install ca-certificates curl gnupg git jq unzip
```

### 2.2 Install Docker Engine

```bash
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release; echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER
newgrp docker
docker version
```

> **Ubuntu 26.04 note:** Docker's apt repo uses the release codename. If Docker hasn't cut a 26.04 pool at the moment you run this, temporarily substitute the previous LTS codename in the `sources.list` line.

---

## 3. Clone and Launch the ADX Workshop

### 3.1 Clone

```bash
cd ~ && git clone https://github.com/dcodev1702/Cyber-Defense-Workshop-ADX.git
cd Cyber-Defense-Workshop-ADX
```

### 3.2 Start the Compose runtime

```bash
# Persist the Student database files outside the container.
mkdir -p data/local-kusto

docker compose up --detach --wait kusto
docker compose ps

# Confirm ADX is listening locally
curl -s http://127.0.0.1:8080/v1/rest/mgmt -X POST \
  -H 'Content-Type: application/json' \
  -d '{"csl":".show cluster"}' | jq .
```

The Compose defaults give the emulator four vCPUs, a 24 GiB hard memory limit, no additional swap, and a 2,048-process limit. The default-database cleaner, read-only gateway, and `cloudflared` connector each have an independent 1 GiB memory and swap limit. The Compose file binds the Kusto HTTP port only to `127.0.0.1:8080`; the `cloudflared` service reaches the read-only gateway through the internal Docker network at `tcp://kusto-readonly-gateway:8081`.

> **Bind to localhost only.** Keep the Kusto host port on `127.0.0.1`, not `0.0.0.0`. The Cloudflare connector does not need a host port because it uses the private Compose network.

⚠️ **Keep the Kusto container.** The Student database survives a clean `docker compose stop kusto` followed by `docker compose start kusto`. Do not use `docker compose down`, `docker compose rm`, or `--force-recreate` for Kusto while relying on its local persistent database. After an intentional container replacement, restore the Student snapshot with `./scripts/Copy-StudentAdxToLocalKusto.ps1 -ForceRecreate`.

`kusto-defaultdb-cleaner` runs automatically after Kustainer is healthy. When `CyberDefendStudentSnapshot` exists, it drops `NetDefaultDB` and deletes its persistent state directory. It waits during first-run bootstrap so the Student import can create the retained database before the default database is removed.

### 3.3 Verify the resource limits

```bash
docker inspect cyber-conf-wiesbaden-kusto \
  --format 'CPUs={{.HostConfig.NanoCpus}} MemoryBytes={{.HostConfig.Memory}} MemorySwapBytes={{.HostConfig.MemorySwap}}'
docker stats cyber-conf-wiesbaden-kusto --no-stream

for container in cyber-conf-wiesbaden-kusto-defaultdb-cleaner cyber-conf-wiesbaden-kusto-readonly-gateway cyber-conf-wiesbaden-cloudflared; do
  docker inspect "$container" --format '{{.Name}} MemoryBytes={{.HostConfig.Memory}} MemorySwapBytes={{.HostConfig.MemorySwap}}'
done
```

The Kusto inspect output should show `CPUs=4000000000`, `MemoryBytes=25769803776`, and `MemorySwapBytes=25769803776`. Each supporting-service inspect output should show `MemoryBytes=1073741824` and `MemorySwapBytes=1073741824`.

### 3.4 Change resource limits

Kusto resource limits require a container replacement. Preserve the current export or use the Student source as the recovery source, replace the container, then rebuild the snapshot:

```bash
KUSTO_CPU_LIMIT=4.0 KUSTO_MEMORY_LIMIT=16g KUSTO_PIDS_LIMIT=2048 \
  docker compose up --detach --wait --force-recreate kusto
pwsh ./scripts/Copy-StudentAdxToLocalKusto.ps1 -ForceRecreate
```

The replacement removes Kustainer's database registration, so the final import is required even though the persistent files remain under `data/local-kusto`.

### 3.5 Back up the local Student snapshot

Before an intentional replacement, stop only Kusto, create the archive, and start that same container again. The command prints the timestamped ZIP path and SHA-256 hash; copy the ZIP from `data\backups\local-kusto` to secure storage or Google Drive.

```powershell
docker compose stop kusto
.\scripts\Backup-LocalKustoSnapshot.ps1
docker compose start kusto
```

---

## 4. Cloudflare Tunnel

### 4.1 Prereqs

- Cloudflare account with your domain added (nameservers delegated).
- API token scoped to: **Account →** Cloudflare Tunnel:Edit, Cloudflare One Connector:Edit, Access: Apps and Policies:Edit, and Access: Service Tokens:Edit; **Zone →** DNS:Edit when Terraform manages DNS.
- Docker Compose v2 and Terraform.
- A host-installed `cloudflared` client only when using the optional browser-authorized DNS helper below.

### 4.2 Optional: install Cloudflared for browser-authorized DNS routing

```bash
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | \
  sudo tee /usr/share/keyrings/cloudflare-main.gpg > /dev/null
echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] \
  https://pkg.cloudflare.com/cloudflared any main' | \
  sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt update && sudo apt -y install cloudflared
```

### 4.3 Use the checked-in Compose connector

The checked-in Compose runtime is the supported path. It routes Cloudflare traffic to the private `kusto-readonly-gateway` service, which applies the read-only KQL policy before forwarding to Kustainer.

---

## 5. Shared Class Credential Model

Terraform creates one Cloudflare Service Token and a Service Auth policy for `adx.tier1-cyberdefense.ai`. The token defaults to 168 hours and Terraform enforces a 48-hour minimum. It is not a Cloudflare user identity, so 20-35 students can share it without consuming individual Access seats.

> ⚠️ The shared Client ID and Client Secret are a temporary class password. Distribute them only through the class channel and rotate the token after the workshop.

---

## 6. Terraform — Version-Control the Cloudflare Resources

### 6.1 Install Terraform

```bash
wget -O - https://apt.releases.hashicorp.com/gpg | \
  sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] \
  https://apt.releases.hashicorp.com $(lsb_release -cs) main" | \
  sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt -y install terraform
```

### 6.2 Validated module layout

```bash
infra/cloudflare-adx/
├── main.tf
├── outputs.tf
├── providers.tf
├── terraform.tfvars.example
├── variables.tf
└── versions.tf
```

The repository module uses Cloudflare provider `5.22.x` resource names and is the canonical configuration. It creates a remotely managed tunnel that routes TCP traffic to the read-only Kusto gateway, a self-hosted Access application with a Service Auth policy, and one shared Service Token. It also generates the Compose override: Kustainer defaults to 4 CPUs and 24 GiB memory and swap, while the cleaner, gateway, and Cloudflared connector are each pinned to 1 GiB memory and swap. If the API token has Zone DNS permission, Terraform can also manage the CNAME with `-ManageDnsWithApi`; otherwise the checked-in Cloudflared helper creates the `adx.tier1-cyberdefense.ai` CNAME through a browser-authorized Cloudflare session.

### 6.3 Apply

```bash
# Run from the repository root after setting CLOUDFLARE_API_TOKEN in your shell.
pwsh ./scripts/Start-CloudflareAdxTunnel.ps1 \
  -Apply
```

The launcher starts the Compose `kusto` service, waits for its local health check, applies the shared Service Auth route, writes the ignored `infra/cloudflare-adx/cloudflared.env` connector-token file when required, writes the shared class credential to ignored `infra/cloudflare-adx/student-access.env`, and starts the Compose `cloudflared` service. After initial provisioning, use `docker compose stop`, `docker compose start`, and `docker compose logs --follow cloudflared` for normal local lifecycle operations.

For an existing pair of containers created with the former direct Docker commands, perform the one-time migration instead:

```bash
pwsh ./scripts/Start-CloudflareAdxTunnel.ps1 \
  -Apply \
  -MigrateLegacyContainers
```

The migration removes only the named containers and preserves the bind-mounted recovery files. It also replaces Kustainer's database registration, so rebuild the Student snapshot after migration:

```bash
pwsh ./scripts/Copy-StudentAdxToLocalKusto.ps1 -ForceRecreate
```

When the API token does not have Zone DNS permission, authorize the local Cloudflared client once and create the CNAME route:

```powershell
& 'C:\Program Files (x86)\cloudflared\cloudflared.exe' tunnel login
.\scripts\Add-CloudflareAdxDnsRoute.ps1
```

The checked-in Compose connector uses `tcp://kusto-readonly-gateway:8081` on its private Docker network.

---

## 7. Validation

1. Confirm Kusto answers locally before testing the tunnel:

  ```powershell
  curl.exe -fsS http://127.0.0.1:8080/v1/rest/ping
  ```

1. On the instructor host, confirm Kusto answers locally:

  ```powershell
  curl.exe -fsS http://127.0.0.1:8080/v1/rest/ping
  ```

1. Distribute `student-access.env` and `Start-StudentAdxProxy.ps1` through the temporary class channel. On a student device, start the local proxy:

  ```powershell
  winget install --id Cloudflare.cloudflared --exact
  .\Start-StudentAdxProxy.ps1 -CredentialFile .\student-access.env
  ```

1. Confirm the student proxy answers a Kusto management query:

  ```powershell
  $body = @{ csl = '.show cluster' } | ConvertTo-Json -Compress
  Invoke-WebRequest -UseBasicParsing -Method Post `
    -ContentType 'application/json' `
    -Body $body `
    -Uri 'http://127.0.0.1:8080/v1/rest/mgmt'
  ```

1. The read-only gateway supports the ADX web UI browser origin, its required `x-ms-*` headers, and browser private-network preflight to the local proxy. If the ADX connection dialog previously failed, hard-refresh the browser with `Ctrl+F5` before retrying the exact URI `http://127.0.0.1:8080;Fed=false`.

  Use the CORS/private-network preflight diagnostic in [docs/cloudflare_adx_access.md](docs/cloudflare_adx_access.md) when the local management query succeeds but the browser still cannot add the connection.

1. Sign in to the Azure Data Explorer web UI with Microsoft Entra ID and add `http://127.0.0.1:8080;Fed=false` as the cluster connection URI. Select the `CyberDefendStudentSnapshot` database.

1. Run a basic query:

  ```kusto
  SecurityIncident
  | take 10
  ```

1. On the Docker host, inspect connector activity with `docker compose logs --follow cloudflared` and confirm the tunnel has registered a connection.

---

## 8. Hardening & Housekeeping

- **Least-privilege API token** — scope to only this account/zone.
- **Credential handling** — keep Cloudflare API tokens, R2 access keys, secret keys, and tunnel tokens in a secret manager or environment injection mechanism. Never place live values in Markdown, Terraform variables files, Git, screenshots, or terminal history.
- **Credential containment** — if a credential was ever saved in a document or committed to source control, revoke and rotate it immediately, then remove it from Git history and shared copies.
- **Remote state** — move to Azure Storage or Terraform Cloud when sharing the repo.
- **Credential rotation** — rotate the shared class credential after the workshop with `Start-CloudflareAdxTunnel.ps1 -Apply -RotateStudentCredential`.
- **Log streaming** — pipe tunnel and container logs to Log Analytics/Sentinel to correlate availability with workshop activity.
- **Container updates** — treat an image update or a Kusto container replacement as a database recovery event: keep the local export, replace the container deliberately, then run `Copy-StudentAdxToLocalKusto.ps1 -ForceRecreate`.
- **Secret rotation** — `terraform apply -replace=random_id.tunnel_secret` annually.

---

## 9. Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| `curl.exe -fsS http://127.0.0.1:8080/v1/rest/ping` fails | Kusto is not healthy on the Docker host. Check `docker compose ps` and `docker compose logs kusto`. |
| Student proxy returns `403` | The shared Service Token is expired, rotated, or missing. Distribute the current `student-access.env` file. |
| Student can query but a `.drop` or `.create` command returns `403` | Expected. The read-only gateway is enforcing immutable workshop data. |
| Azure Data Explorer cannot connect | Start the local student proxy and use the complete Kusto connection URI `http://127.0.0.1:8080;Fed=false`, not the public hostname or bare local URL. |
| ADX still cannot connect after `Fed=false` | Run the student proxy management query from the validation step. If it returns HTTP `200`, hard-refresh the ADX web UI with `Ctrl+F5`; the gateway now allows ADX browser CORS and private-network preflight. |
| Terraform reports an existing resource | Import the actual Tunnel, DNS record, Access application, or Service Token, then rerun the plan. |

---

## 10. References

- Workshop repo: <https://github.com/dcodev1702/Cyber-Defense-Workshop-ADX>
- Cloudflare Tunnel: <https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/>
- Cloudflare Service Tokens: <https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/>
- Cloudflare Terraform provider: <https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs>
- Kusto emulator: <https://learn.microsoft.com/azure/data-explorer/kusto-emulator-overview>
