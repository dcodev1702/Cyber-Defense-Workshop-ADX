# Cyber Defense Workshop — ADX
### End-to-End Walkthrough
*Local ADX in Docker · Cloudflare Tunnel · Cloudflare Access (Pro) · Terraform IaC*

**Prepared for:** Lorenzo Ireland — Sr. Cloud Solution Architect, Microsoft
**Version:** 1.1 · July 2026

---

## 1. Overview

This walkthrough documents an end-to-end lab that spins up the **Cyber-Defense-Workshop-ADX** repository inside Docker on your Ubuntu 26.04 host, then publishes the local Azure Data Explorer instance to a single trusted collaborator over the internet using **Cloudflare Tunnel** and **Cloudflare Access (Pro)** with One-Time PIN identity. The Cloudflare resources are defined in **Terraform** so the policy is version-controlled and reproducible.

Reference repo: https://github.com/dcodev1702/Cyber-Defense-Workshop-ADX

| Component | Purpose |
|---|---|
| Ubuntu 26.04 host | Docker engine host running ADX + supporting services |
| Cyber-Defense-Workshop-ADX | KQL / ADX workshop content packaged for local lab use |
| Kusto emulator | Persistent local ADX-compatible query engine, capped at 4 vCPUs and 4 GiB RAM by default |
| Cloudflare Tunnel (`cloudflared`) | Outbound-only tunnel from your host to Cloudflare's edge — no inbound ports |
| Cloudflare Access (Pro) | Zero-Trust gateway with One-Time PIN, restricted to a specific email |
| Terraform | Declarative, version-controlled Tunnel + DNS + Access app/policy |

> **Design principle:** No inbound ports are opened on your host. All traffic is initiated outbound by `cloudflared`. Access enforces identity before the request ever reaches your container.

### Placeholders used throughout

| Placeholder | Example |
|---|---|
| `<YOUR_DOMAIN>` | `example.com` (a zone you own in Cloudflare) |
| `<HOSTNAME>` | `adx.example.com` |
| `<BUDDY_EMAIL>` | `buddy@company.com` |
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

The Compose defaults give the emulator four vCPUs, a 4 GiB hard memory limit, no additional swap, and a 2,048-process limit. The Compose file binds the Kusto TCP port only to `127.0.0.1:8080`; the `cloudflared` service reaches Kusto through the internal Docker network at `tcp://kusto:8080`.

> **Bind to localhost only.** Keep the Kusto host port on `127.0.0.1`, not `0.0.0.0`. The Cloudflare connector does not need a host port because it uses the private Compose network.

> ⚠️ **Keep the Kusto container.** The Student database survives a clean `docker compose stop kusto` followed by `docker compose start kusto`. Do not use `docker compose down`, `docker compose rm`, or `--force-recreate` for Kusto while relying on its local persistent database. After an intentional container replacement, restore the Student snapshot with `./scripts/Copy-StudentAdxToLocalKusto.ps1 -ForceRecreate`.

### 3.3 Verify the resource limits
```bash
docker inspect cyber-conf-wiesbaden-kusto \
  --format 'CPUs={{.HostConfig.NanoCpus}} MemoryBytes={{.HostConfig.Memory}} MemorySwapBytes={{.HostConfig.MemorySwap}}'
docker stats cyber-conf-wiesbaden-kusto --no-stream
```

The default inspect output should show `CPUs=4000000000`, `MemoryBytes=4294967296`, and `MemorySwapBytes=4294967296`.

### 3.4 Change resource limits

Kusto resource limits require a container replacement. Preserve the current export or use the Student source as the recovery source, replace the container, then rebuild the snapshot:

```bash
KUSTO_CPU_LIMIT=4.0 KUSTO_MEMORY_LIMIT=16g KUSTO_PIDS_LIMIT=2048 \
  docker compose up --detach --wait --force-recreate kusto
pwsh ./scripts/Copy-StudentAdxToLocalKusto.ps1 -ForceRecreate
```

The replacement removes Kustainer's database registration, so the final import is required even though the persistent files remain under `data/local-kusto`.

---

## 4. Cloudflare Tunnel

### 4.1 Prereqs
- Cloudflare account with your domain added (nameservers delegated).
- API token scoped to: **Account →** Cloudflare Tunnel:Edit, Access:Edit; **Zone →** DNS:Edit.
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

### 4.3 Optional manual connector path

Use this path only when intentionally running `cloudflared` directly on the host instead of the checked-in Docker Compose runtime.

1. Zero Trust dashboard → **Networks → Tunnels → Create a tunnel**.
2. Choose **Cloudflared**, name it `adx-workshop`.
3. Copy the install/run command shown; execute on the Ubuntu host.
4. **Public Hostnames:** Subdomain `adx`, Domain `<YOUR_DOMAIN>`, Service `tcp://127.0.0.1:8080`.

### 4.4 Optional manual CLI connector path
```bash
cloudflared tunnel login
cloudflared tunnel create adx-workshop
cloudflared tunnel route dns adx-workshop adx.<YOUR_DOMAIN>

sudo mkdir -p /etc/cloudflared
sudo tee /etc/cloudflared/config.yml >/dev/null <<'YAML'
tunnel: adx-workshop
credentials-file: /root/.cloudflared/<TUNNEL_UUID>.json
ingress:
  - hostname: adx.<YOUR_DOMAIN>
    service: tcp://127.0.0.1:8080
  - service: http_status:404
YAML

sudo cloudflared service install
sudo systemctl enable --now cloudflared
```

---

## 5. Cloudflare Access (Pro) — Restrict to Your Buddy

1. Zero Trust → **Access → Applications → Add → Self-hosted**.
2. Name: `ADX Workshop`. Session duration: `168h` (one week).
3. Application domain: `adx.<YOUR_DOMAIN>`.
4. Identity providers: leave **One-Time PIN** enabled (default on Pro).
5. Add policy: **Buddy Only**, Action *Allow*, Include → *Emails* → `<BUDDY_EMAIL>`.

> **Why OTP is a great fit:** Your buddy doesn't need a Cloudflare/Google/SSO account. Cloudflare emails a 6-digit code; Access issues a signed cookie for the session length. Zero standing credentials.

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

The repository module uses Cloudflare provider `5.22.x` resource names and is the canonical configuration. It creates a remotely managed tunnel, a One-Time PIN identity provider, and an Access policy based on the local `infra\cloudflare-adx\allowed-emails.txt` allow-list. Add one user email per line, then rerun the deployment script to synchronize the Cloudflare Access policy. Users can select One-Time PIN and receive a short-lived code through the email address listed in the policy; no Cloudflare account is required. If the API token has Zone DNS permission, Terraform can also manage the CNAME with `-ManageDnsWithApi`; otherwise the checked-in Cloudflared helper creates the `adx.tier1-cyberdefense.ai` CNAME through a browser-authorized Cloudflare session.

### 6.3 Apply
```bash
# Run from the repository root after setting CLOUDFLARE_API_TOKEN in your shell.
pwsh ./scripts/Start-CloudflareAdxTunnel.ps1 \
  -Apply
```

The launcher starts the Compose `kusto` service, waits for its local health check, applies the remotely managed Cloudflare Tunnel and Access policy, writes the ignored `infra/cloudflare-adx/cloudflared.env` connector-token file when required, and starts the Compose `cloudflared` service. After initial provisioning, use `docker compose stop`, `docker compose start`, and `docker compose logs --follow cloudflared` for normal local lifecycle operations.

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

The checked-in Compose connector uses `tcp://kusto:8080` on its private Docker network. Set `local_service = "tcp://127.0.0.1:8080"` only for the optional host-installed `cloudflared` connector.

---

## 7. Validation

1. Confirm the protected endpoint redirects to Cloudflare Access:

  ```text
  https://adx.tier1-cyberdefense.ai
  ```

1. On the remote analyst's computer, install `cloudflared`, then start a local authenticated TCP proxy:

  ```powershell
  cloudflared access tcp --hostname adx.tier1-cyberdefense.ai --url localhost:8080
  ```

  Cloudflare Access opens a browser session. The analyst selects **One-Time PIN**, enters an email allowed by the policy, and completes the code delivered to that mailbox.

1. In Kusto Explorer, allow unsafe connections and connect to `http://localhost:8080` with Microsoft Entra authentication disabled. Select the `CyberDefendStudentSnapshot` database.

1. Run a basic query:

  ```kusto
  SecurityIncident
  | take 10
  ```

1. On the Docker host, inspect connector activity with `docker compose logs --follow cloudflared`. In Zero Trust → Logs → Access, confirm the matching authenticated email event.

---

## 8. Hardening & Housekeeping

- **Least-privilege API token** — scope to only this account/zone.
- **Credential handling** — keep Cloudflare API tokens, R2 access keys, secret keys, and tunnel tokens in a secret manager or environment injection mechanism. Never place live values in Markdown, Terraform variables files, Git, screenshots, or terminal history.
- **Credential rotation** — if a credential was ever saved in a document or committed to source control, revoke and rotate it immediately, then remove it from Git history and shared copies.
- **Remote state** — move to Azure Storage or Terraform Cloud when sharing the repo.
- **Session length** — shorten to 1–8h for higher-sensitivity data.
- **Log streaming** — pipe Zero Trust logs to Log Analytics/Sentinel to correlate with your Defender XDR hunts.
- **Container updates** — treat an image update or a Kusto container replacement as a database recovery event: keep the local export, replace the container deliberately, then run `Copy-StudentAdxToLocalKusto.ps1 -ForceRecreate`.
- **Secret rotation** — `terraform apply -replace=random_id.tunnel_secret` annually.

---

## 9. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Access page loops / error 1033 | DNS CNAME not proxied, or Tunnel not connected. Check orange cloud and `cloudflared` status. |
| PIN never arrives | Check spam; verify email is in include list; try lowercase. |
| 502/504 from Access | `cloudflared` can't reach the local service — container down or bound to wrong interface. |
| Terraform "already exists" | `terraform import cloudflare_access_application.adx <ACCOUNT_ID>/<APP_ID>`. |

---

## 10. References

- Workshop repo: <https://github.com/dcodev1702/Cyber-Defense-Workshop-ADX>
- Cloudflare Tunnel: <https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/>
- Cloudflare Access: <https://developers.cloudflare.com/cloudflare-one/policies/access/>
- Cloudflare Terraform provider: <https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs>
- Kusto emulator: <https://learn.microsoft.com/azure/data-explorer/kusto-emulator-overview>
