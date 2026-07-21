# Changelog

## Unreleased

- Replaced the manual local Kusto and Cloudflared container workflow with Docker Compose, keeping Kusto bound to `127.0.0.1:8080` and routing the tunnel over an internal Compose network.
- Updated the Cloudflare Tunnel launcher to provision the remote resources, create an ignored connector-token environment file, and support a one-time migration from legacy containers.
- Preserved the Cloudflare Access session duration at one week (`168h`).
- Configured Kustainer for a graceful `SIGINT` shutdown so the mounted Student snapshot remains available across normal Compose stop/start cycles.
- Added a source-of-truth workflow that copies the live Student ADX database into a persistent local Kusto emulator and verifies table row counts.
- Updated the Cloudflare/Terraform runbook for the 4-vCPU, 4-GiB default Compose profile and removed plaintext credential material.
- Added a Cloudflare provider v5 Terraform module and secure environment-driven connector launcher for `adx.tier1-cyberdefense.ai`.
- Added browser-authorized Cloudflared DNS routing for restricted API tokens and made tunnel launcher reruns preserve a healthy connector.
- Added an ignored local Cloudflare Access email allow-list to support workshop cohorts without committing participant identities.
- Added Cloudflare One-Time PIN login so allowed workshop users do not need Cloudflare accounts.
