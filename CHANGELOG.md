# Changelog

## Unreleased

- Replaced the manual local Kusto and Cloudflared container workflow with Docker Compose, keeping Kusto bound to `127.0.0.1:8080` and routing the tunnel over an internal Compose network.
- Updated the Cloudflare Tunnel launcher to provision the remote resources, create an ignored connector-token environment file, and support a one-time migration from legacy containers.
- Added a shared 48-hour-minimum Cloudflare Service Auth credential and read-only KQL gateway for classroom access without per-student Cloudflare seats.
- Documented `Fed=false` for student Kustainer connection URIs so ADX clients do not attempt Microsoft Entra authentication against the local emulator.
- Added ADX web UI CORS and private-network preflight support to the read-only gateway for browser connections through the local student proxy.
- Updated class, instructor, managed-access, and troubleshooting documentation for the shared 72-hour Service Token, `Fed=false` connection URI, read-only gateway, and ADX browser CORS/private-network recovery path.
- Added a continuous Kustainer cleaner that removes `NetDefaultDB` and its persistent state after the Student snapshot database is available.
- Added a dedicated gateway reference describing its read-only policy, browser support, cleaner lifecycle, configuration, and security boundary.
- Configured Kustainer for a graceful `SIGINT` shutdown so the mounted Student snapshot remains available across normal Compose stop/start cycles.
- Added a source-of-truth workflow that copies the live Student ADX database into a persistent local Kusto emulator and verifies table row counts.
- Increased the Terraform-managed Kustainer profile from 16 GiB to 24 GiB of memory and swap while retaining 4 vCPUs, with a Terraform-generated Compose override and in-place runtime synchronization that preserves the Student snapshot.
- Added a Cloudflare provider v5 Terraform module and secure environment-driven connector launcher for `adx.tier1-cyberdefense.ai`.
- Added browser-authorized Cloudflared DNS routing for restricted API tokens and made tunnel launcher reruns preserve a healthy connector.
