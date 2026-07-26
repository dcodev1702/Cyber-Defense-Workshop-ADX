# Security Policy

This repository contains a conference teaching lab: synthetic telemetry, schemas,
and the tooling that stands up a local Kustainer emulator behind a Cloudflare
tunnel and a read-only gateway. It is not a production service. Even so, the lab
is designed to survive a room full of curious security practitioners, so security
reports are welcome.

## Reporting a vulnerability

Please report suspected vulnerabilities privately rather than opening a public
issue:

- Use GitHub's **private vulnerability reporting** ("Report a vulnerability" under
  the Security tab), or
- Email the maintainer listed on the GitHub profile for `dcodev1702`.

Include what the issue is, how to reproduce it, and the impact you see. We aim to
acknowledge a report within a few business days.

## Scope

In scope:

- The read-only gateway (`tools/kusto-readonly-gateway/`) — its statement
  validation, canonical forwarding, `.show` allowlist, database allowlist, and
  rate limiting are the lab's policy boundary.
- The Compose topology and container hardening (`compose.yaml`).
- The telemetry-safety controls that keep tenant data out of the repository
  (`.githooks/pre-commit`, `.github/workflows/telemetry-safety.yml`,
  `scripts/Test-RepositorySafety.ps1`, `scripts/Test-FieldProfileSafety.ps1`).

Out of scope / by design:

- Kustainer itself has no authentication; the gateway and the Cloudflare tunnel
  are what constrain access. A host administrator with direct access to
  `127.0.0.1:8080` can always send unrestricted commands. This is documented, not
  a defect.
- The shared Cloudflare Service Token used for the classroom tunnel is an
  intentional simplification for a time-boxed event and is rotated or deleted
  afterward.

## Handling tenant data

The generated telemetry is synthetic. The field profiles that ground it are
scanned for real tenant identifiers on every commit and in CI. If you find live
tenant data (a subscription GUID, a real UPN, an `onmicrosoft.com` domain, a
token) anywhere in the tracked tree, treat it as a security issue and report it
privately.
