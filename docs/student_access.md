# Student access model

> This guide applies only to the managed Azure ADX deployment protected by Microsoft Entra B2B. For the containerized class lab, use [cloudflare_adx_access.md](cloudflare_adx_access.md): it uses a shared 168-hour Cloudflare Service Token, the local student proxy, `http://127.0.0.1:8080;Fed=false`, and the read-only gateway instead of B2B database roles.

For conference delivery, use the SFI-aligned B2B provisioning model in [`..\user_creation\README.md`](../user_creation/README.md). Participants should authenticate with their own home organization identities, redeem Microsoft Entra B2B guest access in the resource tenant, satisfy MFA, and receive access through a participant security group.

The helper scripts below are retained for internal-only rehearsals or isolated tenant builds where cloud-only workshop accounts are explicitly acceptable. Do not use shared accounts or unmanaged temporary passwords for external conference participants.

## Recommended conference approach

1. Create a resource-tenant security group for the workshop participants.
2. Create an entitlement management access package that adds approved users to that group.
3. Require approval, MFA, and an assignment expiration that covers the event.
4. Grant the group ADX database `viewer` access.
5. Share the ADX dashboard with the same group using dashboard `Can view` permission.
6. Provide each participant with:
   - My Access request link
   - ADX Web UI database URL
   - ADX dashboard link
   - Workshop lab instructions

## Scripts

These scripts create or grant access for local workshop accounts and should be treated as an internal-only fallback.

Create the roster only:

```powershell
.\scripts\New-WorkshopStudents.ps1 `
  -TenantDomain 'contoso.onmicrosoft.com' `
  -InitialPassword '<temporary-password>'
```

Create users, a group, and TAP values:

```powershell
.\scripts\New-WorkshopStudents.ps1 `
  -TenantDomain 'contoso.onmicrosoft.com' `
  -InitialPassword '<temporary-password>' `
  -CreateUsers `
  -CreateTemporaryAccessPass
```

Grant ADX access to the group:

```powershell
.\scripts\Grant-StudentAdxAccess.ps1 `
  -ClusterUri 'https://<cluster>.<region>.kusto.windows.net' `
  -DatabaseName 'CyberDefenseKqlWorkshop' `
  -GroupObjectId '<group-object-id>'
```

## Required roles and modules

- Entra permissions for B2B delivery: Identity Governance Administrator or delegated access package manager, security group owner, Conditional Access Administrator, and Security Administrator if cross-tenant access settings must be changed
- Entra permissions for internal-only helper scripts: Global Administrator, Privileged Role Administrator, or User Administrator plus Authentication Administrator for TAP
- Azure/ADX permissions: database admin rights in ADX to grant database roles; Azure Owner or Contributor is not required for participants
- PowerShell modules: `Az.Accounts`, `Az.Kusto`, `Microsoft.Graph.Users`, `Microsoft.Graph.Groups`, and `Microsoft.Graph.Identity.SignIns` when creating TAP values

## Operational notes

- Prefer governed B2B guest access for external participants.
- Set TAP lifetime to cover check-in, the two-hour workshop, and troubleshooting buffer.
- If using internal-only SMS MFA, pre-stage phone numbers or have students register MFA before the lab starts.
- Keep the roster CSV out of source control and delete it after the event.
- Expire or remove access package assignments after the event and confirm the participant security group is empty.
