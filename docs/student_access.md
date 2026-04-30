# Student access model

Students should use the Azure Data Explorer Web UI URL and sign in with a workshop-only Entra ID account. Use either Temporary Access Pass (TAP) or SMS MFA depending on your tenant policy.

## Recommended approach

1. Create a security group for the workshop students.
2. Create 20 cloud-only student users.
3. Assign either TAP or SMS-capable MFA.
4. Grant the group ADX database `viewer` access.
5. Provide each student with:
   - ADX Web UI URL
   - Username
   - Initial password
   - TAP value or SMS MFA instructions

## Scripts

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

- Entra permissions: Global Administrator, Privileged Role Administrator, or User Administrator plus Authentication Administrator for TAP
- Azure permissions: Owner or User Access Administrator on the ADX resource scope, and database admin rights in ADX
- PowerShell modules: `Az.Accounts`, `Az.Kusto`, `Microsoft.Graph.Users`, `Microsoft.Graph.Groups`, and `Microsoft.Graph.Identity.SignIns` when creating TAP values

## Operational notes

- Prefer workshop-only users, not real employee identities.
- Set TAP lifetime to cover check-in, the two-hour workshop, and troubleshooting buffer.
- If using SMS MFA, pre-stage phone numbers or have students register MFA before the lab starts.
- Keep the roster CSV out of source control and delete it after the event.
