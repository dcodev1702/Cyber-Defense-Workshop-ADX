# Cyber Range user provisioning

This guide describes how exercise participants are provisioned to access the Cyber Range Azure Data Explorer (ADX) database and dashboard. For conference delivery, participants should use Microsoft Entra B2B guest access rather than shared accounts, local throwaway passwords, or unmanaged tenant users.

The access model aligns to Microsoft's [Secure Future Initiative](https://www.microsoft.com/en-us/security/blog/2024/05/03/security-above-all-else-expanding-microsofts-secure-future-initiative/) emphasis on protected identities, least privilege, tenant isolation, and MFA. In particular, the exercise should enforce MFA for guest access and avoid password-based workshop-only accounts where external identities can be governed through B2B.

## Recommended model

Use one Microsoft Entra security group as the control point for all participant access. Put that group in the resource tenant that owns the ADX cluster and database.

Recommended flow:

1. Create a resource-tenant security group such as `sg-cyber-range-adx-participants`.
2. Create a Microsoft Entra entitlement management access package such as `Cyber Range ADX Participant`.
3. Add the participant security group as a resource in the access package with the `Member` role.
4. Configure an external-user policy for the expected partner or conference domains. Require approval and set an assignment expiration that covers the event plus a short troubleshooting buffer.
5. Require MFA for guest users with Conditional Access. If a partner tenant already enforces MFA, decide whether cross-tenant access settings should trust that home-tenant MFA claim; otherwise require MFA in the resource tenant.
6. Assign ADX database and dashboard access to the participant security group, not to individual users.
7. Send participants the My Access request link, the ADX Web UI database URL, the dashboard link, and any workshop instructions after access is approved.

Entitlement management is preferred because it can invite approved external users as B2B guests, add them to the access-package resources, time-limit access, and remove the guest account lifecycle when access expires if the user has no other assignments.

## Required participant permissions

The participant security group needs two ADX-facing permissions for the full exercise experience.

| Capability | Required permission | Why it is needed |
| --- | --- | --- |
| Open the dashboard | Dashboard `Can view` permission | ADX dashboards have their own share permissions. Students need dashboard permission and the dashboard link. |
| Query the workshop database and render dashboard tiles | ADX database `Viewer` role on `cyber-defend-q0xxzc` | `Viewer` can read database data and metadata, except tables protected by the `RestrictedViewAccess` policy. This is the least-privilege role for read-only KQL labs. |
| Type KQL in the ADX Web UI and observe query results | ADX database `Viewer` role on `cyber-defend-q0xxzc` | Query execution is authorized by ADX data-plane roles, not by Azure portal roles. |

Do not grant Azure `Owner`, `Contributor`, or ADX `User`/`Admin` roles to participants. ADX `User` can create tables and functions and becomes admin of objects it creates, which is unnecessary for the exercise. ADX `Monitor` is also insufficient because it only allows metadata `.show` commands, not data queries. Azure Resource Manager roles such as `Reader` are for Azure resource administration and portal discovery; they are not required when students use the ADX Web UI database URL and dashboard link directly.

Only add the ADX database `Unrestrictedviewer` role if the workshop database uses the `RestrictedViewAccess` policy on tables that participants must query. `Unrestrictedviewer` is additive and still requires `Viewer`, `User`, or `Admin`.

## Assign ADX database access

Assign the participant security group to the database-level `viewers` role. This can be done in the Azure portal from the ADX database permissions blade, or with a Kusto management command run by a database admin.

Example command:

```kusto
.add database ['cyber-defend-q0xxzc'] viewers ('aadgroup=<security-group-object-id>;<resource-tenant-id>') 'Cyber Range participant read-only access'
```

Use the resource tenant ID because the group lives in the tenant that owns the ADX resource. A group object ID is preferred over a display name because it is stable and avoids ambiguity.

Validate the assignment:

```kusto
.show database ['cyber-defend-q0xxzc'] principals
```

## Share the dashboard

ADX dashboard sharing requires all of the following:

- The dashboard link.
- Dashboard permission, usually `Can view` for the participant security group.
- Access to the underlying ADX database.

In the ADX Web UI, open the dashboard, switch to Editing mode, select `Share`, choose `Manage access`, add the participant security group, and grant `Can view`. Then copy and distribute the dashboard link.

Because participants are B2B guests represented in the resource tenant and are members of the resource-tenant security group, the recommended share target is the group. If you instead share directly to users or groups in another tenant, cross-tenant dashboard sharing must be enabled in the ADX Web UI settings, and invitees must accept the dashboard invitation.

## Conditional Access and MFA

For SFI-aligned delivery, require MFA for guest users who access the Cyber Range resources. The resource tenant remains responsible for enforcing its Conditional Access policy. For guests from another Microsoft Entra tenant, cross-tenant access settings can optionally trust MFA claims from the home tenant so users do not have to register MFA twice.

Before the event, test with a pilot guest account and the Conditional Access What If tool. Confirm the policy does not block My Access, invitation redemption, dashboard access, or the ADX Web UI sign-in path.

## Participant handout values

Participants should receive:

- The My Access request link for the `Cyber Range ADX Participant` access package.
- The ADX Web UI database URL, for example `https://dataexplorer.azure.com/clusters/dibsecadx.eastus2.kusto.windows.net/databases/cyber-defend-q0xxzc`.
- The ADX dashboard link after dashboard permissions are assigned.
- The workshop KQL instructions or lab file reference.

Participants should not receive shared credentials or temporary passwords for a resource-tenant account. They sign in with their own home organization identity, redeem B2B access when prompted, complete MFA, and then access the Cyber Range resources through the resource tenant.

## Validation checklist

Validate with at least one pilot participant before the workshop:

1. The participant can request the access package from My Access.
2. Approval creates or uses the B2B guest object and adds the guest to the participant security group.
3. The participant can open the ADX Web UI database URL.
4. The participant can run `SecurityIncident | take 5` and see results.
5. The participant can open the dashboard link and dashboard tiles render.
6. The participant can use `View query` on a dashboard tile and open the query in a new query tab.
7. The participant cannot edit the dashboard, create tables, create functions, ingest data, or administer ADX resources.

Allow for Entra group membership and ADX permission propagation delay during testing.

## Offboarding

After the event, expire or remove the access package assignments. Confirm the participant security group membership is empty, and confirm external guest lifecycle settings block or remove B2B accounts when they no longer have access package assignments.

If any dashboard access was granted directly to individuals instead of the group, remove those dashboard permissions manually.

## Microsoft references

- [Secure Future Initiative expansion](https://www.microsoft.com/en-us/security/blog/2024/05/03/security-above-all-else-expanding-microsofts-secure-future-initiative/)
- [Microsoft Entra B2B collaboration](https://learn.microsoft.com/en-us/entra/external-id/what-is-b2b)
- [Govern access for external users in entitlement management](https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-external-users)
- [Enforce MFA for B2B guest users](https://learn.microsoft.com/en-us/entra/external-id/b2b-tutorial-require-mfa)
- [Cross-tenant access settings](https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-overview)
- [ADX role-based access control](https://learn.microsoft.com/en-us/kusto/access-control/role-based-access-control?view=azure-data-explorer)
- [Manage ADX database security roles](https://learn.microsoft.com/en-us/kusto/management/manage-database-security-roles?view=azure-data-explorer)
- [Share ADX dashboards](https://learn.microsoft.com/en-us/azure/data-explorer/azure-data-explorer-dashboard-share)
- [Query data in the ADX Web UI](https://learn.microsoft.com/en-us/azure/data-explorer/web-query-data)