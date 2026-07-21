# Cloudflare Access Guide for the Containerized ADX Lab

## Purpose

Use this guide for the containerized Azure Data Explorer (ADX) lab that is exposed through Cloudflare Tunnel and protected by Cloudflare Access One-time PIN (OTP) email authentication.

This is a separate access model from the managed Azure ADX cluster and its Microsoft Entra B2B access described in [student_access.md](student_access.md).

## Working connection details

| Item | Value |
| --- | --- |
| Cloudflare Tunnel | `cyber-conf-wiesbaden-kusto` |
| Protected hostname | `adx.tier1-cyberdefense.ai` |
| Participant local listener | `127.0.0.1:8080` |
| ADX endpoint protocol | HTTP |
| Database | `CyberDefendStudentSnapshot` |

Connection flow:

```text
Participant browser and cloudflared
    -> Cloudflare Access OTP policy
    -> Cloudflare Tunnel
    -> ADX container on the tunnel origin
```

## Credential boundary: administrators versus participants

The two Cloudflare authentication flows have different purposes and must not be mixed.

| Role | Command or credential | What it grants | Who receives it |
| --- | --- | --- | --- |
| Tunnel administrator | `cloudflared tunnel login` creates `%USERPROFILE%\.cloudflared\cert.pem` | Named-tunnel administration, including listing, creating, and routing locally managed tunnels | Only the Cloudflare tunnel administrator |
| Tunnel connector | Tunnel token or tunnel credentials file | Permission for the connector host to run the specific tunnel | Only the managed tunnel origin or connector host |
| ADX participant | `cloudflared access tcp` plus email One-time PIN | A temporary Cloudflare Access session to the protected ADX hostname | Each participant whose email matches the Access Allow policy |

Participants do **not** run `cloudflared tunnel login`, do **not** receive `cert.pem`, and do **not** receive a tunnel token or credentials file. After they enter an approved email address and a valid One-time PIN, Cloudflare gives their local `cloudflared` process a temporary Access session for `adx.tier1-cyberdefense.ai`. That session does not grant any tunnel-management capability and expires according to the Access application session duration.

## Administrator: configure the origin and tunnel

Complete these steps once for the lab host. Participants do not need Cloudflare account access or a tunnel token.

1. In the Cloudflare dashboard, go to **Zero Trust** > **Networking** > **Tunnels**.
2. Open `cyber-conf-wiesbaden-kusto` and confirm that at least one connector is **Healthy**.
3. On the tunnel's **Routes** tab, confirm the published application route has:
   - Hostname: `adx.tier1-cyberdefense.ai`
   - Service: the ADX container HTTP endpoint, normally `http://127.0.0.1:8080` when the container and connector run on the same host.
4. On the tunnel origin, verify that the container answers before troubleshooting Cloudflare:

   ```powershell
   curl.exe -fsS http://127.0.0.1:8080/v1/rest/ping
   ```

   If the connector and container run on different machines, replace `127.0.0.1` with the container host's private address in the tunnel route.
5. Keep the tunnel connector running as a service or other managed process. Do not expose the container's port directly to the Internet.

Expected result: the tunnel shows a healthy connector and the route points to a responding ADX container.

## Administrator: enable OTP and authorize email addresses

### Enable the One-time PIN identity provider

1. In the Cloudflare dashboard, go to **Zero Trust** > **Integrations** > **Identity providers**.
2. Under **Your identity providers**, select **Add new identity provider**.
3. Select **One-time PIN** and save it. If it already exists, confirm that it remains enabled.
4. Open **Zero Trust** > **Access controls** > **Applications**, then open the Access application for `adx.tier1-cyberdefense.ai`.
5. Confirm that **One-time PIN** is available as an identity provider for this application.

### Add individual participant email addresses

There is no separate Cloudflare OTP user roster. An address is allowed only when an **Allow** policy for this application matches it.

1. Go to **Zero Trust** > **Access controls** > **Policies**.
2. Select **Add a policy**.
3. Set a clear name, such as `Cyber Conference ADX participants`.
4. Set **Action** to **Allow**.
5. Set a session duration appropriate for the workshop. A short event-scoped duration limits access after the session ends.
6. Add an **Include** rule with selector **Emails**.
7. Enter each approved participant email address and save the policy.
8. Open the `adx.tier1-cyberdefense.ai` Access application and attach the policy.

For a small roster, keeping the email addresses directly in this policy is simplest.

### Use a reusable rule group for a larger roster

For multiple workshops or a changing participant list, use a Cloudflare **Rule group**:

1. Go to **Zero Trust** > **Access controls** > **Policies** > **Rule groups**.
2. Select **Add a group** and name it, for example, `Cyber Conference ADX participants`.
3. Add an **Include** rule with selector **Emails**, then enter the approved addresses.
4. Save the rule group.
5. In the ADX application's Allow policy, add an **Include** rule with selector **Rule groups** and select the new group.

Update the rule group to add or remove participants without editing every application policy.

### Important policy guardrails

- Cloudflare Access is deny by default. A participant must match an **Allow** policy.
- Use **Emails** for a curated event roster. Use **Emails ending in** only when every address in that email domain should have access.
- Do not use **Include** > **Login Methods** > **One-time PIN** as the only Allow rule. That permits every user who can authenticate with OTP, not just invited participants.
- If a mail security gateway scans participant mail, allow `noreply@notify.cloudflare.com` so the OTP arrives and is not consumed by link scanning.
- Use the application's **Policies** > **Policy tester** with a participant address before distributing the instructions.

Expected result: the Policy tester reports the participant as allowed, while an unlisted test address is denied.

## Participant: connect to the ADX lab

### 1. Install cloudflared

On Windows, open PowerShell and run:

```powershell
winget install --id Cloudflare.cloudflared --exact
```

Open a new terminal after installation. Participants do not run `cloudflared tunnel login`; that command is for tunnel administrators.

### 2. Start the local Cloudflare Access proxy

Run this command and leave the terminal open for the entire ADX session:

```powershell
cloudflared access tcp --hostname adx.tier1-cyberdefense.ai --url 127.0.0.1:8080
```

On the first connection, or after the Access session expires, `cloudflared` opens a browser window. If it prints a URL instead, open that URL in a browser.

### 3. Authenticate with the email One-time PIN

1. Enter the same email address that the workshop administrator added to the Access Allow policy.
2. Select **Send login code**.
3. Check the inbox for a message from `noreply@notify.cloudflare.com`.
4. Enter the PIN and select **Sign in**.

Expected result: the browser confirms the login and the terminal remains running with a local listener on `127.0.0.1:8080`.

The PIN expires after 10 minutes, can be used only once, and requesting a new PIN invalidates the previous one.

### 4. Open ADX and run a query

1. Open Azure Data Explorer Web UI.
2. Add or select the cluster endpoint:

   ```text
   http://127.0.0.1:8080
   ```

3. Select the `CyberDefendStudentSnapshot` database.
4. Run this validation query:

   ```kusto
   .show tables | project TableName
   ```

5. Run a workshop query, for example:

   ```kusto
   DeviceEvents
   | take 10
   ```

Expected result: the database and tables are visible, and KQL returns results. A Microsoft sign-in prompt from the Azure Data Explorer web site, if shown, is separate from the Cloudflare OTP prompt.

## Troubleshooting

| Symptom | Likely cause and action |
| --- | --- |
| The browser says that a code was emailed, but no message arrives | Cloudflare intentionally shows this generic response for blocked users. Confirm the exact address is in the application's Allow policy or rule group, then check spam and mail filtering. |
| `That account does not have access` | The address did not match an Allow policy, an exclusion applied, or the user entered a different address. Use the application's Policy tester. |
| `This One-Time PIN has already been used` | Request a fresh code. Mail security software may have followed the link or scanned the message. Allowlist `noreply@notify.cloudflare.com`. |
| `cloudflared` cannot listen on port 8080 | Another process already uses the local port. Check with `Get-NetTCPConnection -LocalPort 8080`. Stop that process or choose an unused local port and use the same port in the ADX endpoint. |
| ADX cannot connect after OTP succeeds | Keep the `cloudflared access tcp` terminal open. Verify the local endpoint is `http://127.0.0.1:8080`, then ask the administrator to check connector health, the published route, and the container health endpoint. |
| Access worked earlier but now redirects to login | The Access session expired. Rerun the `cloudflared access tcp` command and complete OTP again. |

## End-of-event steps

1. Remove participant addresses from the Allow policy or rule group.
2. Keep the Access session duration short for event access.
3. Review Access authentication logs for unexpected activity.
4. Stop the client-side `cloudflared` process on participant devices when the session ends.

## References

- [Cloudflare One-time PIN login](https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/one-time-pin/)
- [Cloudflare Access policies](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [Cloudflare client-side cloudflared](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/non-http/cloudflared-authentication/)
