# How the Jupyter Notebook Connects to Kusto Through Cloudflare

## Short Answer

The notebook contains its own `%%kql` implementation. It is not a command built into Jupyter, IPython, or a separately installed Kusto extension. The Section 3 Python cell registers a custom IPython cell magic named `kql`, and that function sends the cell body to Kusto with Python's standard-library HTTP client.

The notebook does not discover a cluster URI, database, or health routes. They are explicit constants and paths in the notebook:

| Setting | Value |
| --- | --- |
| Client base URL | `http://127.0.0.1:8080` |
| Database | `CyberDefendStudentSnapshot` |
| Query route | `/v1/rest/query` |
| Management route | `/v1/rest/mgmt` |
| Kusto health route | `/v1/rest/ping` |
| Gateway health route | `/healthz` |

Section 2 decides what is listening behind the loopback URL. Section 3 verifies that route, creates the REST client, and registers `%%kql` for the current kernel.

## What IPython Provides

Jupyter supplies the notebook document and user interface, while `ipykernel` runs its Python cells. That Python kernel is built on IPython, an interactive Python runtime that adds notebook-oriented capabilities beyond the standard Python interpreter.

This notebook uses IPython for three specific jobs:

- **Persistent kernel state:** names created by one cell remain available to later cells. Section 2 stores `TUNNEL_STATUS`; Section 3 reads it and stores `ENDPOINT_STATUS` and `CONTAINER_IS_LOCAL`.
- **The magic-command system:** IPython recognizes line magics such as `%name` and cell magics such as `%%name`. The notebook uses `get_ipython().register_magic_function(...)` to add its own `%%kql` cell magic at runtime.
- **Rich notebook output:** `IPython.display.HTML` and `display` render the color-coded connection status and investigation-flow results in the notebook interface.

IPython does **not** discover the Kusto endpoint, authenticate Cloudflare, translate KQL, or enforce read-only access. Those responsibilities belong respectively to the notebook's fixed configuration, the `cloudflared` process, Kusto itself, and the read-only gateway. IPython only supplies the live Python execution environment and the extension point that lets the notebook treat a cell body as KQL.

The custom registration exists only in the current kernel process. Restarting the kernel clears the Python variables and magic registration, which is why Sections 2 and 3 must be rerun.

## Request Path

The notebook always sends HTTP requests to the same local address. It never sends KQL directly to the public Cloudflare hostname.

```text
Jupyter/IPython kernel
    -> Python urllib request
    -> http://127.0.0.1:8080
       -> local mode: Kustainer
       -> Cloudflare mode: cloudflared access tcp
           -> Cloudflare Access Service Auth
           -> Cloudflare Tunnel
           -> read-only Kusto gateway
           -> Kustainer
```

This gives the notebook one client configuration for two operating modes:

- **Local mode:** an instructor workstation already exposes Kustainer on loopback port `8080`.
- **Cloudflare mode:** `cloudflared` listens on loopback port `8080` and carries the HTTP byte stream to the remote gateway through Cloudflare Access and Tunnel.

The Cloudflare Service Token authenticates the `cloudflared` process. The notebook's Kusto requests therefore need no Cloudflare headers or Kusto credentials of their own.

## Section 2: Select or Start the Route

Section 2 runs `start_workshop_endpoint()` and stores its result in `TUNNEL_STATUS`.

### When port 8080 is already open

The notebook posts this management request to `http://127.0.0.1:8080/v1/rest/mgmt`:

```json
{
  "db": "CyberDefendStudentSnapshot",
  "csl": ".show cluster"
}
```

It uses the response as a route fingerprint:

| Result | Interpretation |
| --- | --- |
| HTTP `200` | Direct local Kustainer. Kustainer accepts `.show cluster`, so Section 2 records `mode = "local"` and does not start Cloudflare. |
| HTTP `403` | Existing Cloudflare route through the read-only gateway. The gateway deliberately rejects `.show cluster` because it is not on the metadata allowlist, so Section 2 records `mode = "cloudflare"`. |
| Any other status or no HTTP response | Port conflict or unhealthy workshop route. Section 2 stops without treating the endpoint as ready. |

The expected `403` is only a route-identification check. It does not mean the database query path is ready; Section 3 performs the complete checks.

### When port 8080 is closed

The notebook:

1. Locates `cloudflared` on `PATH` or in known platform-specific locations.
2. Reads `~/.config/cloudflare/student-access.env` using UTF-8.
3. Requires `TUNNEL_SERVICE_HOSTNAME`, `TUNNEL_SERVICE_TOKEN_ID`, and `TUNNEL_SERVICE_TOKEN_SECRET`.
4. Copies those values into the child process environment.
5. Starts `cloudflared access tcp --url 127.0.0.1:8080 --loglevel info`.
6. Polls for up to 20 seconds until port `8080` opens and the `.show cluster` route probe returns the gateway's expected HTTP `403`.
7. Stores the running process and route state in `TUNNEL_STATUS`.

The Service Token values are not placed in command-line arguments or displayed in notebook output. Cloudflared reads them from its environment. The process log is written beside the credential file as `student-access.log`.

The kernel owns the process object. Keep the kernel running during the lab; after a kernel restart, rerun Sections 2 and 3.

## Section 3: Verify Kusto and Build the Client

Section 3 requires a successful `TUNNEL_STATUS` from Section 2. It sets `CONTAINER_IS_LOCAL` from the recorded mode and performs these checks:

| Check | Route | Applies to | Success condition | What it proves |
| --- | --- | --- | --- | --- |
| Gateway process health | `GET /healthz` | Cloudflare mode only | JSON field `status` equals `healthy` | The read-only gateway process is running. This endpoint does not contact Kustainer. |
| Kusto health | `GET /v1/rest/ping` | Both modes | JSON field `ApplicationHealthState` equals `Healthy` | The request path reaches a healthy Kustainer service. In Cloudflare mode, the gateway proxies this route. |
| Database visibility | `POST /v1/rest/mgmt` with `.show databases` | Both modes | The response includes `CyberDefendStudentSnapshot` | The target database exists and is visible through the active route. |

The setup fails if any required check fails. On success it stores `ENDPOINT_STATUS`, sets `CONTAINER_IS_LOCAL`, and displays the green connection summary.

There is no endpoint enumeration or service discovery. The code knows which checks to run because those paths and expected JSON fields are programmed directly into Section 3.

## How `%%kql` Works

The complete call and transport flow is:

```text
%%kql cell
  -> IPython custom cell-magic dispatcher
  -> run_kql_cell(line, cell)
  -> kql(query)
  -> kusto_request(query)
  -> make_kusto_request(...)
  -> urllib.request POST http://127.0.0.1:8080/v1/rest/query
  -> JSON {"db": "CyberDefendStudentSnapshot", "csl": "<raw KQL text>"}
  -> local Kustainer, or cloudflared -> Cloudflare -> gateway -> Kustainer
  -> Kustainer parses and executes the KQL text
  -> primary_records() converts the Kusto response to Python dictionaries
  -> display_hunt_flow() renders workshop results, or the records are returned
```

Section 3 obtains the active IPython shell and registers `run_kql_cell` as a cell magic named `kql`. Conceptually, the registration is:

```python
ipython_shell.register_magic_function(
    run_kql_cell,
    magic_kind="cell",
    magic_name="kql",
)
```

After registration, IPython handles a cell such as:

```kusto
%%kql
SecurityIncident
| take 10
```

as follows:

1. IPython recognizes `%%kql` and passes the remaining cell text to `run_kql_cell`.
2. `run_kql_cell` strips the text and rejects an empty query.
3. `kql()` calls `kusto_request()` with the default `query` endpoint.
4. `make_kusto_request()` creates an HTTP `POST` to `http://127.0.0.1:8080/v1/rest/query` with a JSON body:

   ```json
   {
     "db": "CyberDefendStudentSnapshot",
     "csl": "SecurityIncident\n| take 10"
   }
   ```

5. `primary_records()` converts the primary Kusto result table into a list of Python dictionaries. It supports both the version 1 `Tables` response shape and the framed `DataTable` response shape.
6. If every row has the workshop's investigation-flow columns, the notebook renders the specialized pivot and evidence view. Otherwise it prints the row count and returns the records.

Because registration lives in kernel memory, `%%kql` disappears when the kernel restarts. Rerunning Section 3 registers it again. No `jupyter-kql` package or Azure Data Explorer Python SDK is involved.

### What `csl` Means

`CSL` historically stands for **Cousteau Semantic Language**. Cousteau was the original project/language name before it was renamed Kusto; **KQL**, or **Kusto Query Language**, is the current name. The older initials remain in API and SDK names such as the REST request field `csl`.

Microsoft's current [Kusto query/management HTTP request reference](https://learn.microsoft.com/kusto/api/rest/request?view=microsoft-fabric) does not expand the historical acronym. It defines `csl` operationally as "the text of the query or management command to execute." The historical expansion and Cousteau-to-Kusto rename are recorded in the accepted answer to [Meaning of Kusto CSL acronym](https://stackoverflow.com/questions/64913523/meaning-of-kusto-csl-acronym).

In this notebook, `csl` is only the JSON property that carries the text. For a `%%kql` cell, its value is the raw KQL cell body. For a health or metadata check, it can instead carry a management command such as `.show databases`. The notebook does not compile or translate that text; Kustainer parses and executes it after receiving the REST request.

## Query and Management Endpoints

The notebook's request helper accepts only two endpoint names:

- `query` maps to `/v1/rest/query` and is used by `%%kql`.
- `mgmt` maps to `/v1/rest/mgmt` and is used for `.show databases` during verification.

Every request contains both the database name in `db` and the KQL or management text in `csl`. The active transport is transparent to the client because both local Kustainer and the Cloudflare proxy expose the same Kusto REST shape at the same loopback URL.

## Read-Only Boundary

In Cloudflare mode, the tunnel terminates at the repository's read-only Kusto gateway. The gateway:

- Allows KQL query statements on `/v1/rest/query`.
- Allows only an explicit set of read-only `.show` commands on `/v1/rest/mgmt`.
- Rejects data-changing management commands and disallowed egress primitives.
- Rebuilds validated request bodies, forces KQL mode, and normally sets Kusto's read-only request option.
- Applies database, request-size, rate, timeout, and concurrency controls.

In direct local mode, requests go straight to Kustainer and do not cross that gateway. Kustainer has no native authorization boundary, so the notebook's 19 supplied hunts are read-only by convention rather than by enforcement in that mode.

## Troubleshooting by Failed Check

| Symptom | Meaning | Next action |
| --- | --- | --- |
| `CLOUDFLARED REQUIRED` | No supported `cloudflared` executable was found. | Install Cloudflared using the platform command shown by Section 2, then rerun it. |
| `WORKSHOP CREDENTIALS REQUIRED` or `INCOMPLETE` | The credential file or one of its three required values is absent. | Obtain the current file from the instructor; do not create or guess token values. |
| `PORT 8080 IS OCCUPIED` | A listener exists, but it is neither direct Kustainer nor the expected gateway route. | Stop the conflicting process, then rerun Section 2. |
| Gateway health fails | The tunnel reaches a route whose gateway is not healthy or does not return the expected JSON. | Check the Cloudflared log and have the instructor inspect the gateway service. |
| Kusto ping fails | The route exists, but Kustainer is unavailable or unhealthy behind it. | Have the instructor inspect Kustainer and the gateway-to-Kustainer path. |
| Database visibility fails | Kusto responds, but `CyberDefendStudentSnapshot` is absent from `.show databases`. | Have the instructor restore/import the workshop database or correct the target database. |
| `%%kql` is unknown | The custom magic is not registered in the current kernel. | Run Section 2, then rerun Section 3. |
| A query returns HTTP `403` in Cloudflare mode | The read-only gateway rejected the request. | Confirm the cell contains a permitted read-only query and no blocked management or egress operation. |

## Related Documentation

- [Primary conference Cloudflare access guide](cloudflare_adx_access.md)
- [Read-only Kusto gateway policy](../tools/kusto-readonly-gateway/README.md)
- [Workshop notebook](../hunt-notebook/Cyber-Defense-Workshop.ipynb)
