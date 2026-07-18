# nimux MCP Integration

This directory contains the first working MCP wrapper for nimux.

For the full CLI command surface that the wrapper tracks, see `../COMMAND_SURFACE.md`.

The first implementation is in:

```text
nimux-mcp/
```

It is a separate Nim package that wraps the installed `nimux` binary through stdio JSON-RPC. The main `nimux` binary stays independent from AI providers and model APIs.

## Build

```bash
cd integrations/mcp/nimux-mcp
nimble build -y
```

## Run

```bash
NIMUX_BIN=/path/to/nimux \
NIMUX_MCP_POLICY=./policy.example.json \
./nimux_mcp
```

## Goals

- Provide typed actions around common `nimux` workflows.
- Parse JSON output into structured MCP responses.
- Enforce scope and approval gates.
- Redact sensitive values by default.
- Keep writes and destructive actions explicit.

## Non-Goals

- Do not embed model calls into the `nimux` binary.
- Do not store credentials.
- Do not bypass operator approval.
- Do not expose raw secrets unless explicitly requested.

## Implemented Tools

```text
nimux.scan
nimux.smb_enum
nimux.ldap_query
nimux.kerberos_request
nimux.winrm_command
nimux.remote_exec
nimux.socks_deploy
nimux.socks_status
nimux.socks_cleanup
nimux.proxy_scan
nimux.gpo_dry_run
nimux.gpo_apply
nimux.file_operation
nimux.database_query
nimux.secrets
nimux.protocol_probe
nimux.report_summary
```

The wrapper maps the main command families into typed tool calls:

```text
scan, smb, ldap, kerberos, krb5conf, winrm, scm, bin, cim, tsch, mmc,
socks, secrets, dcsync, mssql, postgres, mysql, ssh, ftp, vnc, nfs,
afp, webdav, http, rdp, put, get, ls, mkdir, rm
```

## Native Pivoting Model

`nimux socks` is a native pivoting feature. The MCP server should model it as a long-running background capability rather than a one-shot command.

Lifecycle:

```text
deploy pivot helper
capture local SOCKS URL
capture cleanup metadata
route future nimux calls through --proxy
check pivot status
cleanup pivot helper
```

Deployment command shape:

```bash
nimux socks <pivot-host> -u <admin> -p '<password>' -d <domain> \
  --reverse --listener <operator-ip> --socks-port 1080 --control-port 1081
```

Routed command shape:

```bash
nimux scan <internal-cidr> --port 445,389,5985 --open \
  --proxy socks5://127.0.0.1:1080 --json
```

The MCP server should store pivot session metadata:

```text
pivot_id
pivot_host
local_proxy_url
listener
socks_port
control_port
pid
socks_task
remote_helper_path
created_at
scope_id
```

Any MCP tool that accepts `proxy` should also accept `pivot_id`. When `pivot_id` is supplied, the server resolves it to the stored `local_proxy_url` and passes it to `nimux` as `--proxy`.

## Safety Model

Each request should include:

```text
scope_id
target
command_family
auth_ref
intent
approval_id for write or execution actions
```

The MCP server should reject write operations unless:

- scope is configured
- the tool is allowed by policy
- an approval token is present
- rollback output is configured where supported

## Policy File

```json
{
  "scope": {
    "name": "corp-lab",
    "domains": ["corp.local"],
    "cidrs": ["10.10.10.0/24"],
    "hosts": ["dc01.corp.local"]
  },
  "defaults": {
    "redact": true,
    "require_approval": true,
    "rollback_dir": "./rollback",
    "evidence_dir": "./evidence"
  },
  "allow": {
    "read_only": true,
    "remote_execution": false,
    "secrets": false,
    "dcsync": false,
    "ldap_writes": false,
    "gpo_writes": false,
    "socks_deploy": false,
    "proxy_reuse": true
  }
}
```

## Output Redaction

Redact these fields by default:

```text
password
hash
nt_hash
aes_key
ticket
ccache
kirbi
private_key
pfx_password
dpapi
secret
cookie
token
```

## Implementation Notes

The wrapper currently calls the installed `nimux` binary as a subprocess:

```text
MCP request
  -> validate scope
  -> build nimux argv
  -> run nimux with --json
  -> parse JSON
  -> redact
  -> return structured result
```

## Roadmap

- Add Content-Length framing for MCP clients that require full MCP transport framing.
- Add streaming command output for long-running operations.
- Add optional native Nim library bindings after the subprocess wrapper stabilizes.
- Expand structured parsers for each JSON output shape.
