# nimux MCP Integration

This directory contains the first working MCP wrapper for nimux.

For the full CLI command surface that the wrapper tracks, see `../COMMAND_SURFACE.md`.

The first implementation is in:

```text
nimux-mcp/
```

It is a separate Nim package that wraps the installed `nimux` binary through stdio JSON-RPC. The main `nimux` binary stays independent from AI providers and model APIs.

The wrapper supports MCP `Content-Length` framing for real clients and newline-delimited JSON-RPC for local smoke tests.

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

## Client Config

Ready-to-copy config examples are available in:

```text
examples/
```

Files:

```text
examples/codex.config.toml
examples/claude-desktop.json
examples/cursor.json
examples/windsurf.json
examples/generic-stdio.json
examples/local-dev.json
```

```json
{
  "mcpServers": {
    "nimux": {
      "command": "/path/to/integrations/mcp/nimux-mcp/nimux_mcp",
      "env": {
        "NIMUX_BIN": "/usr/local/bin/nimux",
        "NIMUX_MCP_POLICY": "/path/to/policy.json"
      }
    }
  }
}
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

`nimux.smb_enum` can pass SMB spider flags such as `--spider`, `--share`,
`--remote`, `--max-depth`, `--spider-pattern`, `--size-limit`, and
`--interesting` for read-only share crawling.

The wrapper maps the main command families into typed tool calls:

```text
scan, smb, ldap, kerberos, krb5conf, winrm, scm, bin, cim, tsch, mmc,
socks, secrets, dcsync, mssql, postgres, mysql, ssh, ftp, vnc, nfs,
afp, webdav, http, dns, rdp, put, get, ls, mkdir, rm
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

nimux socks <pivot-host> --linux -u <user> -p '<password>' \
  --reverse --listener <operator-ip> --socks-port 1080 --control-port 1081

nimux socks <pivot-host> --linux -u <user> --ssh-key ~/.ssh/id_rsa \
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
platform
```

Any MCP tool that accepts `proxy` should also accept `pivot_id`. When `pivot_id` is supplied, the server resolves it to the stored `local_proxy_url` and passes it to `nimux` as `--proxy`.

Linux pivot support in the MCP layer:

```text
set linux=true to route deployment through SSH instead of WinRM
use password or ssh_key authentication
Linux deploy and cleanup also accept port and timeout_ms
Linux cleanup uses pid and remote_helper_path
Windows cleanup can also use socks_task
```

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

## 1.0.5 Command Surface Notes

The MCP wrapper should recognize the current nimux CLI even when not every flow has a first-class typed tool yet. Use controlled subprocess calls with `--json` and policy approval for:

- `nimux ldap --bloodhound --legacy --bloodhound-out <zip>` for BloodHound Legacy 4.x output.
- `nimux ldap --adcs-policy --ca <ca> --adcs-get-editflags` and `--adcs-get-disable-extension-list` as read operations.
- `nimux ldap --adcs-policy --ca <ca> --adcs-set-editflags <value>` and `--adcs-set-disable-extension-list <value>` as write operations.
- `nimux ldap --adcs-request --adcs-rpc ... --out <file.pfx>` as certificate material creation.
- `nimux ldap --adcs-auth --pfx <file.pfx> --ccache <file> --krb5-config <file>` as PKINIT ccache generation.
- `nimux ldap --server --srvhost <ip> --srvport <port> [--challenge <hex>]` as a long-running capture listener.
- `nimux http <host> --dirs <wordlist> --workers <n> --status <codes> --baseline --json` as read-only directory discovery with soft-404 filtering.
- `nimux http <host> --dirs <wordlist> --auto-calibrate --recursion --depth <n> --extract-links --json` as read-only calibrated recursive discovery.
- `nimux http <host> --files <wordlist> --extensions <csv> --filter-regex <re> -fs <size> --json` as read-only file discovery.
- `nimux http <ip> --vhosts <wordlist> -d <domain> --workers <n> --resume <jsonl> --json` as read-only virtual-host discovery.
- `nimux dns <domain> --subdomains <wordlist> --workers <n> --json` as read-only subdomain discovery.
- `nimux smb <host> --shares --json` as authenticated or anonymous/null-session share enumeration when the target permits it.
- `nimux smb <host> --spider --share <name> --max-depth <n> --interesting --json` as read-only SMB share spidering.

LDAP capture and ADCS request outputs can contain credential-equivalent material. Redact captures, PFX/private key paths when appropriate, and never store raw secrets in MCP logs.

## Roadmap

- Add streaming command output for long-running operations.
- Add optional native Nim library bindings after the subprocess wrapper stabilizes.
- Expand structured parsers for each JSON output shape.
