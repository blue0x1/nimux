# nimux-mcp

`nimux-mcp` is a small stdio JSON-RPC MCP wrapper for `nimux`.

It keeps the main `nimux` binary independent and calls it as a subprocess. The MCP layer adds:

- tool discovery
- policy checks
- approval gates
- target scope checks
- default redaction
- pivot metadata tracking
- JSON-oriented responses

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

The server reads newline-delimited JSON-RPC messages from stdin and writes JSON-RPC responses to stdout.

## Environment

```text
NIMUX_BIN          Path to nimux. Defaults to nimux in PATH.
NIMUX_MCP_POLICY   JSON policy file. Optional.
NIMUX_MCP_STATE    Pivot state JSON file. Defaults to a temp file.
```

## Supported Tools

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

## Safety

By default the example policy allows read-only activity and blocks:

- remote execution
- secrets collection
- DCSync
- LDAP writes
- GPO writes
- SOCKS deployment

Enable those only for authorized lab scopes.

Write and execution tools require `approval_id` when `require_approval` is true.

## Example tools/list

```json
{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}
```

## Example scan call

```json
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"nimux.scan","arguments":{"target":"dc01.corp.local","ports":"445,389,5985","open_only":true}}}
```

## Example pivot flow

Allow `socks_deploy` in the policy first.

Deploy:

```json
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"nimux.socks_deploy","arguments":{"target":"host01.corp.local","username":"administrator","password":"<password>","domain":"corp.local","listener":"10.10.14.10","socks_port":1080,"control_port":1081,"approval_id":"approved-001"}}}
```

Reuse:

```json
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"nimux.proxy_scan","arguments":{"pivot_id":"pivot-123","target":"10.20.30.0/24","ports":"445,389,5985"}}}
```

Cleanup:

```json
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"nimux.socks_cleanup","arguments":{"pivot_id":"pivot-123","username":"administrator","password":"<password>","domain":"corp.local","approval_id":"approved-002"}}}
```

