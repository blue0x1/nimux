# nimux Integrations

This directory contains optional AI and automation integration material for `nimux`.

The core `nimux` binary remains independent. These files teach external agents and future MCP servers how to call `nimux` safely and consistently.

## Layout

```text
integrations/
  claude/CLAUDE.md
  codex/SKILL.md
  COMMAND_SURFACE.md
  mcp/README.md
  mcp/tools.json
```

## Design

`nimux` should remain the native execution engine.

AI integrations should act as:

- planners
- command builders
- JSON parsers
- report writers
- safety gates

They should not replace scope checks, authorization, or operator approval.

Agents should read `COMMAND_SURFACE.md` before building multi-step workflows.

## Safety

AI clients should default to read-only actions and require explicit approval for:

- remote command execution
- secrets extraction
- DCSync
- password changes
- LDAP object writes
- ACL modifications
- GPO creation, linking, and file writes
- certificate mapping
- shadow credentials
- SOCKS helper deployment


## Current Version Coverage

Agent and MCP integration material should cover the 1.0.3 and 1.0.4 command surface:

- BloodHound Legacy 4.x collection with `--bloodhound --legacy --bloodhound-out <zip>`, including ACL and object-control data.
- ADCS inventory, certificate inventory, native `ICertAdminD2` policy get/set, `EditFlags`, `DisableExtensionList`, empty-value clearing, RPC certificate requests, PFX output, and PKINIT ccache generation.
- Kerberos execution paths that pass explicit `--krb5-config` alongside generated ccaches.
- LDAP capture server mode with `nimux ldap --server`, `--srvhost`, `--srvport`, and optional `--challenge`.
- Lightweight web discovery with `nimux http --dirs`, `--files`, `--vhosts`, `--workers`, status filters, soft-404 baselines, `--auto-calibrate`, `--recursion --depth`, `--extract-links`, regex filters, length/size filters (`--filter-length` / `-fs`), custom method/header support, rate limits, resume files, and `nimux dns --subdomains`.
- Read-only SMB share spidering with `nimux smb --spider`, optional `--share`, `--remote`, `--max-depth`, `--spider-pattern`, `--size-limit`, and `--interesting` filename patterns.

These workflows remain operator-driven. AI clients should parse JSON when possible, redact sensitive values, and request explicit approval before writes, certificate material creation, capture listeners, service restarts, or remote execution. HTTP directory/file/vhost discovery and DNS subdomain enumeration are read-only, but clients should still respect scope, rate limits, and target authorization.
