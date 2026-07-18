# nimux Integrations

This directory contains optional AI and automation integration material for `nimux`.

The core `nimux` binary remains independent. These files teach external agents and future MCP servers how to call `nimux` safely and consistently.

## Layout

```text
integrations/
  claude/SKILLS.md
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
