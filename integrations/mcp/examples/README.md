# MCP Client Config Examples

This directory contains ready-to-copy MCP client configuration examples for the nimux MCP wrapper.

Files:

```text
codex.config.toml      Codex config.toml example
claude-desktop.json    Claude Desktop mcpServers example
cursor.json            Cursor mcpServers example
windsurf.json          Windsurf mcpServers example
generic-stdio.json     Generic stdio MCP client example
local-dev.json         Local development example
```

Adjust these paths before use:

```text
command
NIMUX_BIN
NIMUX_MCP_POLICY
NIMUX_MCP_STATE
```

Build the wrapper first:

```bash
cd integrations/mcp/nimux-mcp
nimble build -y
```

Then restart or reload your MCP client.
