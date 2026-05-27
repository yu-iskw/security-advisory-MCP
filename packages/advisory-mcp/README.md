# advisory-mcp

Local-first security advisory MCP server (RFC 0001).

## Status

**Phase 1 scaffold** — SQLite schema, CLI (`init`, `sync`, `serve`, `status`, `doctor`), MCP stdio with `source_status` tool, `advisory://source/status` resource, and `triage-advisory` prompt. Network feed sync and analysis tools follow incrementally.

## Quick start

```bash
pnpm install
pnpm --filter advisory-mcp build
advisory-mcp init
advisory-mcp sync --preset core   # fixture/network sync in progress
advisory-mcp serve --transport stdio
```

## Claude Desktop

```json
{
  "mcpServers": {
    "advisory-mcp": {
      "command": "advisory-mcp",
      "args": ["serve", "--transport", "stdio"]
    }
  }
}
```

## Development

```bash
pnpm --filter advisory-mcp test
pnpm --filter advisory-mcp build
```

## Design

See `docs/rfc/0001-local-first-advisory-mcp.md`.
