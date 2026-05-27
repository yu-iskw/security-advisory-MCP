# advisory-mcp

Local-first security advisory MCP server ([RFC 0001](docs/rfc/0001-local-first-advisory-mcp.md)).

## Features

- **Local SQLite** advisory store with FTS search, evidence, and raw record retention
- **No API keys** — sync uses public feeds (fixture-driven in tests; network adapters use HTTPS allowlist)
- **MCP tools:** `analyze_advisory`, `search_advisories`, `explain_risk`, `analyze_package`, `scan_sbom`, `prioritize`, `source_status`
- **MCP resources:** `advisory://id/{id}`, `advisory://source/status`, risk profiles, schemas
- **MCP prompts:** triage, patch brief, SBOM review, risk acceptance
- **Presets:** `core`, `packages`, `ecosystems`, `context`, `all`, `research`

## Quick start

````bash
pnpm install
pnpm --filter advisory-mcp build
advisory-mcp init
advisory-mcp sync --preset core --fixtures packages/advisory-mcp/tests/fixtures
advisory-mcp serve --transport stdio
```text

For production sync without `--fixtures`, configure cache paths and allowlisted feed URLs (see `src/security/url-policy.ts`).

## Claude Desktop

```json
{
  "mcpServers": {
    "advisory-mcp": {
      "command": "advisory-mcp",
      "args": ["serve", "--transport", "stdio", "--auto-sync-if-empty"]
    }
  }
}
```text

## Development

```bash
pnpm --filter advisory-mcp test
pnpm --filter advisory-mcp test:unit
pnpm --filter advisory-mcp test:integration
```text

## Architecture

```text
bundled fixtures → source adapters → sync engine → merge → SQLite → MCP tools (read-only, offline)
```

MCP tool calls never perform arbitrary network I/O.
````
