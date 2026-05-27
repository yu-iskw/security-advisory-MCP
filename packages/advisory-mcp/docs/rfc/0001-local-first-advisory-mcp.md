# advisory-mcp RFC 0001 — incremental implementation

## Phase 1 — Core MVP scaffold (current)

- [x] Package `packages/advisory-mcp` with ESM, Vitest unit + integration projects
- [x] SQLite schema migrations + `openStore`
- [x] CLI: `init`, `serve`, `status`, `doctor`, `sync` (stub)
- [x] MCP stdio: `source_status` tool, `advisory://source/status` resource, `triage-advisory` prompt
- [x] Unit tests: migrations, paths, source status, missing DB message
- [x] Integration tests: empty DB, MCP handlers
- [ ] Core sync from fixtures (CVEProject, NVD, KEV, EPSS, Vulnrichment)
- [ ] Tools: `analyze_advisory`, `search_advisories`, `explain_risk`
- [ ] Resources: `advisory://id/{id}`, `advisory://risk-profile/{name}`

## Phase 2 — Package intelligence

- [ ] OSV, GHSA, OpenSSF malicious-packages sources
- [ ] `analyze_package`, `scan_sbom`, PURL support

## Phase 3 — Ecosystem advisories

- [ ] Debian, Ubuntu, Alpine, RustSec, Go vuln DB, PyPA

## Phase 4 — MCP polish

- [ ] Remaining prompts, HTTP transport, roots-aware SBOM

## Phase 5 — Research preset

- [ ] Optional low-trust sources (disabled by default)
