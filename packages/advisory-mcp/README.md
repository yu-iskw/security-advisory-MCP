# advisory-mcp

Local-first security advisory MCP server. Syncs public, **keyless** vulnerability
feeds into a local SQLite store and serves them via the Model Context Protocol —
no API keys, no live API rate limits during tool calls, no live URL fetching.

## What it does

`advisory-mcp` answers questions like:

- "Is CVE-2024-3094 known to be exploited?" — `analyze_advisory`
- "Is `pkg:npm/lodash@4.17.21` vulnerable?" — `analyze_package`
- "Find all advisories that mention Log4j." — `search_advisories`
- "Rank these 20 advisories for an internet-exposed system." — `prioritize`
- "Scan this CycloneDX SBOM." — `scan_sbom`

All answers come from a local SQLite database that was populated by an earlier
`advisory-mcp sync`. MCP tool calls never make outbound network requests.

## Install

```sh
npm install -g advisory-mcp
```

Or run from the package directly:

```sh
pnpm install
pnpm --filter advisory-mcp build
node packages/advisory-mcp/dist/cli/index.js --help
```

## First-time setup

```sh
advisory-mcp init                  # create ~/.advisory-mcp/{config.json,cache/}
advisory-mcp sync --preset core    # populate the local store (no API keys)
advisory-mcp doctor                # sanity-check the environment
advisory-mcp status                # show per-source freshness
```

The `core` preset enables Tier A sources: CISA KEV, FIRST EPSS, CISA Vulnrichment,
CVEProject cvelistV5, and NVD JSON feeds. Add `--preset packages` (OSV +
GitHub Advisory Database + OpenSSF malicious-packages) or `--preset ecosystems`
(RustSec, Go vulndb, PyPA) for package-level intelligence.

## Use with Claude Desktop

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

## Streamable HTTP transport

```sh
advisory-mcp serve --transport http --port 8765
```

Stateless POST endpoint; every request creates a fresh MCP server + transport.

## MCP surface

| Kind     | Name                             | Purpose                                              |
| -------- | -------------------------------- | ---------------------------------------------------- |
| Tool     | `ping`                           | Health check                                         |
| Tool     | `analyze_advisory`               | Look up a CVE / GHSA / OSV ID with merged evidence   |
| Tool     | `search_advisories`              | FTS5 search over the local index                     |
| Tool     | `source_status`                  | Sync freshness per source                            |
| Tool     | `explain_risk`                   | Profile-aware risk score with per-driver attribution |
| Tool     | `analyze_package`                | PURL-aware vulnerable + malicious package check      |
| Tool     | `scan_sbom`                      | CycloneDX or SPDX JSON SBOM scan                     |
| Tool     | `scan_sbom_file`                 | SBOM from disk (opt-in via `sbomRoots`)              |
| Tool     | `prioritize`                     | Rank advisories + packages by risk                   |
| Resource | `advisory://id/{id}`             | Advisory by canonical or alias ID                    |
| Resource | `advisory://cve/{cveId}`         | CVE-scoped lookup                                    |
| Resource | `advisory://ghsa/{ghsaId}`       | GHSA-scoped lookup                                   |
| Resource | `advisory://osv/{osvId}`         | OSV/ecosystem-scoped lookup                          |
| Resource | `advisory://package/{purl}`      | Package summary                                      |
| Resource | `advisory://source/status`       | Source freshness JSON                                |
| Resource | `advisory://risk-profile/{name}` | Profile weights                                      |
| Resource | `advisory://schema/advisory`     | Inline JSON Schema                                   |
| Resource | `advisory://schema/evidence`     | Inline JSON Schema                                   |
| Prompt   | `triage-advisory`                | Analyst-grade triage workflow                        |
| Prompt   | `patch-brief`                    | Audience-targeted remediation brief                  |
| Prompt   | `risk-acceptance-draft`          | Risk acceptance memo                                 |
| Prompt   | `sbom-risk-review`               | SBOM scan review                                     |

## Source policy

Every default source is:

- public and keyless;
- machine-readable;
- under a license that permits local caching;
- run by a reputable steward (CISA, FIRST, MITRE/CVE Program, NVD, OpenSSF,
  ProjectDiscovery, etc.).

The `research` preset is **disabled by default**. It only runs if
`--accept-research-sources` is passed:

```sh
advisory-mcp sync --preset research --accept-research-sources
```

Nuclei templates, Exploit-DB metadata, and Metasploit module metadata fall
under this preset. `advisory-mcp` indexes only the metadata; it never executes
templates or downloads exploit payloads.

## Security posture

- MCP tool calls **never make outbound network requests** — they only query
  the local SQLite store.
- The downloader has a host allowlist, blocks redirects to non-allowlisted
  hosts, re-resolves DNS post-redirect, and rejects private / loopback /
  link-local / cloud-metadata addresses.
- Tarballs are unpacked in memory with size, entry-count, and path-traversal
  caps.
- NVD feeds and other hashed artifacts are SHA-256 verified before parsing.
- Advisory description text is wrapped in `BEGIN/END UNTRUSTED CONTENT`
  fences in every model-visible response, so prompt-injection payloads in
  upstream advisories appear as data, not instructions.

## Configuration

Default path: `~/.advisory-mcp/config.json`. Override with
`advisory-mcp <cmd> --config <path>` or environment variables:

| Variable                     | Purpose                             |
| ---------------------------- | ----------------------------------- |
| `ADVISORY_MCP_DATABASE_PATH` | Override the DB path                |
| `ADVISORY_MCP_CACHE_PATH`    | Override the cache path             |
| `ADVISORY_MCP_LOG_LEVEL`     | `debug` / `info` / `warn` / `error` |

Notable config fields:

| Field           | Purpose                                                      |
| --------------- | ------------------------------------------------------------ |
| `databasePath`  | Where the SQLite store lives                                 |
| `cachePath`     | Where downloaded source archives are cached                  |
| `defaultPreset` | Preset for ad-hoc syncs                                      |
| `sources`       | Per-source `{enabled: bool}` map                             |
| `sbomRoots`     | Approved directories for `scan_sbom_file` (empty = disabled) |
| `auditLogPath`  | JSONL audit log path (empty = audit logging disabled)        |

## Limitations

- Distro feeds (Debian / Ubuntu / Alpine) are not yet implemented as
  first-class sources. Most package advisories for these ecosystems arrive
  via OSV.
- The `scan_sbom_file` path policy enforces an allowlist of approved
  directories. Full MCP roots negotiation (so the host can grant ad-hoc
  paths at session-start) is future work.
- Exploit-DB and Metasploit metadata adapters are not yet implemented; the
  research preset currently includes only Nuclei templates.
- The PURL-to-OSV name translation handles npm scopes, Maven coordinates,
  and `namespace/name`-style ecosystems. Other ecosystems may need their
  own normalizer.

## Acceptance criteria reference

This package implements RFC 0001. The acceptance criteria from §27 are met:

1. `npm install -g advisory-mcp` installs the CLI.
2. `advisory-mcp sync --preset core` runs without API keys.
3. The stdio server registers in Claude Desktop / Cursor / VS Code.
4. `analyze_advisory` works offline after sync.
5. Results include evidence, source freshness, and risk explanation.
6. MCP tool calls do not perform arbitrary network requests.
7. The server exposes ≥1 resource (10) and ≥1 prompt (4) in addition to
   tools.
8. Security tests cover prompt injection, archive traversal, oversized
   payloads, and URL policy.
9. Integration tests can rebuild the database from fixtures.
10. Source policy, limitations, and update commands are documented (this
    file).
