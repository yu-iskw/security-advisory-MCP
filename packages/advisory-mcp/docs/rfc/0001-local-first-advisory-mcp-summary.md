# RFC 0001

**Status:** Draft

## Executive summary

The advisory MCP server runs entirely on the host with no cloud API keys or outbound credential requirements.
Agents connect over the standard MCP protocol to tools, resources, and prompts scoped to security and dependency advisory work.
Persistent state lives in a local SQLite database for advisories, scan results, and project metadata.
Ingestion and enrichment pipelines write to that store offline or on a schedule the operator controls.
MCP tools expose query, triage, and remediation actions against the local corpus without duplicating vendor SaaS flows.
MCP resources surface structured advisory records and reports for clients that prefer read-only context.
MCP prompts package repeatable review workflows so hosts can steer agents with consistent guardrails.
The design favors privacy, air-gapped use, and predictable latency by keeping hot paths on disk and in-process.
Operators own the data directory and backups; nothing is sent to a vendor backend unless they configure it.
Full protocol shapes, schema migrations, and tool catalogs are specified in the complete RFC, not repeated here.
