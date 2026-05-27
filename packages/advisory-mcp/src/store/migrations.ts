export const MIGRATION_STATEMENTS: readonly string[] = [
  `CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS advisories (
    id TEXT PRIMARY KEY,
    canonical_id TEXT NOT NULL,
    type TEXT NOT NULL,
    title TEXT,
    description TEXT,
    published_at TEXT,
    modified_at TEXT,
    withdrawn_at TEXT,
    merged_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS aliases (
    advisory_id TEXT NOT NULL,
    alias TEXT NOT NULL,
    PRIMARY KEY (advisory_id, alias)
  )`,
  `CREATE TABLE IF NOT EXISTS affected_packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    purl TEXT,
    vulnerable_range TEXT,
    fixed_version TEXT,
    source TEXT NOT NULL,
    confidence REAL NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    advisory_id TEXT NOT NULL,
    source TEXT NOT NULL,
    type TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    observed_at TEXT,
    source_modified_at TEXT,
    confidence REAL NOT NULL,
    trust_tier TEXT NOT NULL,
    source_url TEXT,
    raw_ref TEXT,
    summary TEXT NOT NULL,
    normalized_json TEXT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS raw_records (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    source_record_id TEXT,
    fetched_at TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    compression TEXT,
    payload BLOB NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS source_state (
    source TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL,
    preset TEXT NOT NULL,
    last_sync_started_at TEXT,
    last_sync_completed_at TEXT,
    last_success_at TEXT,
    last_error TEXT,
    version TEXT,
    etag TEXT,
    last_modified TEXT,
    sha256 TEXT,
    status TEXT NOT NULL
  )`,
  `CREATE VIRTUAL TABLE IF NOT EXISTS advisory_fts USING fts5(
    id,
    title,
    description,
    aliases
  )`,
  `CREATE INDEX IF NOT EXISTS idx_aliases_alias ON aliases(alias)`,
  `CREATE INDEX IF NOT EXISTS idx_affected_packages_lookup
    ON affected_packages(ecosystem, name, fixed_version)`,
  `CREATE INDEX IF NOT EXISTS idx_evidence_advisory_source
    ON evidence(advisory_id, source)`,
  `CREATE INDEX IF NOT EXISTS idx_source_state_status
    ON source_state(status)`,
];

export const SCHEMA_VERSION = 1;
