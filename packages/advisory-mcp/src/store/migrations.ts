import type { Database } from 'better-sqlite3';

interface Migration {
  version: number;
  name: string;
  up: string;
}

/**
 * Migration 001 — initial schema. Tables and indexes mirror RFC section 14.
 * The FTS5 virtual table is intentionally deferred to M5.
 */
const MIGRATION_001: Migration = {
  version: 1,
  name: '001_initial_schema',
  up: `
    CREATE TABLE advisories (
      id              TEXT PRIMARY KEY,
      canonical_id    TEXT NOT NULL,
      type            TEXT NOT NULL,
      title           TEXT,
      description     TEXT,
      published_at    TEXT,
      modified_at     TEXT,
      withdrawn_at    TEXT,
      merged_json     TEXT NOT NULL,
      created_at      TEXT NOT NULL,
      updated_at      TEXT NOT NULL
    );

    CREATE TABLE aliases (
      advisory_id     TEXT NOT NULL,
      alias           TEXT NOT NULL,
      PRIMARY KEY (advisory_id, alias),
      FOREIGN KEY (advisory_id) REFERENCES advisories(id) ON DELETE CASCADE
    );

    CREATE TABLE affected_packages (
      id                INTEGER PRIMARY KEY AUTOINCREMENT,
      advisory_id       TEXT NOT NULL,
      ecosystem         TEXT NOT NULL,
      name              TEXT NOT NULL,
      purl              TEXT,
      vulnerable_range  TEXT,
      fixed_version     TEXT,
      source            TEXT NOT NULL,
      confidence        REAL NOT NULL,
      FOREIGN KEY (advisory_id) REFERENCES advisories(id) ON DELETE CASCADE
    );

    CREATE TABLE evidence (
      id                  TEXT PRIMARY KEY,
      advisory_id         TEXT NOT NULL,
      source              TEXT NOT NULL,
      type                TEXT NOT NULL,
      fetched_at          TEXT NOT NULL,
      observed_at         TEXT,
      source_modified_at  TEXT,
      confidence          REAL NOT NULL,
      trust_tier          TEXT NOT NULL,
      source_url          TEXT,
      raw_ref             TEXT,
      summary             TEXT NOT NULL,
      normalized_json     TEXT NOT NULL,
      FOREIGN KEY (advisory_id) REFERENCES advisories(id) ON DELETE CASCADE
    );

    CREATE TABLE raw_records (
      id                TEXT PRIMARY KEY,
      source            TEXT NOT NULL,
      source_record_id  TEXT,
      fetched_at        TEXT NOT NULL,
      sha256            TEXT NOT NULL,
      compression       TEXT,
      payload           BLOB NOT NULL
    );

    CREATE TABLE source_state (
      source                  TEXT PRIMARY KEY,
      enabled                 INTEGER NOT NULL,
      preset                  TEXT NOT NULL,
      last_sync_started_at    TEXT,
      last_sync_completed_at  TEXT,
      last_success_at         TEXT,
      last_error              TEXT,
      version                 TEXT,
      etag                    TEXT,
      last_modified           TEXT,
      sha256                  TEXT,
      status                  TEXT NOT NULL
    );

    CREATE INDEX idx_aliases_alias               ON aliases(alias);
    CREATE INDEX idx_affected_packages_lookup    ON affected_packages(ecosystem, name, fixed_version);
    CREATE INDEX idx_evidence_advisory_source    ON evidence(advisory_id, source);
    CREATE INDEX idx_source_state_status         ON source_state(status);
  `,
};

const MIGRATIONS: readonly Migration[] = [MIGRATION_001];

export function runMigrations(db: Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version    INTEGER PRIMARY KEY,
      name       TEXT NOT NULL,
      applied_at TEXT NOT NULL
    );
  `);

  const applied = new Set(
    (db.prepare('SELECT version FROM schema_migrations').all() as { version: number }[]).map(
      (r) => r.version,
    ),
  );

  const insert = db.prepare(
    'INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)',
  );

  const apply = db.transaction((migration: Migration) => {
    db.exec(migration.up);
    insert.run(migration.version, migration.name, new Date().toISOString());
  });

  for (const m of MIGRATIONS) {
    if (applied.has(m.version)) continue;
    apply(m);
  }
}

export function appliedMigrationVersions(db: Database): number[] {
  const rows = db.prepare('SELECT version FROM schema_migrations ORDER BY version').all() as {
    version: number;
  }[];
  return rows.map((r) => r.version);
}
