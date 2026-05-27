import fs from 'node:fs';
import path from 'node:path';

import Database from 'better-sqlite3';

import { CORE_SOURCE_IDS } from '../schemas/source.js';

import { MIGRATION_STATEMENTS, SCHEMA_VERSION } from './migrations.js';

export interface AdvisoryStoreOptions {
  databasePath: string;
  readonly?: boolean;
}

export interface AdvisoryStore {
  db: Database.Database;
  databasePath: string;
  close(): void;
}

export class DatabaseNotInitializedError extends Error {
  constructor(databasePath: string) {
    super(
      [
        'The advisory database has not been initialized.',
        `Database path: ${databasePath}`,
        'Run:',
        '  advisory-mcp init',
        '  advisory-mcp sync --preset core',
        'No API keys are required.',
      ].join('\n'),
    );
    this.name = 'DatabaseNotInitializedError';
  }
}

function ensureParentDirectory(databasePath: string): void {
  const parent = path.dirname(databasePath);
  fs.mkdirSync(parent, { recursive: true });
}

function hasMigrationsTable(db: Database.Database): boolean {
  const row = db
    .prepare(
      `SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'`,
    )
    .get();
  return row !== undefined;
}

function getAppliedVersion(db: Database.Database): number {
  if (!hasMigrationsTable(db)) {
    return 0;
  }
  const row = db.prepare('SELECT MAX(version) AS version FROM schema_migrations').get() as
    | { version: number | null }
    | undefined;
  return row?.version ?? 0;
}

function applyMigrations(db: Database.Database): void {
  const current = getAppliedVersion(db);
  if (current >= SCHEMA_VERSION) {
    return;
  }

  const migrate = db.transaction(() => {
    for (const statement of MIGRATION_STATEMENTS) {
      db.exec(statement);
    }
    db.prepare('INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)').run(
      SCHEMA_VERSION,
      new Date().toISOString(),
    );
  });

  migrate();
}

export function openStore(options: AdvisoryStoreOptions): AdvisoryStore {
  const { databasePath, readonly = false } = options;

  if (!readonly) {
    ensureParentDirectory(databasePath);
  }

  const db = new Database(databasePath, { readonly, fileMustExist: readonly });
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  if (!readonly) {
    applyMigrations(db);
  }

  return {
    db,
    databasePath,
    close() {
      db.close();
    },
  };
}

export function isStoreInitialized(databasePath: string): boolean {
  if (!fs.existsSync(databasePath)) {
    return false;
  }

  try {
    const store = openStore({ databasePath, readonly: true });
    const version = getAppliedVersion(store.db);
    store.close();
    return version >= SCHEMA_VERSION;
  } catch {
    return false;
  }
}

export function assertStoreReady(store: AdvisoryStore): void {
  const version = getAppliedVersion(store.db);
  if (version < SCHEMA_VERSION) {
    throw new DatabaseNotInitializedError(store.databasePath);
  }
}

export function seedCoreSourceStates(store: AdvisoryStore, preset: string): void {
  const insert = store.db.prepare(
    `INSERT INTO source_state (
      source, enabled, preset, status
    ) VALUES (
      @source, @enabled, @preset, @status
    )
    ON CONFLICT(source) DO UPDATE SET
      enabled = excluded.enabled,
      preset = excluded.preset`,
  );

  const seed = store.db.transaction(() => {
    for (const source of CORE_SOURCE_IDS) {
      insert.run({
        source,
        enabled: 1,
        preset,
        status: 'never_synced',
      });
    }
  });

  seed();
}
