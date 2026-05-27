import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

// better-sqlite3 default export is the constructor; the namespace exposes the
// `Database` instance type used in DatabaseHandle.
// eslint-disable-next-line import-x/no-named-as-default
import Database from 'better-sqlite3';

import { runMigrations } from './migrations.js';

export type DatabaseHandle = Database.Database;

interface OpenStoreOptions {
  /** Filesystem path, or `:memory:` for an ephemeral test database. */
  path: string;
  /** Disable WAL journaling. Required for `:memory:`. */
  noWal?: boolean;
}

export function openStore(options: OpenStoreOptions): DatabaseHandle {
  if (options.path !== ':memory:') {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- caller-provided database path
    mkdirSync(dirname(options.path), { recursive: true });
  }

  const db = new Database(options.path);
  db.pragma('foreign_keys = ON');
  if (!options.noWal && options.path !== ':memory:') {
    db.pragma('journal_mode = WAL');
  }
  db.pragma('synchronous = NORMAL');

  runMigrations(db);
  return db;
}

export function closeStore(db: DatabaseHandle): void {
  db.close();
}
