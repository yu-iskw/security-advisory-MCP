import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { CORE_SOURCE_IDS } from '../../src/schemas/source.js';
import { openStore, seedCoreSourceStates } from '../../src/store/db.js';
import { SCHEMA_VERSION } from '../../src/store/migrations.js';

const tempDirs: string[] = [];

function tempDatabasePath(name: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `advisory-mcp-${name}-`));
  tempDirs.push(dir);
  return path.join(dir, 'advisory.db');
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe('store migrations', () => {
  it('creates schema version and core tables including FTS5', () => {
    const databasePath = tempDatabasePath('migrate');
    const store = openStore({ databasePath });
    try {
      const version = store.db
        .prepare('SELECT MAX(version) AS version FROM schema_migrations')
        .get() as { version: number };
      expect(version.version).toBe(SCHEMA_VERSION);

      const tables = store.db
        .prepare(
          `SELECT name FROM sqlite_master WHERE type IN ('table', 'virtual table') ORDER BY name`,
        )
        .all() as Array<{ name: string }>;
      const names = tables.map((t) => t.name);
      expect(names).toContain('advisories');
      expect(names).toContain('source_state');
      expect(names).toContain('advisory_fts');
    } finally {
      store.close();
    }
  });

  it('seeds core source_state rows on init', () => {
    const databasePath = tempDatabasePath('seed');
    const store = openStore({ databasePath });
    try {
      seedCoreSourceStates(store, 'core');
      const count = (
        store.db.prepare('SELECT COUNT(*) AS count FROM source_state').get() as { count: number }
      ).count;
      expect(count).toBe(CORE_SOURCE_IDS.length);
    } finally {
      store.close();
    }
  });
});
