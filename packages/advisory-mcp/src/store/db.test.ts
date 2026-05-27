import { describe, expect, it } from 'vitest';

import { closeStore, openStore } from './db.js';
import { appliedMigrationVersions, runMigrations } from './migrations.js';

describe('store / db', () => {
  it('opens an in-memory database with migrations applied', () => {
    const db = openStore({ path: ':memory:', noWal: true });
    try {
      expect(appliedMigrationVersions(db)).toEqual([1]);
      const tables = db
        .prepare(
          "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .all() as { name: string }[];
      const names = tables.map((t) => t.name);
      expect(names).toEqual(
        expect.arrayContaining([
          'advisories',
          'affected_packages',
          'aliases',
          'evidence',
          'raw_records',
          'schema_migrations',
          'source_state',
        ]),
      );
    } finally {
      closeStore(db);
    }
  });

  it('is idempotent: a second open does not re-apply migrations', () => {
    const db = openStore({ path: ':memory:', noWal: true });
    try {
      const v1 = appliedMigrationVersions(db);
      runMigrations(db); // no-op: migrations already applied
      const v2 = appliedMigrationVersions(db);
      expect(v2).toEqual(v1);
    } finally {
      closeStore(db);
    }
  });

  it('foreign keys are enforced', () => {
    const db = openStore({ path: ':memory:', noWal: true });
    try {
      expect(() =>
        db
          .prepare('INSERT INTO aliases (advisory_id, alias) VALUES (?, ?)')
          .run('nonexistent-advisory', 'CVE-9999-0001'),
      ).toThrow(/FOREIGN KEY/i);
    } finally {
      closeStore(db);
    }
  });
});
