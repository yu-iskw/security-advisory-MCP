import type { DatabaseHandle } from '../db.js';

interface AdvisoryRow {
  id: string;
  canonicalId: string;
  type: string;
  title: string | null;
  description: string | null;
  publishedAt: string | null;
  modifiedAt: string | null;
  withdrawnAt: string | null;
  mergedJson: string;
  createdAt: string;
  updatedAt: string;
}

interface UpsertAdvisoryInput {
  id: string;
  canonicalId: string;
  type: string;
  title?: string;
  description?: string;
  publishedAt?: string;
  modifiedAt?: string;
  withdrawnAt?: string;
  mergedJson: string;
  aliases?: string[];
}

interface DbAdvisoryRow {
  id: string;
  canonical_id: string;
  type: string;
  title: string | null;
  description: string | null;
  published_at: string | null;
  modified_at: string | null;
  withdrawn_at: string | null;
  merged_json: string;
  created_at: string;
  updated_at: string;
}

function rowFromDb(row: DbAdvisoryRow): AdvisoryRow {
  return {
    id: row.id,
    canonicalId: row.canonical_id,
    type: row.type,
    title: row.title,
    description: row.description,
    publishedAt: row.published_at,
    modifiedAt: row.modified_at,
    withdrawnAt: row.withdrawn_at,
    mergedJson: row.merged_json,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export class AdvisoryRepository {
  constructor(private readonly db: DatabaseHandle) {}

  upsert(input: UpsertAdvisoryInput): void {
    const now = new Date().toISOString();
    const stmt = this.db.prepare(`
      INSERT INTO advisories (
        id, canonical_id, type, title, description,
        published_at, modified_at, withdrawn_at,
        merged_json, created_at, updated_at
      ) VALUES (
        @id, @canonicalId, @type, @title, @description,
        @publishedAt, @modifiedAt, @withdrawnAt,
        @mergedJson, @now, @now
      )
      ON CONFLICT(id) DO UPDATE SET
        canonical_id = excluded.canonical_id,
        type         = excluded.type,
        title        = excluded.title,
        description  = excluded.description,
        published_at = excluded.published_at,
        modified_at  = excluded.modified_at,
        withdrawn_at = excluded.withdrawn_at,
        merged_json  = excluded.merged_json,
        updated_at   = excluded.updated_at
    `);

    const aliasInsert = this.db.prepare(
      'INSERT OR IGNORE INTO aliases (advisory_id, alias) VALUES (?, ?)',
    );

    const tx = this.db.transaction((data: UpsertAdvisoryInput) => {
      stmt.run({
        id: data.id,
        canonicalId: data.canonicalId,
        type: data.type,
        title: data.title ?? null,
        description: data.description ?? null,
        publishedAt: data.publishedAt ?? null,
        modifiedAt: data.modifiedAt ?? null,
        withdrawnAt: data.withdrawnAt ?? null,
        mergedJson: data.mergedJson,
        now,
      });
      for (const alias of data.aliases ?? []) {
        aliasInsert.run(data.id, alias);
      }
    });

    tx(input);
  }

  findById(id: string): AdvisoryRow | undefined {
    const row = this.db
      .prepare('SELECT * FROM advisories WHERE id = ?')
      .get(id) as DbAdvisoryRow | undefined;
    return row ? rowFromDb(row) : undefined;
  }

  findByAlias(alias: string): AdvisoryRow | undefined {
    const row = this.db
      .prepare(
        `SELECT a.*
         FROM advisories a
         JOIN aliases al ON al.advisory_id = a.id
         WHERE al.alias = ?
         LIMIT 1`,
      )
      .get(alias) as DbAdvisoryRow | undefined;
    return row ? rowFromDb(row) : undefined;
  }

  aliasesFor(advisoryId: string): string[] {
    const rows = this.db
      .prepare('SELECT alias FROM aliases WHERE advisory_id = ? ORDER BY alias')
      .all(advisoryId) as { alias: string }[];
    return rows.map((r) => r.alias);
  }

  count(): number {
    const row = this.db.prepare('SELECT COUNT(*) as c FROM advisories').get() as { c: number };
    return row.c;
  }
}
