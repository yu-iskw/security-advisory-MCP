import type { Advisory } from '../../schemas/advisory.js';
import { advisorySchema } from '../../schemas/advisory.js';
import type { AdvisoryStore } from '../db.js';

export function upsertAdvisory(store: AdvisoryStore, advisory: Advisory): void {
  const parsed = advisorySchema.parse(advisory);
  const now = new Date().toISOString();
  store.db
    .prepare(
      `INSERT INTO advisories (
        id, canonical_id, type, title, description, published_at, modified_at, withdrawn_at,
        merged_json, created_at, updated_at
      ) VALUES (
        @id, @canonicalId, @type, @title, @description, @publishedAt, @modifiedAt, @withdrawnAt,
        @mergedJson, @createdAt, @updatedAt
      )
      ON CONFLICT(id) DO UPDATE SET
        canonical_id = excluded.canonical_id,
        type = excluded.type,
        title = excluded.title,
        description = excluded.description,
        published_at = excluded.published_at,
        modified_at = excluded.modified_at,
        withdrawn_at = excluded.withdrawn_at,
        merged_json = excluded.merged_json,
        updated_at = excluded.updated_at`,
    )
    .run({
      id: parsed.id,
      canonicalId: parsed.canonicalId,
      type: parsed.type,
      title: parsed.title ?? null,
      description: parsed.description ?? null,
      publishedAt: parsed.publishedAt ?? null,
      modifiedAt: parsed.modifiedAt ?? null,
      withdrawnAt: parsed.withdrawnAt ?? null,
      mergedJson: JSON.stringify(parsed),
      createdAt: now,
      updatedAt: now,
    });

  const delAliases = store.db.prepare('DELETE FROM aliases WHERE advisory_id = ?');
  delAliases.run(parsed.id);
  const insAlias = store.db.prepare(
    'INSERT OR IGNORE INTO aliases (advisory_id, alias) VALUES (?, ?)',
  );
  for (const alias of new Set([parsed.id, parsed.canonicalId, ...parsed.aliases])) {
    insAlias.run(parsed.id, alias);
  }

  store.db.prepare('DELETE FROM affected_packages WHERE advisory_id = ?').run(parsed.id);
  const insPkg = store.db.prepare(
    `INSERT INTO affected_packages (
      advisory_id, ecosystem, name, purl, vulnerable_range, fixed_version, source, confidence
    ) VALUES (
      @advisoryId, @ecosystem, @name, @purl, @vulnerableRange, @fixedVersion, @source, @confidence
    )`,
  );
  for (const pkg of parsed.affected) {
    for (const range of pkg.vulnerableRanges.length > 0 ? pkg.vulnerableRanges : ['*']) {
      for (const fix of pkg.fixedVersions.length > 0 ? pkg.fixedVersions : [null]) {
        insPkg.run({
          advisoryId: parsed.id,
          ecosystem: pkg.ecosystem,
          name: pkg.name,
          purl: pkg.purl ?? null,
          vulnerableRange: range,
          fixedVersion: fix,
          source: pkg.source,
          confidence: pkg.confidence,
        });
      }
    }
  }

  store.db.prepare('DELETE FROM advisory_fts WHERE id = ?').run(parsed.id);
  store.db
    .prepare('INSERT INTO advisory_fts (id, title, description, aliases) VALUES (?, ?, ?, ?)')
    .run(
      parsed.id,
      parsed.title ?? '',
      parsed.description ?? '',
      [parsed.canonicalId, ...parsed.aliases].join(' '),
    );
}

export function findAdvisoryById(store: AdvisoryStore, id: string): Advisory | null {
  const aliasRow = store.db
    .prepare('SELECT advisory_id FROM aliases WHERE alias = ? COLLATE NOCASE')
    .get(id) as { advisory_id: string } | undefined;
  const advisoryId = aliasRow?.advisory_id ?? id;
  const row = store.db
    .prepare('SELECT merged_json FROM advisories WHERE id = ?')
    .get(advisoryId) as { merged_json: string } | undefined;
  if (!row) {
    return null;
  }
  return advisorySchema.parse(JSON.parse(row.merged_json));
}

export function searchAdvisories(store: AdvisoryStore, query: string, limit: number): Advisory[] {
  const rows = store.db
    .prepare(
      `SELECT a.merged_json AS merged_json
       FROM advisory_fts fts
       JOIN advisories a ON a.id = fts.id
       WHERE advisory_fts MATCH ?
       LIMIT ?`,
    )
    .all(query.replace(/[^\w\-@.]+/g, ' '), limit) as Array<{ merged_json: string }>;
  return rows.map((r) => advisorySchema.parse(JSON.parse(r.merged_json)));
}

export function countAdvisories(store: AdvisoryStore): number {
  return (store.db.prepare('SELECT COUNT(*) AS c FROM advisories').get() as { c: number }).c;
}
