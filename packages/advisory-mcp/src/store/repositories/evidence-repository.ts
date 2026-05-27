import type { DatabaseHandle } from '../db.js';

interface UpsertEvidenceInput {
  id: string;
  advisoryId: string;
  source: string;
  type: string;
  fetchedAt: string;
  observedAt?: string;
  sourceModifiedAt?: string;
  confidence: number;
  trustTier: string;
  sourceUrl?: string;
  rawRef?: string;
  summary: string;
  normalizedJson: string;
}

interface EvidenceRow {
  id: string;
  advisoryId: string;
  source: string;
  type: string;
  fetchedAt: string;
  observedAt: string | null;
  sourceModifiedAt: string | null;
  confidence: number;
  trustTier: string;
  sourceUrl: string | null;
  rawRef: string | null;
  summary: string;
  normalizedJson: string;
}

interface DbEvidenceRow {
  id: string;
  advisory_id: string;
  source: string;
  type: string;
  fetched_at: string;
  observed_at: string | null;
  source_modified_at: string | null;
  confidence: number;
  trust_tier: string;
  source_url: string | null;
  raw_ref: string | null;
  summary: string;
  normalized_json: string;
}

function rowFromDb(row: DbEvidenceRow): EvidenceRow {
  return {
    id: row.id,
    advisoryId: row.advisory_id,
    source: row.source,
    type: row.type,
    fetchedAt: row.fetched_at,
    observedAt: row.observed_at,
    sourceModifiedAt: row.source_modified_at,
    confidence: row.confidence,
    trustTier: row.trust_tier,
    sourceUrl: row.source_url,
    rawRef: row.raw_ref,
    summary: row.summary,
    normalizedJson: row.normalized_json,
  };
}

export class EvidenceRepository {
  constructor(private readonly db: DatabaseHandle) {}

  upsert(input: UpsertEvidenceInput): void {
    this.db
      .prepare(
        `
        INSERT INTO evidence (
          id, advisory_id, source, type, fetched_at,
          observed_at, source_modified_at, confidence, trust_tier,
          source_url, raw_ref, summary, normalized_json
        ) VALUES (
          @id, @advisoryId, @source, @type, @fetchedAt,
          @observedAt, @sourceModifiedAt, @confidence, @trustTier,
          @sourceUrl, @rawRef, @summary, @normalizedJson
        )
        ON CONFLICT(id) DO UPDATE SET
          advisory_id        = excluded.advisory_id,
          source             = excluded.source,
          type               = excluded.type,
          fetched_at         = excluded.fetched_at,
          observed_at        = excluded.observed_at,
          source_modified_at = excluded.source_modified_at,
          confidence         = excluded.confidence,
          trust_tier         = excluded.trust_tier,
          source_url         = excluded.source_url,
          raw_ref            = excluded.raw_ref,
          summary            = excluded.summary,
          normalized_json    = excluded.normalized_json
      `,
      )
      .run({
        ...input,
        observedAt: input.observedAt ?? null,
        sourceModifiedAt: input.sourceModifiedAt ?? null,
        sourceUrl: input.sourceUrl ?? null,
        rawRef: input.rawRef ?? null,
      });
  }

  findByAdvisoryId(advisoryId: string): EvidenceRow[] {
    const rows = this.db
      .prepare('SELECT * FROM evidence WHERE advisory_id = ? ORDER BY fetched_at DESC')
      .all(advisoryId) as DbEvidenceRow[];
    return rows.map(rowFromDb);
  }

  count(): number {
    const row = this.db.prepare('SELECT COUNT(*) as c FROM evidence').get() as { c: number };
    return row.c;
  }
}
