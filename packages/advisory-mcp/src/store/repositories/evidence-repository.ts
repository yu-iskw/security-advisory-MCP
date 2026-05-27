import type { Evidence } from '../../schemas/evidence.js';
import { evidenceSchema } from '../../schemas/evidence.js';
import type { AdvisoryStore } from '../db.js';

export function upsertEvidence(store: AdvisoryStore, evidence: Evidence): void {
  const parsed = evidenceSchema.parse(evidence);
  store.db
    .prepare(
      `INSERT INTO evidence (
        id, advisory_id, source, type, fetched_at, observed_at, source_modified_at,
        confidence, trust_tier, source_url, raw_ref, summary, normalized_json
      ) VALUES (
        @id, @advisoryId, @source, @type, @fetchedAt, @observedAt, @sourceModifiedAt,
        @confidence, @trustTier, @sourceUrl, @rawRef, @summary, @normalizedJson
      )
      ON CONFLICT(id) DO UPDATE SET
        confidence = excluded.confidence,
        summary = excluded.summary,
        normalized_json = excluded.normalized_json,
        fetched_at = excluded.fetched_at`,
    )
    .run({
      id: parsed.id,
      advisoryId: parsed.advisoryId,
      source: parsed.source,
      type: parsed.type,
      fetchedAt: parsed.fetchedAt,
      observedAt: parsed.observedAt ?? null,
      sourceModifiedAt: parsed.sourceModifiedAt ?? null,
      confidence: parsed.confidence,
      trustTier: parsed.trustTier,
      sourceUrl: parsed.sourceUrl ?? null,
      rawRef: parsed.rawRef ?? null,
      summary: parsed.summary,
      normalizedJson: JSON.stringify(parsed),
    });
}

export function listEvidenceForAdvisory(store: AdvisoryStore, advisoryId: string): Evidence[] {
  const rows = store.db
    .prepare('SELECT normalized_json FROM evidence WHERE advisory_id = ? ORDER BY source')
    .all(advisoryId) as Array<{ normalized_json: string }>;
  return rows.map((r) => evidenceSchema.parse(JSON.parse(r.normalized_json)));
}

export function storeRawRecord(
  store: AdvisoryStore,
  params: {
    id: string;
    source: string;
    sourceRecordId?: string;
    fetchedAt: string;
    sha256: string;
    payload: Buffer;
    compression?: string;
  },
): void {
  store.db
    .prepare(
      `INSERT INTO raw_records (id, source, source_record_id, fetched_at, sha256, compression, payload)
       VALUES (@id, @source, @sourceRecordId, @fetchedAt, @sha256, @compression, @payload)
       ON CONFLICT(id) DO UPDATE SET payload = excluded.payload, sha256 = excluded.sha256`,
    )
    .run({
      id: params.id,
      source: params.source,
      sourceRecordId: params.sourceRecordId ?? null,
      fetchedAt: params.fetchedAt,
      sha256: params.sha256,
      compression: params.compression ?? null,
      payload: params.payload,
    });
}
