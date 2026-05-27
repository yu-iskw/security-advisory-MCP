import { evidenceSchema } from '../../schemas/evidence.js';
import { readStringColumn } from '../sql-rows.js';
import { SQLITE_IN_CHUNK_SIZE, chunkArray } from '../sqlite-batch.js';

import type { Evidence } from '../../schemas/evidence.js';
import type { AdvisoryStore } from '../db.js';

const DEFAULT_RAW_PREVIEW_BYTES = 16_384;

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

export function listEvidenceForAdvisoryIds(
  store: AdvisoryStore,
  advisoryIds: string[],
): Map<string, Evidence[]> {
  const map = new Map<string, Evidence[]>();
  const unique = [...new Set(advisoryIds)];
  for (const id of unique) {
    map.set(id, []);
  }
  if (unique.length === 0) {
    return map;
  }

  for (const chunk of chunkArray(unique, SQLITE_IN_CHUNK_SIZE)) {
    const placeholders = chunk.map(() => '?').join(',');
    const rows = store.db
      .prepare(
        `SELECT advisory_id, normalized_json FROM evidence WHERE advisory_id IN (${placeholders}) ORDER BY source`,
      )
      .all(...chunk) as Array<{ advisory_id: string; normalized_json: string }>;
    for (const row of rows) {
      const advisoryId = readStringColumn(row, 'advisory_id');
      const list = map.get(advisoryId) ?? [];
      list.push(evidenceSchema.parse(JSON.parse(row.normalized_json)));
      map.set(advisoryId, list);
    }
  }
  return map;
}

export interface RawRecordPreview {
  id: string;
  source: string;
  sha256: string;
  preview: string;
  truncated: boolean;
}

export function getRawRecordPreview(
  store: AdvisoryStore,
  id: string,
  maxBytes = DEFAULT_RAW_PREVIEW_BYTES,
): RawRecordPreview | null {
  const row = store.db
    .prepare('SELECT source, sha256, payload FROM raw_records WHERE id = ?')
    .get(id) as { source: string; sha256: string; payload: Buffer } | undefined;
  if (!row) {
    return null;
  }
  const payload = row.payload;
  const truncated = payload.length > maxBytes;
  const slice = truncated ? payload.subarray(0, maxBytes) : payload;
  return {
    id,
    source: row.source,
    sha256: row.sha256,
    preview: slice.toString('utf8'),
    truncated,
  };
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
