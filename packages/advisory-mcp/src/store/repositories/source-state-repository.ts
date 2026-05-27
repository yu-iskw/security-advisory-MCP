import {
  sourceIdSchema,
  sourceStateRowSchema,
  sourceStatusSchema,
  syncPresetSchema,
  type SourceStateRow,
  type SourceStatusInput,
} from '../../schemas/source.js';

import type { AdvisoryStore } from '../db.js';

interface SourceStateDbRow {
  source: string;
  enabled: number;
  preset: string;
  last_sync_started_at: string | null;
  last_sync_completed_at: string | null;
  last_success_at: string | null;
  last_error: string | null;
  version: string | null;
  etag: string | null;
  last_modified: string | null;
  sha256: string | null;
  status: string;
}

function mapRow(row: SourceStateDbRow): SourceStateRow {
  return sourceStateRowSchema.parse({
    source: sourceIdSchema.parse(row.source),
    enabled: row.enabled === 1,
    preset: syncPresetSchema.parse(row.preset),
    lastSyncStartedAt: row.last_sync_started_at,
    lastSyncCompletedAt: row.last_sync_completed_at,
    lastSuccessAt: row.last_success_at,
    lastError: row.last_error,
    version: row.version,
    etag: row.etag,
    lastModified: row.last_modified,
    sha256: row.sha256,
    status: sourceStatusSchema.parse(row.status),
  });
}

export function listSourceStates(store: AdvisoryStore, input: SourceStatusInput): SourceStateRow[] {
  const conditions: string[] = [];
  const params: { source?: string } = {};

  if (input.source) {
    conditions.push('source = @source');
    params.source = input.source;
  }
  if (!input.includeDisabled) {
    conditions.push('enabled = 1');
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const rows = store.db
    .prepare(
      `SELECT
        source,
        enabled,
        preset,
        last_sync_started_at,
        last_sync_completed_at,
        last_success_at,
        last_error,
        version,
        etag,
        last_modified,
        sha256,
        status
      FROM source_state
      ${where}
      ORDER BY source`,
    )
    .all(params) as SourceStateDbRow[];

  return rows.map(mapRow);
}

export interface SourceStatusSummary {
  sources: SourceStateRow[];
  advisoryCount: number;
  evidenceCount: number;
  markdownSummary: string;
}

export function sourceStatusPayload(summary: SourceStatusSummary): {
  sources: SourceStateRow[];
  advisoryCount: number;
  evidenceCount: number;
} {
  return {
    sources: summary.sources,
    advisoryCount: summary.advisoryCount,
    evidenceCount: summary.evidenceCount,
  };
}

export function buildSourceStatusSummary(
  store: AdvisoryStore,
  input: SourceStatusInput,
): SourceStatusSummary {
  const sources = listSourceStates(store, input);
  const advisoryCount = (
    store.db.prepare('SELECT COUNT(*) AS count FROM advisories').get() as { count: number }
  ).count;
  const evidenceCount = (
    store.db.prepare('SELECT COUNT(*) AS count FROM evidence').get() as { count: number }
  ).count;

  const lines = [
    '# Advisory source status',
    '',
    `Advisories indexed: **${advisoryCount}**`,
    `Evidence rows: **${evidenceCount}**`,
    '',
    '| Source | Status | Enabled | Last success |',
    '| --- | --- | --- | --- |',
    ...sources.map(
      (s) =>
        `| ${s.source} | ${s.status} | ${s.enabled ? 'yes' : 'no'} | ${s.lastSuccessAt ?? '—'} |`,
    ),
  ];

  if (sources.length === 0) {
    lines.push(
      '',
      '_No source state rows. Run `advisory-mcp init` and `advisory-mcp sync --preset core`._',
    );
  }

  return {
    sources,
    advisoryCount,
    evidenceCount,
    markdownSummary: lines.join('\n'),
  };
}
