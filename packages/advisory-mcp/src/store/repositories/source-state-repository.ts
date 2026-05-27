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

export function listSourceStates(
  store: AdvisoryStore,
  input: SourceStatusInput,
): SourceStateRow[] {
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
      ORDER BY source`,
    )
    .all() as SourceStateDbRow[];

  return rows
    .map(mapRow)
    .filter((row) => {
      if (input.source && row.source !== input.source) {
        return false;
      }
      if (!input.includeDisabled && !row.enabled) {
        return false;
      }
      return true;
    });
}

export interface SourceStatusSummary {
  sources: SourceStateRow[];
  advisoryCount: number;
  evidenceCount: number;
  markdownSummary: string;
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
    lines.push('', '_No source state rows. Run `advisory-mcp init` and `advisory-mcp sync --preset core`._');
  }

  return {
    sources,
    advisoryCount,
    evidenceCount,
    markdownSummary: lines.join('\n'),
  };
}
