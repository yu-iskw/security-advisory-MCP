import type { FreshnessSummary } from '../../schemas/risk.js';
import type { AdvisoryStore } from '../db.js';

const STALE_MS = 7 * 24 * 60 * 60 * 1000;

export function buildFreshnessSummary(store: AdvisoryStore): FreshnessSummary {
  const rows = store.db
    .prepare(`SELECT source, last_success_at, status FROM source_state WHERE enabled = 1`)
    .all() as Array<{ source: string; last_success_at: string | null; status: string }>;

  const warnings: string[] = [];
  const staleSources: string[] = [];
  let oldest: string | null = null;

  for (const row of rows) {
    if (!row.last_success_at) {
      staleSources.push(row.source);
      warnings.push(`Source ${row.source} has never completed a successful sync.`);
      continue;
    }
    if (!oldest || row.last_success_at < oldest) {
      oldest = row.last_success_at;
    }
    const age = Date.now() - new Date(row.last_success_at).getTime();
    if (age > STALE_MS || row.status === 'stale' || row.status === 'never_synced') {
      staleSources.push(row.source);
      warnings.push(`Source ${row.source} may be stale (last success ${row.last_success_at}).`);
    }
  }

  return {
    oldestSourceSuccess: oldest,
    staleSources,
    warnings,
  };
}
