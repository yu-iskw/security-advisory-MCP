import { z } from 'zod';

import { ageMs, nowIso } from '../../util/time.js';

import type { AdvisoryStore } from '../../store/store.js';

export const SourceStatusInputSchema = z.object({
  source: z.string().min(1).max(64).optional(),
  staleAfterHours: z
    .number()
    .int()
    .min(1)
    .max(24 * 30)
    .default(168)
    .optional(),
});

type SourceStatusInput = z.infer<typeof SourceStatusInputSchema>;

interface SourceStatusEntry {
  source: string;
  enabled: boolean;
  preset: string;
  status: string;
  lastSuccessAt: string | null;
  lastError: string | null;
  ageHours: number | null;
  stale: boolean;
}

interface SourceStatusResultShape {
  asOf: string;
  staleAfterHours: number;
  sources: SourceStatusEntry[];
  markdown: string;
}

export function sourceStatus(
  store: AdvisoryStore,
  input: SourceStatusInput,
): SourceStatusResultShape {
  const asOf = nowIso();
  const staleAfterHours = input.staleAfterHours ?? 168;
  const cutoffMs = staleAfterHours * 3_600_000;
  const rows = store.sourceState.listAll();

  const filtered = input.source ? rows.filter((r) => r.source === input.source) : rows;
  const refDate = new Date(asOf);

  const sources: SourceStatusEntry[] = filtered.map((r) => {
    let ageHours: number | null = null;
    let stale = true;
    if (r.lastSuccessAt) {
      const ms = ageMs(r.lastSuccessAt, refDate);
      ageHours = Math.round((ms / 3_600_000) * 10) / 10;
      stale = ms > cutoffMs;
    }
    return {
      source: r.source,
      enabled: r.enabled,
      preset: r.preset,
      status: r.status,
      lastSuccessAt: r.lastSuccessAt,
      lastError: r.lastError,
      ageHours,
      stale,
    };
  });

  return {
    asOf,
    staleAfterHours,
    sources,
    markdown: renderMarkdown(sources, staleAfterHours),
  };
}

function renderMarkdown(entries: SourceStatusEntry[], staleHours: number): string {
  if (entries.length === 0) return 'No source state recorded yet. Run `advisory-mcp sync`.';
  const lines: string[] = [];
  lines.push(`# Source status (stale threshold: ${staleHours}h)`);
  for (const e of entries) {
    const flag = e.stale ? ' :warning: stale' : '';
    const age = e.ageHours == null ? 'never synced' : `${e.ageHours}h ago`;
    lines.push(`- **${e.source}** (${e.preset}) — ${e.status}, ${age}${flag}`);
  }
  return lines.join('\n');
}
