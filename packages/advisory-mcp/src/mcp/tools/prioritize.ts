import { z } from 'zod';

import { RISK_PROFILE_NAMES } from '../../risk/profiles.js';

import { analyzePackage } from './analyze-package.js';
import { explainRisk } from './explain-risk.js';

import type { AdvisoryStore } from '../../store/store.js';

export const PrioritizeInputSchema = z
  .object({
    advisoryIds: z.array(z.string().min(1).max(128)).max(500).optional(),
    packages: z
      .array(
        z.object({
          purl: z.string().optional(),
          ecosystem: z.string().optional(),
          name: z.string().optional(),
          version: z.string().optional(),
        }),
      )
      .max(500)
      .optional(),
    profile: z.enum(RISK_PROFILE_NAMES).default('default'),
  })
  .refine(
    (v) =>
      (v.advisoryIds !== undefined && v.advisoryIds.length > 0) ||
      (v.packages !== undefined && v.packages.length > 0),
    { message: 'Provide at least one of `advisoryIds` or `packages`.' },
  );

type PrioritizeInput = z.infer<typeof PrioritizeInputSchema>;

interface RankedItem {
  advisoryId: string;
  score: number;
  severity: string;
  knownExploited: boolean;
  source: 'advisoryId' | 'package';
  query?: string;
}

interface PrioritizeResult {
  profile: string;
  ranked: RankedItem[];
  markdown: string;
}

export function prioritize(store: AdvisoryStore, input: PrioritizeInput): PrioritizeResult {
  const items: RankedItem[] = [];
  const seen = new Set<string>();

  for (const id of input.advisoryIds ?? []) {
    const result = explainRisk(store, { id, profile: input.profile });
    if (!result.found || !result.risk) continue;
    if (seen.has(id)) continue;
    seen.add(id);
    items.push({
      advisoryId: id,
      score: result.risk.score,
      severity: result.risk.severity,
      knownExploited: store.evidence
        .findByAdvisoryId(id)
        .some((e) => e.source === 'cisa-kev' && e.type === 'known_exploited'),
      source: 'advisoryId',
    });
  }

  for (const pkg of input.packages ?? []) {
    const result = analyzePackage(store, { ...pkg, profile: input.profile });
    const query = pkg.purl ?? `${pkg.ecosystem ?? '?'}/${pkg.name ?? '?'}@${pkg.version ?? '?'}`;
    for (const m of result.matches) {
      if (seen.has(m.advisoryId)) continue;
      seen.add(m.advisoryId);
      items.push({
        advisoryId: m.advisoryId,
        score: m.riskScore ?? 0,
        severity: m.severity ?? 'none',
        knownExploited: m.knownExploited ?? false,
        source: 'package',
        query,
      });
    }
  }

  items.sort((a, b) => b.score - a.score);

  return {
    profile: input.profile,
    ranked: items,
    markdown: renderMarkdown(input.profile, items),
  };
}

function renderMarkdown(profile: string, ranked: RankedItem[]): string {
  if (ranked.length === 0) return 'No matching advisories found.';
  const lines: string[] = [];
  lines.push(`# Prioritized findings (${profile}) — ${ranked.length} item(s)`);
  for (const r of ranked) {
    const flag = r.knownExploited ? ' :rotating_light: KEV' : '';
    const ctx = r.query ? ` from ${r.query}` : '';
    lines.push(`- **${r.advisoryId}** — ${r.score}/100 (${r.severity})${flag}${ctx}`);
  }
  return lines.join('\n');
}
