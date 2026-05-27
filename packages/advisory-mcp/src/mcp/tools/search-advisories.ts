import { z } from 'zod';

import { computeRiskScore } from '../../risk/score.js';
import { sourceIdSchema } from '../../schemas/source.js';
import { searchAdvisories as searchDb } from '../../store/repositories/advisory-repository.js';
import { listEvidenceForAdvisory } from '../../store/repositories/evidence-repository.js';
import { escapeMarkdownTableCell } from '../../util/markdown.js';

import type { AdvisoryStore } from '../../store/db.js';

export const searchAdvisoriesInputSchema = z.object({
  query: z.string().min(1).max(200),
  ecosystem: z.string().optional(),
  source: sourceIdSchema.optional(),
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
  hasFix: z.boolean().optional(),
  knownExploited: z.boolean().optional(),
  limit: z.number().int().min(1).max(50).default(10),
});

export type SearchAdvisoriesInput = z.infer<typeof searchAdvisoriesInputSchema>;

function advisoryMatchesSource(
  advisory: { affected: Array<{ source: string }> },
  source: z.infer<typeof sourceIdSchema>,
): boolean {
  return advisory.affected.some((pkg) => pkg.source === source);
}

export function runSearchAdvisories(store: AdvisoryStore, input: SearchAdvisoriesInput) {
  let results = searchDb(store, input.query, input.limit * 3);

  if (input.ecosystem) {
    results = results.filter((a) =>
      a.affected.some((p) => p.ecosystem.toLowerCase() === input.ecosystem?.toLowerCase()),
    );
  }
  if (input.source) {
    results = results.filter((a) => {
      if (advisoryMatchesSource(a, input.source!)) {
        return true;
      }
      const evidence = listEvidenceForAdvisory(store, a.id);
      return evidence.some((e) => e.source === input.source);
    });
  }
  if (input.knownExploited) {
    results = results.filter((a) => Boolean(a.kev));
  }
  if (input.hasFix) {
    results = results.filter((a) => a.affected.some((p) => p.fixedVersions.length > 0));
  }

  const enriched = results.slice(0, input.limit).map((advisory) => {
    const evidence = listEvidenceForAdvisory(store, advisory.id);
    const risk = computeRiskScore(advisory, evidence, 'default');
    return {
      id: advisory.canonicalId,
      title: advisory.title,
      severity: risk.severity,
      score: risk.score,
      kev: Boolean(advisory.kev),
    };
  });

  if (input.severity) {
    const target = input.severity.toLowerCase();
    const filtered = enriched.filter((r) => r.severity === target);
    return formatSearchResult(filtered, input.query);
  }

  return formatSearchResult(enriched, input.query);
}

function formatSearchResult(
  items: Array<{ id: string; title?: string; severity: string; score: number; kev: boolean }>,
  query: string,
) {
  const lines = [
    `# Advisory search: "${query}"`,
    '',
    '| ID | Severity | Score | KEV | Title |',
    '| --- | --- | --- | --- | --- |',
    ...items.map(
      (i) =>
        `| ${i.id} | ${i.severity} | ${i.score} | ${i.kev ? 'yes' : 'no'} | ${escapeMarkdownTableCell(i.title ?? '')} |`,
    ),
  ];
  return {
    structured: { results: items },
    markdown: lines.join('\n'),
  };
}
