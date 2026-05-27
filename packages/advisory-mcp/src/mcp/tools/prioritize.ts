import { z } from 'zod';

import { computeRiskScore } from '../../risk/score.js';
import { findAdvisoriesByIds } from '../../store/repositories/advisory-repository.js';
import { listEvidenceForAdvisoryIds } from '../../store/repositories/evidence-repository.js';

import { runAnalyzePackage } from './analyze-package.js';

import type { AdvisoryStore } from '../../store/db.js';

export const prioritizeInputSchema = z.object({
  advisoryIds: z.array(z.string()).max(500).optional(),
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
  profile: z
    .enum(['default', 'internet_exposed', 'application_dependency', 'container_image', 'executive'])
    .default('default'),
});

export function runPrioritize(store: AdvisoryStore, input: z.infer<typeof prioritizeInputSchema>) {
  const ids = new Set(input.advisoryIds ?? []);

  if (input.packages) {
    for (const pkg of input.packages) {
      const result = runAnalyzePackage(store, {
        ...pkg,
        includeMaliciousPackageReports: true,
        profile: 'application_dependency',
      });
      for (const f of result.structured.findings) {
        ids.add(f.advisoryId);
      }
    }
  }

  const idList = [...ids];
  const advisories = findAdvisoriesByIds(store, idList);
  const evidenceByAdvisory = listEvidenceForAdvisoryIds(store, idList);

  const ranked = idList.map((id) => {
    const advisory =
      advisories.get(id) ?? [...advisories.values()].find((a) => a.canonicalId === id);
    if (!advisory) {
      return { id, score: 0, severity: 'none' as const, title: undefined };
    }
    const evidence = evidenceByAdvisory.get(advisory.id) ?? [];
    const risk = computeRiskScore(advisory, evidence, input.profile);
    return {
      id: advisory.canonicalId,
      score: risk.score,
      severity: risk.severity,
      title: advisory.title,
    };
  });

  ranked.sort((a, b) => b.score - a.score);

  const markdown = [
    '# Prioritized advisories',
    '',
    '| Rank | ID | Score | Severity |',
    '| --- | --- | --- | --- |',
    ...ranked.map((r, i) => `| ${i + 1} | ${r.id} | ${r.score} | ${r.severity} |`),
  ].join('\n');

  return { structured: { ranked }, markdown };
}
