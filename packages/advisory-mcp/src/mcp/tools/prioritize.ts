import { z } from 'zod';

import { findAdvisoryById } from '../../store/repositories/advisory-repository.js';
import { listEvidenceForAdvisory } from '../../store/repositories/evidence-repository.js';
import type { AdvisoryStore } from '../../store/db.js';
import { computeRiskScore } from '../../risk/score.js';
import { runAnalyzePackage } from './analyze-package.js';

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

  const ranked = [...ids].map((id) => {
    const advisory = findAdvisoryById(store, id);
    if (!advisory) {
      return { id, score: 0, severity: 'none' as const };
    }
    const evidence = listEvidenceForAdvisory(store, advisory.id);
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
