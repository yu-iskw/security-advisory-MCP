import { z } from 'zod';

import { computeRiskScore } from '../../risk/score.js';
import { riskProfileNameSchema } from '../../schemas/risk.js';
import { findAdvisoryById } from '../../store/repositories/advisory-repository.js';
import { listEvidenceForAdvisory } from '../../store/repositories/evidence-repository.js';

import {
  analyzePackageCoordinate,
  coordinateFromInput,
  formatPackageAnalysisMarkdown,
} from './package-analysis.js';

import type { AdvisoryStore } from '../../store/db.js';

export const analyzePackageInputSchema = z
  .object({
    purl: z.string().optional(),
    ecosystem: z.string().optional(),
    name: z.string().optional(),
    version: z.string().optional(),
    includeMaliciousPackageReports: z.boolean().default(true),
    profile: riskProfileNameSchema.default('application_dependency'),
  })
  .refine((v) => Boolean(v.purl) || Boolean(v.ecosystem && v.name), {
    message: 'Provide purl or ecosystem+name',
  });

export function runAnalyzePackage(
  store: AdvisoryStore,
  input: z.infer<typeof analyzePackageInputSchema>,
) {
  const coordinate = coordinateFromInput(input);
  const analysis = analyzePackageCoordinate(store, coordinate, {
    includeMaliciousPackageReports: input.includeMaliciousPackageReports,
  });

  let topRisk: ReturnType<typeof computeRiskScore> | null = null;
  if (analysis.findings.length > 0) {
    const topFinding = analysis.findings[0];
    const advisory = findAdvisoryById(store, topFinding.advisoryId);
    if (advisory) {
      const evidence = listEvidenceForAdvisory(store, advisory.id);
      topRisk = computeRiskScore(advisory, evidence, input.profile);
    }
  }

  return {
    structured: {
      ecosystem: analysis.ecosystem,
      name: analysis.name,
      version: analysis.version,
      findings: analysis.findings,
      uncertainty: analysis.uncertainty,
      profile: input.profile,
      topRisk,
    },
    markdown: formatPackageAnalysisMarkdown(analysis),
  };
}
