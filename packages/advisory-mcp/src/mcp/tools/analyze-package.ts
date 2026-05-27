import { z } from 'zod';

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
    profile: z
      .enum(['default', 'application_dependency', 'container_image'])
      .default('application_dependency'),
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

  return {
    structured: {
      ecosystem: analysis.ecosystem,
      name: analysis.name,
      version: analysis.version,
      findings: analysis.findings,
      uncertainty: analysis.uncertainty,
      profile: input.profile,
    },
    markdown: formatPackageAnalysisMarkdown(analysis),
  };
}
