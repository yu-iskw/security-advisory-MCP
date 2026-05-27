import { z } from 'zod';

import { parsePurl } from '../../schemas/purl.js';
import {
  findAdvisoryById,
  searchAdvisories,
} from '../../store/repositories/advisory-repository.js';
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
  const parsed = input.purl ? parsePurl(input.purl) : null;
  const ecosystem = parsed?.type ?? input.ecosystem ?? 'unknown';
  const name = parsed?.name ?? input.name ?? 'unknown';
  const version = parsed?.version ?? input.version;

  const rows = store.db
    .prepare(
      `SELECT DISTINCT advisory_id FROM affected_packages
       WHERE ecosystem = ? AND name = ? COLLATE NOCASE`,
    )
    .all(ecosystem, name) as Array<{ advisory_id: string }>;

  const findings = [];
  for (const row of rows) {
    const advisory = findAdvisoryById(store, row.advisory_id);
    if (!advisory) {
      continue;
    }
    if (!input.includeMaliciousPackageReports && advisory.type === 'malicious-package') {
      continue;
    }
    const vulnerable = version
      ? advisory.affected.some((p) => p.vulnerableRanges.length > 0)
      : true;
    findings.push({
      advisoryId: advisory.canonicalId,
      title: advisory.title,
      vulnerable,
      fixedVersions: advisory.affected.flatMap((p) => p.fixedVersions),
    });
  }

  if (findings.length === 0) {
    const fallback = searchAdvisories(store, name, 5);
    for (const adv of fallback) {
      findings.push({
        advisoryId: adv.canonicalId,
        title: adv.title,
        vulnerable: true,
        fixedVersions: [],
      });
    }
  }

  const markdown = [
    `# Package analysis: ${ecosystem}/${name}${version ? `@${version}` : ''}`,
    '',
    findings.length === 0
      ? 'No matching advisories in local database.'
      : findings
          .map((f) => `- ${f.advisoryId}: ${f.title ?? 'untitled'} (vulnerable=${f.vulnerable})`)
          .join('\n'),
  ].join('\n');

  return { structured: { ecosystem, name, version, findings, profile: input.profile }, markdown };
}
