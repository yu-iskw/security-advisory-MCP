import { z } from 'zod';

import { parseSbomComponents } from '../../schemas/sbom.js';
import { runAnalyzePackage } from './analyze-package.js';
import type { AdvisoryStore } from '../../store/db.js';
import { DEFAULT_MAX_SBOM_BYTES } from '../../security/limits.js';

export const scanSbomInputSchema = z.object({
  sbomJson: z.string().max(DEFAULT_MAX_SBOM_BYTES),
  format: z.enum(['cyclonedx', 'spdx', 'auto']).default('auto'),
  profile: z
    .enum(['default', 'application_dependency', 'container_image'])
    .default('application_dependency'),
  includeDevDependencies: z.boolean().default(false),
  limit: z.number().int().min(1).max(500).default(100),
});

export function runScanSbom(store: AdvisoryStore, input: z.infer<typeof scanSbomInputSchema>) {
  if (input.sbomJson.length > DEFAULT_MAX_SBOM_BYTES) {
    throw new Error('SBOM exceeds maximum allowed size');
  }
  const json = JSON.parse(input.sbomJson) as unknown;
  let components = parseSbomComponents(json, input.format);
  if (!input.includeDevDependencies) {
    components = components.filter((c) => c.type !== 'dev');
  }
  components = components.slice(0, input.limit);

  const findings = [];
  for (const component of components) {
    const result = runAnalyzePackage(store, {
      purl: component.purl,
      ecosystem: component.ecosystem ?? 'generic',
      name: component.name,
      version: component.version,
      includeMaliciousPackageReports: true,
      profile: input.profile,
    });
    if (result.structured.findings.length > 0) {
      findings.push({
        component: component.name,
        version: component.version,
        findings: result.structured.findings,
      });
    }
  }

  const markdown = [
    `# SBOM scan (${input.format})`,
    `Components scanned: ${components.length}`,
    `Findings: ${findings.length}`,
    '',
    ...findings.map(
      (f) =>
        `- **${f.component}@${f.version ?? '?'}**: ${f.findings.map((x) => x.advisoryId).join(', ')}`,
    ),
  ].join('\n');

  return { structured: { findings, componentsScanned: components.length }, markdown };
}
