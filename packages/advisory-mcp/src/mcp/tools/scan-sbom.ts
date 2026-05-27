import { z } from 'zod';

import { parseSbomComponents } from '../../schemas/sbom.js';
import { DEFAULT_MAX_SBOM_BYTES } from '../../security/limits.js';

import { analyzePackageCoordinates } from './package-analysis.js';

import type { AdvisoryStore } from '../../store/db.js';

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
  const json = JSON.parse(input.sbomJson) as unknown;
  let components = parseSbomComponents(json, input.format);
  if (!input.includeDevDependencies) {
    components = components.filter((c) => c.type !== 'dev');
  }
  components = components.slice(0, input.limit);

  const coordinates = components.map((component) => ({
    key: `${component.ecosystem ?? 'generic'}|${component.name}|${component.version ?? ''}`,
    ecosystem: component.ecosystem ?? 'generic',
    name: component.name,
    version: component.version,
  }));

  const analyses = analyzePackageCoordinates(store, coordinates, {
    includeMaliciousPackageReports: true,
  });

  const findings = [];
  for (const component of components) {
    const key = `${component.ecosystem ?? 'generic'}|${component.name}|${component.version ?? ''}`;
    const analysis = analyses.get(key);
    if (!analysis || analysis.findings.length === 0) {
      continue;
    }
    findings.push({
      component: component.name,
      version: component.version,
      findings: analysis.findings,
      uncertainty: analysis.uncertainty,
    });
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
