import { z } from 'zod';

import { parseSbom, type SbomComponent } from '../../schemas/sbom.js';
import { LIMITS } from '../../security/limits.js';

import { analyzePackage } from './analyze-package.js';

import type { AdvisoryStore } from '../../store/store.js';

export const ScanSbomInputSchema = z.object({
  sbomJson: z.string().max(LIMITS.maxSbomJsonBytes),
  format: z.enum(['auto', 'cyclonedx', 'spdx']).default('auto'),
  profile: z
    .enum(['default', 'internet_exposed', 'application_dependency', 'container_image'])
    .default('application_dependency'),
  includeDevDependencies: z.boolean().default(false),
  limit: z.number().int().min(1).max(500).default(100),
});

type ScanSbomInput = z.infer<typeof ScanSbomInputSchema>;

interface ScanHit {
  component: { name?: string; version?: string; purl?: string; ecosystem?: string };
  advisoryId: string;
  riskScore?: number;
  severity?: string;
  knownExploited?: boolean;
  malicious: boolean;
}

interface ScanSbomResult {
  format: string;
  scanned: number;
  hits: ScanHit[];
  markdown: string;
}

export function scanSbom(store: AdvisoryStore, input: ScanSbomInput): ScanSbomResult {
  const sbom = parseSbom(input.sbomJson, input.format);
  const components = filterComponents(sbom.components, input.includeDevDependencies).slice(
    0,
    input.limit,
  );

  const hits: ScanHit[] = [];
  for (const component of components) {
    if (component.name === undefined && component.purl === undefined) continue;
    const result = analyzePackage(store, {
      purl: component.purl,
      ecosystem: component.ecosystem,
      name: component.name,
      version: component.version,
      profile: input.profile,
    });
    for (const match of result.matches) {
      hits.push({
        component: {
          name: component.name,
          version: component.version,
          purl: component.purl,
          ecosystem: component.ecosystem,
        },
        advisoryId: match.advisoryId,
        riskScore: match.riskScore,
        severity: match.severity,
        knownExploited: match.knownExploited,
        malicious: match.evidenceType === 'malicious_package',
      });
    }
  }

  hits.sort((a, b) => (b.riskScore ?? 0) - (a.riskScore ?? 0));

  return {
    format: sbom.format,
    scanned: components.length,
    hits,
    markdown: renderMarkdown(sbom.format, components.length, hits),
  };
}

function filterComponents(
  components: ReadonlyArray<SbomComponent>,
  includeDev: boolean,
): SbomComponent[] {
  if (includeDev) return [...components];
  return components.filter((c) => !c.isDev);
}

function renderMarkdown(format: string, scanned: number, hits: ScanHit[]): string {
  const lines: string[] = [];
  lines.push(`# SBOM scan (${format}) — ${scanned} component(s) scanned, ${hits.length} hit(s)`);
  if (hits.length === 0) {
    lines.push('', 'No advisories matched the scanned components.');
    return lines.join('\n');
  }
  for (const h of hits) {
    const pkg = `${h.component.name ?? h.component.purl ?? '?'}${h.component.version ? `@${h.component.version}` : ''}`;
    const flag = h.malicious
      ? ' :rotating_light: MALICIOUS'
      : h.knownExploited === true
        ? ' :rotating_light: KEV'
        : '';
    const score =
      h.riskScore !== undefined ? ` — risk ${h.riskScore}/100 (${h.severity ?? 'n/a'})` : '';
    lines.push(`- **${pkg}** → ${h.advisoryId}${score}${flag}`);
  }
  return lines.join('\n');
}
