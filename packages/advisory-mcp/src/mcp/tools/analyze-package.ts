import { z } from 'zod';

import { parsePurl } from '../../schemas/purl.js';
import { canonicalEcosystem } from '../../util/ecosystems.js';
import { compareVersion } from '../../util/version-range.js';

import { explainRisk } from './explain-risk.js';

import type { AdvisoryStore } from '../../store/store.js';

export const AnalyzePackageInputSchema = z
  .object({
    purl: z.string().optional(),
    ecosystem: z.string().optional(),
    name: z.string().optional(),
    version: z.string().optional(),
    profile: z
      .enum([
        'default',
        'internet_exposed',
        'application_dependency',
        'container_image',
        'executive',
        'research',
      ])
      .default('application_dependency'),
  })
  .refine((v) => v.purl !== undefined || (v.ecosystem !== undefined && v.name !== undefined), {
    message: 'Provide either `purl` or both `ecosystem` and `name`.',
  });

type AnalyzePackageInput = z.infer<typeof AnalyzePackageInputSchema>;

interface PackageHit {
  advisoryId: string;
  source: string;
  evidenceType: 'vulnerability' | 'malicious_package';
  affected: boolean;
  riskScore?: number;
  severity?: string;
  knownExploited?: boolean;
}

interface AnalyzePackageResult {
  query: { ecosystem: string; name: string; version?: string };
  matches: PackageHit[];
  malicious: boolean;
  markdown: string;
}

export function analyzePackage(
  store: AdvisoryStore,
  input: AnalyzePackageInput,
): AnalyzePackageResult {
  const resolved = resolveQuery(input);
  const rows = store.affectedPackages.findByEcosystemAndName(resolved.ecosystem, resolved.name);

  const matches: PackageHit[] = [];
  let malicious = false;
  const seenAdvisories = new Set<string>();
  for (const row of rows) {
    const advisory = store.advisories.findById(row.advisoryId);
    const isMalicious = advisory?.type === 'malicious_package';
    if (isMalicious) malicious = true;
    const affected = isMalicious || isVersionAffected(resolved.version, row);
    if (!affected) continue;
    if (seenAdvisories.has(row.advisoryId)) continue;
    seenAdvisories.add(row.advisoryId);
    const risk = explainRisk(store, { id: row.advisoryId, profile: input.profile });
    const evidence = store.evidence.findByAdvisoryId(row.advisoryId);
    matches.push({
      advisoryId: row.advisoryId,
      source: row.source,
      evidenceType: isMalicious ? 'malicious_package' : 'vulnerability',
      affected,
      riskScore: risk.risk?.score,
      severity: risk.risk?.severity,
      knownExploited: evidence.some((e) => e.source === 'cisa-kev' && e.type === 'known_exploited'),
    });
  }

  matches.sort((a, b) => (b.riskScore ?? 0) - (a.riskScore ?? 0));

  return {
    query: resolved,
    matches,
    malicious,
    markdown: renderMarkdown(resolved, matches, malicious),
  };
}

function resolveQuery(input: AnalyzePackageInput): {
  ecosystem: string;
  name: string;
  version?: string;
} {
  if (input.purl) {
    const p = parsePurl(input.purl);
    const eco = canonicalEcosystem(p.type) ?? p.type;
    // OSV name shape varies by ecosystem:
    //   - Maven uses `groupId:artifactId`
    //   - npm scoped, go, composer, ... use `namespace/name`
    let name = p.name;
    if (p.namespace !== undefined) {
      name = eco === 'maven' ? `${p.namespace}:${p.name}` : `${p.namespace}/${p.name}`;
    }
    return { ecosystem: eco, name, version: p.version ?? input.version };
  }
  const eco = canonicalEcosystem(input.ecosystem ?? '') ?? input.ecosystem ?? '';
  return { ecosystem: eco, name: input.name ?? '', version: input.version };
}

function isVersionAffected(
  version: string | undefined,
  row: { vulnerableRange: string | null; fixedVersion: string | null },
): boolean {
  if (version === undefined) return true; // unknown version → assume affected, conservative
  const range = row.vulnerableRange;
  const introduced = range !== null && range.startsWith('>=') ? range.slice(2) : undefined;
  if (introduced !== undefined && compareVersion('', version, introduced) < 0) return false;
  if (row.fixedVersion !== null && compareVersion('', version, row.fixedVersion) >= 0) {
    return false;
  }
  return true;
}

function renderMarkdown(
  q: { ecosystem: string; name: string; version?: string },
  matches: PackageHit[],
  malicious: boolean,
): string {
  const lines: string[] = [];
  const versionText = q.version ? `@${q.version}` : '';
  lines.push(`# ${q.ecosystem}/${q.name}${versionText}`);
  if (malicious) {
    lines.push('', ':rotating_light: **Malicious package match.** Do not install.');
  }
  if (matches.length === 0) {
    lines.push('', 'No matching advisories in the local store.');
  } else {
    lines.push('', `**Matches:** ${matches.length}`);
    for (const m of matches) {
      const flag = m.knownExploited ? ' :rotating_light: KEV' : '';
      const score =
        m.riskScore !== undefined ? ` — risk ${m.riskScore}/100 (${m.severity ?? 'n/a'})` : '';
      lines.push(`- **${m.advisoryId}** (${m.evidenceType})${score}${flag}`);
    }
  }
  return lines.join('\n');
}
