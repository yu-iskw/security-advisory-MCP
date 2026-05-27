import { parsePurl } from '../../schemas/purl.js';
import {
  findAdvisoriesByIds,
  listAdvisoryIdsForPackage,
} from '../../store/repositories/advisory-repository.js';

import type { Advisory, AffectedPackage } from '../../schemas/advisory.js';
import type { AdvisoryStore } from '../../store/db.js';

export interface PackageCoordinate {
  key: string;
  ecosystem: string;
  name: string;
  version?: string;
}

export interface PackageFinding {
  advisoryId: string;
  title?: string;
  vulnerable: boolean;
  fixedVersions: string[];
}

export interface PackageAnalysisResult {
  ecosystem: string;
  name: string;
  version?: string;
  findings: PackageFinding[];
  uncertainty: string[];
}

export interface PackageAnalysisOptions {
  includeMaliciousPackageReports: boolean;
}

function packageLookupKey(ecosystem: string, name: string): string {
  return `${ecosystem}|${name}`;
}

function matchingAffected(advisory: Advisory, ecosystem: string, name: string): AffectedPackage[] {
  const lowerName = name.toLowerCase();
  return advisory.affected.filter(
    (p) => p.ecosystem === ecosystem && p.name.toLowerCase() === lowerName,
  );
}

function isAffectedVersionVulnerable(affected: AffectedPackage[], version?: string): boolean {
  if (affected.length === 0) {
    return false;
  }
  if (!version) {
    return affected.some(
      (p) =>
        p.vulnerableRanges.length === 0 ||
        p.vulnerableRanges.some((r) => r === '*' || r.length > 0),
    );
  }
  return affected.some((p) => p.vulnerableRanges.length > 0);
}

function buildFindingsForPackage(
  advisories: Iterable<Advisory>,
  ecosystem: string,
  name: string,
  version: string | undefined,
  options: PackageAnalysisOptions,
): PackageFinding[] {
  const findings: PackageFinding[] = [];
  for (const advisory of advisories) {
    if (!options.includeMaliciousPackageReports && advisory.type === 'malicious-package') {
      continue;
    }
    const affected = matchingAffected(advisory, ecosystem, name);
    if (!isAffectedVersionVulnerable(affected, version)) {
      continue;
    }
    findings.push({
      advisoryId: advisory.canonicalId,
      title: advisory.title,
      vulnerable: true,
      fixedVersions: affected.flatMap((p) => p.fixedVersions),
    });
  }
  return findings;
}

function uncertaintyForCoordinate(version?: string, matchedRows = 0, findings = 0): string[] {
  const uncertainty: string[] = [];
  if (version) {
    uncertainty.push(
      'Semantic version range matching is not implemented; results are based on affected-package rows only.',
    );
  }
  if (findings === 0 && matchedRows === 0) {
    uncertainty.push(
      'No affected-package rows matched. Use search_advisories for full-text lookup by name.',
    );
  }
  return uncertainty;
}

export function coordinateFromInput(input: {
  purl?: string;
  ecosystem?: string;
  name?: string;
  version?: string;
}): PackageCoordinate {
  const parsed = input.purl ? parsePurl(input.purl) : null;
  const ecosystem = parsed?.type ?? input.ecosystem ?? 'unknown';
  const name = parsed?.name ?? input.name ?? 'unknown';
  const version = parsed?.version ?? input.version;
  return {
    key: `${ecosystem}|${name}|${version ?? ''}`,
    ecosystem,
    name,
    version,
  };
}

export function formatPackageAnalysisMarkdown(analysis: PackageAnalysisResult): string {
  return [
    `# Package analysis: ${analysis.ecosystem}/${analysis.name}${analysis.version ? `@${analysis.version}` : ''}`,
    '',
    analysis.findings.length === 0
      ? 'No matching advisories in local database (affected_packages).'
      : analysis.findings
          .map((f) => `- ${f.advisoryId}: ${f.title ?? 'untitled'} (vulnerable=${f.vulnerable})`)
          .join('\n'),
    analysis.uncertainty.length > 0
      ? `\n## Uncertainty\n${analysis.uncertainty.map((u) => `- ${u}`).join('\n')}`
      : '',
  ].join('\n');
}

export function analyzePackageCoordinate(
  store: AdvisoryStore,
  coordinate: PackageCoordinate,
  options: PackageAnalysisOptions,
): PackageAnalysisResult {
  const batch = analyzePackageCoordinates(store, [coordinate], options);
  return (
    batch.get(coordinate.key) ?? {
      ecosystem: coordinate.ecosystem,
      name: coordinate.name,
      version: coordinate.version,
      findings: [],
      uncertainty: uncertaintyForCoordinate(coordinate.version),
    }
  );
}

export function analyzePackageCoordinates(
  store: AdvisoryStore,
  coordinates: PackageCoordinate[],
  options: PackageAnalysisOptions,
): Map<string, PackageAnalysisResult> {
  const idsByLookup = new Map<string, string[]>();
  for (const coordinate of coordinates) {
    const lookup = packageLookupKey(coordinate.ecosystem, coordinate.name);
    if (!idsByLookup.has(lookup)) {
      idsByLookup.set(
        lookup,
        listAdvisoryIdsForPackage(store, coordinate.ecosystem, coordinate.name),
      );
    }
  }

  const allAdvisoryIds = new Set<string>();
  for (const ids of idsByLookup.values()) {
    for (const id of ids) {
      allAdvisoryIds.add(id);
    }
  }
  const advisoriesById = findAdvisoriesByIds(store, [...allAdvisoryIds]);

  const results = new Map<string, PackageAnalysisResult>();
  for (const coordinate of coordinates) {
    const lookup = packageLookupKey(coordinate.ecosystem, coordinate.name);
    const ids = idsByLookup.get(lookup) ?? [];
    const advisories = ids
      .map((id) => advisoriesById.get(id))
      .filter((a): a is Advisory => a !== undefined);
    const findings = buildFindingsForPackage(
      advisories,
      coordinate.ecosystem,
      coordinate.name,
      coordinate.version,
      options,
    );
    results.set(coordinate.key, {
      ecosystem: coordinate.ecosystem,
      name: coordinate.name,
      version: coordinate.version,
      findings,
      uncertainty: uncertaintyForCoordinate(coordinate.version, ids.length, findings.length),
    });
  }
  return results;
}
