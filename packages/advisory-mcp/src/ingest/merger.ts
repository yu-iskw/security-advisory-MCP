import { createHash } from 'node:crypto';

import { classifyAdvisoryId, normalizeAdvisoryId, selectCanonicalId } from '../util/advisory-id.js';

import type { Advisory, AffectedPackage, EvidenceConflict } from '../schemas/advisory.js';
import type { Evidence } from '../schemas/evidence.js';
import type { SourceId } from '../schemas/source.js';

export interface NormalizedRecord {
  advisoryId: string;
  aliases: string[];
  advisory: Partial<Advisory>;
  evidence: Evidence;
}

export function mergeRecords(records: NormalizedRecord[]): Advisory[] {
  const groups = new Map<string, NormalizedRecord[]>();
  for (const record of records) {
    const key = selectCanonicalId([record.advisoryId, ...record.aliases]);
    const list = groups.get(key) ?? [];
    list.push(record);
    groups.set(key, list);
  }

  const merged: Advisory[] = [];
  for (const [canonicalId, group] of groups) {
    merged.push(mergeGroup(canonicalId, group));
  }
  return merged;
}

interface MergeAccumulator {
  aliases: Set<string>;
  affected: AffectedPackage[];
  cwes: Set<string>;
  cvss: Advisory['cvss'];
  references: Advisory['references'];
  title?: string;
  description?: string;
  publishedAt?: string;
  modifiedAt?: string;
  epss?: Advisory['epss'];
  kev?: Advisory['kev'];
  ssvc?: Advisory['ssvc'];
}

function accumulateRecords(group: NormalizedRecord[]): MergeAccumulator {
  const acc: MergeAccumulator = {
    aliases: new Set<string>(),
    affected: [],
    cwes: new Set<string>(),
    cvss: [],
    references: [],
  };

  for (const item of group) {
    for (const a of item.aliases) {
      acc.aliases.add(a);
    }
    acc.aliases.add(item.advisoryId);
    const adv = item.advisory;
    if (adv.title && !acc.title) {
      acc.title = adv.title;
    }
    if (adv.description && !acc.description) {
      acc.description = adv.description;
    }
    acc.publishedAt = earliest(acc.publishedAt, adv.publishedAt);
    acc.modifiedAt = latest(acc.modifiedAt, adv.modifiedAt);
    if (adv.affected) {
      acc.affected.push(...adv.affected);
    }
    for (const c of adv.cwes ?? []) {
      acc.cwes.add(c);
    }
    if (adv.cvss) {
      acc.cvss.push(...adv.cvss);
    }
    if (adv.references) {
      acc.references.push(...adv.references);
    }
    acc.epss = adv.epss ?? acc.epss;
    acc.kev = adv.kev ?? acc.kev;
    acc.ssvc = adv.ssvc ?? acc.ssvc;
  }

  return acc;
}

function resolveMergedType(canonicalId: string, group: NormalizedRecord[]): Advisory['type'] {
  if (group.some((g) => (g.advisory as { type?: string }).type === 'malicious-package')) {
    return 'malicious-package';
  }
  const classified = classifyAdvisoryId(canonicalId);
  if (classified === 'cve') {
    return 'cve';
  }
  if (classified === 'ghsa') {
    return 'ghsa';
  }
  if (classified === 'osv') {
    return 'osv';
  }
  return 'other';
}

function mergeGroup(canonicalId: string, group: NormalizedRecord[]): Advisory {
  const acc = accumulateRecords(group);
  const type = resolveMergedType(canonicalId, group);
  const conflicts = detectVersionConflicts(acc.affected);

  return {
    id: normalizeAdvisoryId(canonicalId),
    canonicalId: normalizeAdvisoryId(canonicalId),
    type,
    aliases: [...acc.aliases].filter(
      (a) => normalizeAdvisoryId(a) !== normalizeAdvisoryId(canonicalId),
    ),
    title: acc.title,
    description: acc.description,
    publishedAt: acc.publishedAt,
    modifiedAt: acc.modifiedAt,
    affected: dedupeAffected(acc.affected),
    cwes: [...acc.cwes],
    cvss: acc.cvss,
    epss: acc.epss,
    kev: acc.kev,
    ssvc: acc.ssvc,
    references: acc.references,
    sourceDisagreements: conflicts,
  };
}

function dedupeAffected(packages: AffectedPackage[]): AffectedPackage[] {
  const seen = new Set<string>();
  const out: AffectedPackage[] = [];
  for (const pkg of packages) {
    const key = `${pkg.ecosystem}|${pkg.name}|${pkg.vulnerableRanges.join(',')}|${pkg.source}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    out.push(pkg);
  }
  return out;
}

function detectVersionConflicts(packages: AffectedPackage[]): EvidenceConflict[] {
  const byPkg = new Map<string, AffectedPackage[]>();
  for (const pkg of packages) {
    const key = `${pkg.ecosystem}:${pkg.name}`;
    const list = byPkg.get(key) ?? [];
    list.push(pkg);
    byPkg.set(key, list);
  }
  const conflicts: EvidenceConflict[] = [];
  for (const [, list] of byPkg) {
    if (list.length < 2) {
      continue;
    }
    const ranges = new Set(list.map((p) => p.vulnerableRanges.join('|')));
    if (ranges.size > 1) {
      conflicts.push({
        field: 'affected.versionRange',
        sources: [...new Set(list.map((p) => p.source))] as SourceId[],
        description: `Conflicting version ranges for ${list[0]?.ecosystem}/${list[0]?.name}`,
        severity: 'low',
      });
    }
  }
  return conflicts;
}

function earliest(a?: string, b?: string): string | undefined {
  if (!a) {
    return b;
  }
  if (!b) {
    return a;
  }
  return a < b ? a : b;
}

function latest(a?: string, b?: string): string | undefined {
  if (!a) {
    return b;
  }
  if (!b) {
    return a;
  }
  return a > b ? a : b;
}

export function hashPayload(payload: Buffer | string): string {
  return createHash('sha256').update(payload).digest('hex');
}
