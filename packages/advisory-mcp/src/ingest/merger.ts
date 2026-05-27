import { createHash } from 'node:crypto';

import type { Advisory, AffectedPackage, EvidenceConflict } from '../schemas/advisory.js';
import type { Evidence } from '../schemas/evidence.js';
import { classifyAdvisoryId, normalizeAdvisoryId, selectCanonicalId } from '../util/advisory-id.js';
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

function mergeGroup(canonicalId: string, group: NormalizedRecord[]): Advisory {
  const aliases = new Set<string>();
  const affected: AffectedPackage[] = [];
  const cwes = new Set<string>();
  const cvss: Advisory['cvss'] = [];
  const references: Advisory['references'] = [];
  const conflicts: EvidenceConflict[] = [];
  let title: string | undefined;
  let description: string | undefined;
  let publishedAt: string | undefined;
  let modifiedAt: string | undefined;
  let epss = undefined;
  let kev = undefined;
  let ssvc = undefined;

  for (const item of group) {
    for (const a of item.aliases) {
      aliases.add(a);
    }
    aliases.add(item.advisoryId);
    const adv = item.advisory;
    if (adv.title && !title) {
      title = adv.title;
    }
    if (adv.description && !description) {
      description = adv.description;
    }
    publishedAt = earliest(publishedAt, adv.publishedAt);
    modifiedAt = latest(modifiedAt, adv.modifiedAt);
    if (adv.affected) {
      affected.push(...adv.affected);
    }
    for (const c of adv.cwes ?? []) {
      cwes.add(c);
    }
    if (adv.cvss) {
      cvss.push(...adv.cvss);
    }
    if (adv.references) {
      references.push(...adv.references);
    }
    epss = adv.epss ?? epss;
    kev = adv.kev ?? kev;
    ssvc = adv.ssvc ?? ssvc;
  }

  const isMalicious = group.some(
    (g) => (g.advisory as { type?: string }).type === 'malicious-package',
  );
  const type = isMalicious
    ? 'malicious-package'
    : classifyAdvisoryId(canonicalId) === 'cve'
      ? 'cve'
      : classifyAdvisoryId(canonicalId) === 'ghsa'
        ? 'ghsa'
        : classifyAdvisoryId(canonicalId) === 'osv'
          ? 'osv'
          : 'other';

  const versionConflicts = detectVersionConflicts(affected);
  conflicts.push(...versionConflicts);

  return {
    id: normalizeAdvisoryId(canonicalId),
    canonicalId: normalizeAdvisoryId(canonicalId),
    type,
    aliases: [...aliases].filter(
      (a) => normalizeAdvisoryId(a) !== normalizeAdvisoryId(canonicalId),
    ),
    title,
    description,
    publishedAt,
    modifiedAt,
    affected: dedupeAffected(affected),
    cwes: [...cwes],
    cvss,
    epss,
    kev,
    ssvc,
    references,
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
