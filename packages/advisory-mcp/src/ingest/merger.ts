import { sanitizeText } from '../security/content-sanitizer.js';

import type { EvidenceRowForMerge } from './merger-types.js';

/**
 * Merge per-source evidence rows for one advisory into a canonical
 * representation with field-level provenance. Sources are not flattened
 * into a single "truth": disagreements are preserved in `conflicts[]` so
 * downstream consumers can surface them.
 *
 * Source precedence (RFC 16.2):
 *
 *   title / description / publishedAt / cvss:
 *     CNA (cveproject) > ADP (cisa-vulnrichment) > NVD (nvd-feed) > KEV
 *
 *   exploitation:
 *     CISA KEV > Vulnrichment SSVC > EPSS
 *
 *   modifiedAt: most recent across sources.
 *   cwes: union, with the source recorded.
 */

type Severity = 'none' | 'low' | 'medium' | 'high' | 'critical';

interface MergedCvss {
  baseScore?: number;
  baseSeverity?: string;
  vectorString?: string;
  source: string;
}

interface MergedCwe {
  cweId: string;
  source: string;
}

interface EvidenceConflict {
  field: string;
  sources: string[];
  description: string;
  severity: 'low' | 'medium' | 'high';
}

interface MergedAdvisory {
  canonicalId: string;
  title?: string;
  description?: string;
  publishedAt?: string;
  modifiedAt?: string;
  cvss?: MergedCvss;
  cwes: MergedCwe[];
  knownExploited: boolean;
  exploitationSources: string[];
  epss?: { probability: number; percentile: number };
  severity: Severity;
  conflicts: EvidenceConflict[];
  perSource: Record<string, { evidenceType: string; provenance?: string }>;
}

const SOURCE_PRIORITY: ReadonlyArray<string> = [
  'cveproject',
  'cisa-vulnrichment',
  'nvd-feed',
  'cisa-kev',
  'first-epss',
];

export function mergeAdvisory(
  canonicalId: string,
  rows: ReadonlyArray<EvidenceRowForMerge>,
): MergedAdvisory {
  const sorted = sortByPriority(rows);
  const ctx: MergeContext = {
    canonicalId,
    cwes: new Map<string, MergedCwe>(),
    conflicts: [],
    perSource: {},
    exploitationSources: [],
    titleBySource: new Map<string, string>(),
    descriptionBySource: new Map<string, string>(),
  };
  const merged: MergedAdvisory = {
    canonicalId,
    cwes: [],
    knownExploited: false,
    exploitationSources: [],
    severity: 'none',
    conflicts: [],
    perSource: {},
  };

  for (const row of sorted) {
    applyRow(row, ctx, merged);
  }
  finalize(merged, ctx);
  return merged;
}

interface MergeContext {
  canonicalId: string;
  cwes: Map<string, MergedCwe>;
  conflicts: EvidenceConflict[];
  perSource: Record<string, { evidenceType: string; provenance?: string }>;
  exploitationSources: string[];
  titleBySource: Map<string, string>;
  descriptionBySource: Map<string, string>;
}

function sortByPriority(rows: ReadonlyArray<EvidenceRowForMerge>): EvidenceRowForMerge[] {
  return [...rows].sort((a, b) => indexOrLast(a.source) - indexOrLast(b.source));
}

function indexOrLast(source: string): number {
  const idx = SOURCE_PRIORITY.indexOf(source);
  return idx === -1 ? SOURCE_PRIORITY.length : idx;
}

function applyRow(
  row: EvidenceRowForMerge,
  ctx: MergeContext,
  merged: MergedAdvisory,
): void {
  const normalized = safeParse(row.normalizedJson);
  const provenance = typeof normalized.provenance === 'string' ? normalized.provenance : undefined;
  ctx.perSource[row.source] = { evidenceType: row.evidenceType, provenance };

  applyDraftFields(row, ctx, merged);
  applyCvss(row, normalized, merged);
  applyCwes(row, normalized, ctx);
  applyExploitation(row, normalized, merged, ctx);
  applyEpss(row, normalized, merged);
}

function applyDraftFields(
  row: EvidenceRowForMerge,
  ctx: MergeContext,
  merged: MergedAdvisory,
): void {
  if (row.title) {
    ctx.titleBySource.set(row.source, row.title);
    if (merged.title === undefined) merged.title = sanitizeText(row.title, { maxChars: 256 });
  }
  if (row.description) {
    ctx.descriptionBySource.set(row.source, row.description);
    if (merged.description === undefined) merged.description = sanitizeText(row.description);
  }
  if (row.publishedAt && merged.publishedAt === undefined) merged.publishedAt = row.publishedAt;
  if (row.modifiedAt) {
    if (merged.modifiedAt === undefined || row.modifiedAt > merged.modifiedAt) {
      merged.modifiedAt = row.modifiedAt;
    }
  }
}

function applyCvss(
  row: EvidenceRowForMerge,
  normalized: Record<string, unknown>,
  merged: MergedAdvisory,
): void {
  const cvss = extractCvss(normalized);
  if (cvss && !merged.cvss) {
    merged.cvss = { ...cvss, source: row.source };
  }
}

function applyCwes(
  row: EvidenceRowForMerge,
  normalized: Record<string, unknown>,
  ctx: MergeContext,
): void {
  const cwes = normalized.cwes;
  if (!Array.isArray(cwes)) return;
  for (const cwe of cwes) {
    if (typeof cwe !== 'string') continue;
    if (!ctx.cwes.has(cwe)) ctx.cwes.set(cwe, { cweId: cwe, source: row.source });
  }
}

function applyExploitation(
  row: EvidenceRowForMerge,
  normalized: Record<string, unknown>,
  merged: MergedAdvisory,
  ctx: MergeContext,
): void {
  if (row.source === 'cisa-kev' && row.evidenceType === 'known_exploited') {
    merged.knownExploited = true;
    if (!ctx.exploitationSources.includes('cisa-kev')) ctx.exploitationSources.push('cisa-kev');
  }
  if (row.source === 'cisa-vulnrichment' && normalized.ssvc) {
    if (!ctx.exploitationSources.includes('cisa-vulnrichment-ssvc')) {
      ctx.exploitationSources.push('cisa-vulnrichment-ssvc');
    }
  }
}

function applyEpss(
  row: EvidenceRowForMerge,
  normalized: Record<string, unknown>,
  merged: MergedAdvisory,
): void {
  if (row.source !== 'first-epss') return;
  const epss = normalized.epss;
  const percentile = normalized.percentile;
  if (typeof epss === 'number' && typeof percentile === 'number') {
    merged.epss = { probability: epss, percentile };
  }
}

function finalize(merged: MergedAdvisory, ctx: MergeContext): void {
  merged.cwes = [...ctx.cwes.values()];
  merged.exploitationSources = ctx.exploitationSources;
  merged.severity = computeSeverity(merged);
  detectTitleConflict(ctx);
  detectDescriptionConflict(ctx);
  merged.perSource = ctx.perSource;
  merged.conflicts = ctx.conflicts;
}

function computeSeverity(merged: MergedAdvisory): Severity {
  if (merged.cvss?.baseSeverity) {
    const s = String(merged.cvss.baseSeverity).toUpperCase();
    if (s === 'CRITICAL') return 'critical';
    if (s === 'HIGH') return 'high';
    if (s === 'MEDIUM') return 'medium';
    if (s === 'LOW') return 'low';
  }
  if (typeof merged.cvss?.baseScore === 'number') {
    const v = merged.cvss.baseScore;
    if (v >= 9) return 'critical';
    if (v >= 7) return 'high';
    if (v >= 4) return 'medium';
    if (v > 0) return 'low';
  }
  if (merged.knownExploited) return 'high';
  return 'none';
}

function detectTitleConflict(ctx: MergeContext): void {
  if (ctx.titleBySource.size < 2) return;
  const unique = new Set(ctx.titleBySource.values());
  if (unique.size > 1) {
    ctx.conflicts.push({
      field: 'title',
      sources: [...ctx.titleBySource.keys()],
      description: 'Sources disagree on advisory title; using highest-priority source.',
      severity: 'low',
    });
  }
}

function detectDescriptionConflict(ctx: MergeContext): void {
  if (ctx.descriptionBySource.size < 2) return;
  const unique = new Set(ctx.descriptionBySource.values());
  if (unique.size > 1) {
    ctx.conflicts.push({
      field: 'description',
      sources: [...ctx.descriptionBySource.keys()],
      description: 'Sources disagree on advisory description; using highest-priority source.',
      severity: 'low',
    });
  }
}

function extractCvss(normalized: Record<string, unknown>): MergedCvss | undefined {
  const direct = normalized.cvss;
  if (isCvssObject(direct)) return normalizeCvss(direct);
  // Some sources nest CVSS under metric blobs keyed by version, e.g. cvssV3_1.
  const candidate = Object.values(normalized).find((v) =>
    typeof v === 'object' && v !== null && Object.keys(v).some((k) => k.toLowerCase().startsWith('cvssv')),
  );
  if (candidate && typeof candidate === 'object') {
    const inner = Object.values(candidate as Record<string, unknown>).find(isCvssObject);
    if (inner) return normalizeCvss(inner);
  }
  return undefined;
}

function isCvssObject(v: unknown): v is Record<string, unknown> {
  return (
    typeof v === 'object' &&
    v !== null &&
    ('baseScore' in v || 'baseSeverity' in v || 'vectorString' in v)
  );
}

function normalizeCvss(raw: Record<string, unknown>): MergedCvss {
  return {
    baseScore: typeof raw.baseScore === 'number' ? raw.baseScore : undefined,
    baseSeverity: typeof raw.baseSeverity === 'string' ? raw.baseSeverity : undefined,
    vectorString: typeof raw.vectorString === 'string' ? raw.vectorString : undefined,
    source: 'unknown',
  };
}

function safeParse(json: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(json) as unknown;
    return typeof parsed === 'object' && parsed !== null
      ? (parsed as Record<string, unknown>)
      : {};
  } catch {
    return {};
  }
}
