/**
 * Per-ecosystem version comparison + range matching.
 *
 * v1 supports the OSV-style range vocabulary:
 *   { introduced?, fixed?, last_affected?, limit? }
 *
 * Comparison defaults to semver-flavored for npm / cargo / pypi (sufficient
 * for the bulk of OSV/GHSA data). Other ecosystems (debian, alpine, maven)
 * arrive with their own adapters and can plug in via `compareVersion`.
 */

type Ecosystem = string;

interface OsvRangeEvent {
  introduced?: string;
  fixed?: string;
  lastAffected?: string;
  limit?: string;
}

interface OsvAffectedRange {
  events: ReadonlyArray<OsvRangeEvent>;
}

export function compareVersion(ecosystem: Ecosystem, a: string, b: string): number {
  // Ecosystem-specific comparators can plug in here. For now we use one
  // general semver-ish comparator that handles the common cases.
  return looseSemverCompare(a, b);
}

export function inRange(ecosystem: Ecosystem, version: string, range: OsvAffectedRange): boolean {
  let affected = false;
  for (const ev of range.events) {
    if (ev.introduced) {
      const target = ev.introduced === '0' ? null : ev.introduced;
      if (target === null || compareVersion(ecosystem, version, target) >= 0) {
        affected = true;
      }
    }
    if (ev.fixed && compareVersion(ecosystem, version, ev.fixed) >= 0) {
      affected = false;
    }
    if (ev.lastAffected && compareVersion(ecosystem, version, ev.lastAffected) > 0) {
      affected = false;
    }
  }
  return affected;
}

/**
 * Compare two version-like strings. Splits on '.', then on a leading numeric
 * run within each part; numeric runs are compared numerically, the remainder
 * lexically. Pre-release suffixes (after '-') compare as lower than no-suffix.
 *
 * Returns <0 if a<b, 0 if equal, >0 if a>b.
 */
export function looseSemverCompare(a: string, b: string): number {
  const [aCore, aPre] = splitPre(a);
  const [bCore, bPre] = splitPre(b);
  const coreCmp = compareCore(aCore, bCore);
  if (coreCmp !== 0) return coreCmp;
  // Same core: any pre-release is "less than" no pre-release.
  if (aPre === '' && bPre === '') return 0;
  if (aPre === '') return 1;
  if (bPre === '') return -1;
  return aPre < bPre ? -1 : aPre > bPre ? 1 : 0;
}

function splitPre(v: string): [string, string] {
  const idx = v.indexOf('-');
  if (idx < 0) return [v, ''];
  return [v.slice(0, idx), v.slice(idx + 1)];
}

function compareCore(a: string, b: string): number {
  const ap = a.split('.');
  const bp = b.split('.');
  const len = Math.max(ap.length, bp.length);
  for (let i = 0; i < len; i++) {
    // i is a bounded counter against ap.length/bp.length; safe.
    /* eslint-disable security/detect-object-injection */
    const ai = i < ap.length ? (ap[i] ?? '') : '0';
    const bi = i < bp.length ? (bp[i] ?? '') : '0';
    /* eslint-enable security/detect-object-injection */
    const cmp = comparePart(ai, bi);
    if (cmp !== 0) return cmp;
  }
  return 0;
}

function comparePart(a: string, b: string): number {
  const an = Number.parseInt(a, 10);
  const bn = Number.parseInt(b, 10);
  const aIsNum = !Number.isNaN(an);
  const bIsNum = !Number.isNaN(bn);
  if (aIsNum && bIsNum) return an - bn;
  if (aIsNum) return -1;
  if (bIsNum) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}
