import type { Advisory } from '../schemas/advisory.js';

const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/i;
const GHSA_PATTERN = /^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/i;
const OSV_PATTERN = /^(GO|PYSEC|RUSTSEC|GHSA|CVE)-/i;

export type AdvisoryIdKind = 'cve' | 'ghsa' | 'osv' | 'unknown';

export function classifyAdvisoryId(id: string): AdvisoryIdKind {
  const normalized = id.trim().toUpperCase();
  if (CVE_PATTERN.test(normalized)) {
    return 'cve';
  }
  if (GHSA_PATTERN.test(id.trim())) {
    return 'ghsa';
  }
  if (OSV_PATTERN.test(id.trim())) {
    return 'osv';
  }
  return 'unknown';
}

export function normalizeAdvisoryId(id: string): string {
  const trimmed = id.trim();
  if (classifyAdvisoryId(trimmed) === 'cve') {
    return trimmed.toUpperCase();
  }
  return trimmed;
}

export function selectCanonicalId(ids: string[]): string {
  const cve = ids.find((i) => classifyAdvisoryId(i) === 'cve');
  if (cve) {
    return normalizeAdvisoryId(cve);
  }
  const ghsa = ids.find((i) => classifyAdvisoryId(i) === 'ghsa');
  if (ghsa) {
    return ghsa;
  }
  const osv = ids.find((i) => classifyAdvisoryId(i) === 'osv');
  if (osv) {
    return osv;
  }
  return ids[0] ?? 'UNKNOWN';
}

export function inferAdvisoryType(
  canonicalId: string,
  hints: { explicitType?: Advisory['type']; isMaliciousPackage?: boolean },
): Advisory['type'] {
  if (hints.isMaliciousPackage || hints.explicitType === 'malicious-package') {
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
