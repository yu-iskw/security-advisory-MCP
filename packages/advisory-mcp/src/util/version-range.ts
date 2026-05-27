/**
 * Pure version/range helpers for affected-package matching (no I/O).
 */

export type VersionMatchResult = 'vulnerable' | 'not_vulnerable' | 'unknown';

interface ParsedVersion {
  core: number[];
  prerelease: string | null;
}

function parseVersion(version: string): ParsedVersion | null {
  let trimmed = version.trim();
  if (trimmed.startsWith('v') || trimmed.startsWith('V')) {
    trimmed = trimmed.slice(1);
  }
  const dashIndex = trimmed.indexOf('-');
  const corePart = dashIndex === -1 ? trimmed : trimmed.slice(0, dashIndex);
  const prerelease = dashIndex === -1 ? null : trimmed.slice(dashIndex + 1);
  if (corePart.length === 0) {
    return null;
  }
  const coreSegments = corePart.split('.');
  const core: number[] = [];
  for (const segment of coreSegments) {
    if (segment.length === 0 || !/^[0-9]+$/.test(segment)) {
      return null;
    }
    core.push(Number.parseInt(segment, 10));
  }
  if (core.some((n) => Number.isNaN(n))) {
    return null;
  }
  return { core, prerelease: prerelease !== null && prerelease.length > 0 ? prerelease : null };
}

function corePartAt(parts: number[], index: number): number {
  if (index >= parts.length) {
    return 0;
  }
  return parts.at(index) ?? 0;
}

/** @returns negative if a < b, positive if a > b, 0 if equal; null if unparsable */
export function compareVersions(a: string, b: string): number | null {
  const left = parseVersion(a);
  const right = parseVersion(b);
  if (!left || !right) {
    return null;
  }
  const maxLen = Math.max(left.core.length, right.core.length);
  for (let i = 0; i < maxLen; i += 1) {
    const lv = corePartAt(left.core, i);
    const rv = corePartAt(right.core, i);
    if (lv !== rv) {
      return lv < rv ? -1 : 1;
    }
  }
  if (!left.prerelease && !right.prerelease) {
    return 0;
  }
  if (!left.prerelease && right.prerelease) {
    return 1;
  }
  if (left.prerelease && !right.prerelease) {
    return -1;
  }
  return left.prerelease!.localeCompare(right.prerelease!);
}

function parseConstraint(trimmed: string): { op: string; bound: string } | null {
  if (trimmed.startsWith('<=')) {
    return { op: '<=', bound: trimmed.slice(2).trim() };
  }
  if (trimmed.startsWith('>=')) {
    return { op: '>=', bound: trimmed.slice(2).trim() };
  }
  if (trimmed.startsWith('<')) {
    return { op: '<', bound: trimmed.slice(1).trim() };
  }
  if (trimmed.startsWith('>')) {
    return { op: '>', bound: trimmed.slice(1).trim() };
  }
  if (trimmed.startsWith('=')) {
    return { op: '=', bound: trimmed.slice(1).trim() };
  }
  if (trimmed.length > 0) {
    return { op: '=', bound: trimmed };
  }
  return null;
}

function versionSatisfiesSingleConstraint(version: string, constraint: string): boolean | null {
  const trimmed = constraint.trim();
  if (trimmed === '*') {
    return true;
  }
  if (trimmed === '') {
    return null;
  }
  const parsed = parseConstraint(trimmed);
  if (!parsed || parsed.bound.length === 0) {
    return null;
  }
  const cmp = compareVersions(version, parsed.bound);
  if (cmp === null) {
    return null;
  }
  switch (parsed.op) {
    case '<':
      return cmp < 0;
    case '<=':
      return cmp <= 0;
    case '>':
      return cmp > 0;
    case '>=':
      return cmp >= 0;
    case '=':
      return cmp === 0;
    default:
      return null;
  }
}

function versionSatisfiesRangeSpec(version: string, rangeSpec: string): boolean | null {
  const parts = rangeSpec
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
  if (parts.length === 0) {
    return null;
  }
  for (const part of parts) {
    const ok = versionSatisfiesSingleConstraint(version, part);
    if (ok === null) {
      return null;
    }
    if (!ok) {
      return false;
    }
  }
  return true;
}

function isAtOrAboveAnyFix(version: string, fixedVersions: string[]): boolean {
  for (const fix of fixedVersions) {
    const cmp = compareVersions(version, fix);
    if (cmp !== null && cmp >= 0) {
      return true;
    }
  }
  return false;
}

export function versionMatchesVulnerableRanges(
  version: string,
  vulnerableRanges: string[],
  fixedVersions: string[],
): VersionMatchResult {
  if (isAtOrAboveAnyFix(version, fixedVersions)) {
    return 'not_vulnerable';
  }
  if (vulnerableRanges.length === 0) {
    return 'unknown';
  }
  let sawUnknown = false;
  for (const range of vulnerableRanges) {
    if (range === '*') {
      return 'vulnerable';
    }
    const match = versionSatisfiesRangeSpec(version, range);
    if (match === true) {
      return 'vulnerable';
    }
    if (match === null) {
      sawUnknown = true;
    }
  }
  if (sawUnknown) {
    return 'unknown';
  }
  return 'not_vulnerable';
}

export function isPackageVersionVulnerable(
  version: string | undefined,
  vulnerableRanges: string[],
  fixedVersions: string[],
): boolean {
  if (!version) {
    if (vulnerableRanges.length === 0) {
      return true;
    }
    return vulnerableRanges.some((r) => r === '*' || r.length > 0);
  }
  const result = versionMatchesVulnerableRanges(version, vulnerableRanges, fixedVersions);
  return result === 'vulnerable';
}
