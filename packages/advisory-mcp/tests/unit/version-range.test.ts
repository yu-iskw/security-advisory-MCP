import { describe, expect, it } from 'vitest';

import {
  compareVersions,
  isPackageVersionVulnerable,
  versionMatchesVulnerableRanges,
} from '../../src/util/version-range.js';

describe('version-range', () => {
  it('compares semver-like versions', () => {
    expect(compareVersions('2.16.0', '2.15.4')).toBe(1);
    expect(compareVersions('2.15.0', '2.15.4')).toBe(-1);
    expect(compareVersions('2.15.4', '2.15.4')).toBe(0);
  });

  it('treats version at or above fix as not vulnerable', () => {
    expect(versionMatchesVulnerableRanges('2.16.0', ['<2.15.4'], ['2.15.0'])).toBe(
      'not_vulnerable',
    );
  });

  it('treats version below range bound as vulnerable', () => {
    expect(versionMatchesVulnerableRanges('2.14.0', ['<2.15.4'], ['2.15.0'])).toBe('vulnerable');
  });

  it('matches compound ranges', () => {
    expect(versionMatchesVulnerableRanges('1.5.0', ['>=1.0.0,<2.0.0'], [])).toBe('vulnerable');
    expect(versionMatchesVulnerableRanges('2.5.0', ['>=1.0.0,<2.0.0'], [])).toBe('not_vulnerable');
  });

  it('isPackageVersionVulnerable respects fixes for pinned versions', () => {
    expect(isPackageVersionVulnerable('2.16.0', ['<2.15.4'], ['2.15.0'])).toBe(false);
    expect(isPackageVersionVulnerable('2.14.0', ['<2.15.4'], ['2.15.0'])).toBe(true);
  });
});
