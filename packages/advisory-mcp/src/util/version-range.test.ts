import { describe, expect, it } from 'vitest';

import { compareVersion, inRange, looseSemverCompare } from './version-range.js';

describe('looseSemverCompare', () => {
  it('compares numeric parts numerically, not lexically', () => {
    expect(looseSemverCompare('1.10.0', '1.9.0')).toBeGreaterThan(0);
    expect(looseSemverCompare('1.2.3', '1.2.3')).toBe(0);
    expect(looseSemverCompare('2.0.0', '1.99.99')).toBeGreaterThan(0);
  });

  it('treats pre-releases as lower than the released version', () => {
    expect(looseSemverCompare('1.0.0-rc.1', '1.0.0')).toBeLessThan(0);
    expect(looseSemverCompare('1.0.0', '1.0.0-rc.1')).toBeGreaterThan(0);
    expect(looseSemverCompare('1.0.0-alpha', '1.0.0-beta')).toBeLessThan(0);
  });

  it('handles fewer parts by padding with zeros', () => {
    expect(looseSemverCompare('1', '1.0.0')).toBe(0);
    expect(looseSemverCompare('1.1', '1.0.99')).toBeGreaterThan(0);
  });
});

describe('inRange', () => {
  it('matches OSV {introduced, fixed} ranges', () => {
    const range = { events: [{ introduced: '1.0.0' }, { fixed: '2.0.0' }] };
    expect(inRange('npm', '1.5.0', range)).toBe(true);
    expect(inRange('npm', '2.0.0', range)).toBe(false);
    expect(inRange('npm', '0.9.0', range)).toBe(false);
  });

  it('matches lastAffected (inclusive upper bound)', () => {
    const range = { events: [{ introduced: '1.0.0' }, { lastAffected: '1.2.3' }] };
    expect(inRange('npm', '1.2.3', range)).toBe(true);
    expect(inRange('npm', '1.2.4', range)).toBe(false);
  });

  it('uses introduced=0 as "from the beginning"', () => {
    const range = { events: [{ introduced: '0' }, { fixed: '2.0.0' }] };
    expect(inRange('npm', '0.0.1', range)).toBe(true);
    expect(inRange('npm', '2.0.0', range)).toBe(false);
  });
});

describe('compareVersion', () => {
  it('delegates to looseSemverCompare for unspecified ecosystems', () => {
    expect(compareVersion('cargo', '1.0.0', '0.9.0')).toBeGreaterThan(0);
  });
});
