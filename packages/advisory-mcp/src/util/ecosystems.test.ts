import { describe, expect, it } from 'vitest';

import { canonicalEcosystem, isKnownEcosystem } from './ecosystems.js';

describe('canonicalEcosystem', () => {
  it('maps known aliases to canonical names', () => {
    expect(canonicalEcosystem('npm')).toBe('npm');
    expect(canonicalEcosystem('NPMJS')).toBe('npm');
    expect(canonicalEcosystem('PyPI')).toBe('pypi');
    expect(canonicalEcosystem('python')).toBe('pypi');
    expect(canonicalEcosystem('crates.io')).toBe('cargo');
    expect(canonicalEcosystem('rust')).toBe('cargo');
    expect(canonicalEcosystem('golang')).toBe('go');
    expect(canonicalEcosystem('packagist')).toBe('composer');
    expect(canonicalEcosystem('debian')).toBe('deb');
  });

  it('returns undefined for unknown ecosystems', () => {
    expect(canonicalEcosystem('unknown')).toBeUndefined();
  });
});

describe('isKnownEcosystem', () => {
  it('only accepts canonical names', () => {
    expect(isKnownEcosystem('npm')).toBe(true);
    expect(isKnownEcosystem('npmjs')).toBe(false);
    expect(isKnownEcosystem('python')).toBe(false);
  });
});
