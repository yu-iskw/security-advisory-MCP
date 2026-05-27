import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { openAdvisoryStore, type AdvisoryStore } from '../../store/store.js';

import { analyzePackage, AnalyzePackageInputSchema } from './analyze-package.js';

function seed(store: AdvisoryStore): void {
  store.advisories.upsert({
    id: 'CVE-2021-44228',
    canonicalId: 'CVE-2021-44228',
    type: 'cve',
    title: 'Log4Shell',
    mergedJson: '{}',
  });
  store.affectedPackages.replaceForAdvisory('CVE-2021-44228', [
    {
      advisoryId: 'CVE-2021-44228',
      ecosystem: 'maven',
      name: 'org.apache.logging.log4j:log4j-core',
      vulnerableRange: '>=2.0',
      fixedVersion: '2.17.0',
      source: 'osv',
      confidence: 0.85,
    },
  ]);

  store.advisories.upsert({
    id: 'MAL-2024-0001',
    canonicalId: 'MAL-2024-0001',
    type: 'malicious_package',
    title: 'foo-typosquat',
    mergedJson: '{}',
  });
  store.affectedPackages.replaceForAdvisory('MAL-2024-0001', [
    {
      advisoryId: 'MAL-2024-0001',
      ecosystem: 'npm',
      name: 'foo-typosquat',
      source: 'ossf-malicious-packages',
      confidence: 0.9,
    },
  ]);
}

describe('analyzePackage', () => {
  let store: AdvisoryStore;

  beforeEach(() => {
    store = openAdvisoryStore({ path: ':memory:', noWal: true });
    seed(store);
  });

  afterEach(() => {
    store.close();
  });

  it('rejects input that has neither purl nor ecosystem+name', () => {
    expect(() => AnalyzePackageInputSchema.parse({})).toThrow();
  });

  it('finds an affected vulnerable version', () => {
    const r = analyzePackage(store, {
      ecosystem: 'maven',
      name: 'org.apache.logging.log4j:log4j-core',
      version: '2.14.0',
      profile: 'application_dependency',
    });
    expect(r.matches).toHaveLength(1);
    expect(r.matches[0]?.advisoryId).toBe('CVE-2021-44228');
    expect(r.matches[0]?.affected).toBe(true);
  });

  it('treats versions >= fixed as not affected', () => {
    const r = analyzePackage(store, {
      ecosystem: 'maven',
      name: 'org.apache.logging.log4j:log4j-core',
      version: '2.17.0',
      profile: 'application_dependency',
    });
    expect(r.matches).toEqual([]);
  });

  it('flags malicious package matches regardless of version', () => {
    const r = analyzePackage(store, {
      ecosystem: 'npm',
      name: 'foo-typosquat',
      version: '0.0.1',
      profile: 'application_dependency',
    });
    expect(r.malicious).toBe(true);
    expect(r.matches[0]?.evidenceType).toBe('malicious_package');
    expect(r.markdown).toMatch(/Malicious package match/);
  });

  it('accepts a PURL and routes through to the lookup', () => {
    const r = analyzePackage(store, {
      purl: 'pkg:npm/foo-typosquat@0.0.1',
      profile: 'application_dependency',
    });
    expect(r.malicious).toBe(true);
  });

  it('returns no matches for an unknown package', () => {
    const r = analyzePackage(store, {
      ecosystem: 'npm',
      name: 'no-such-package',
      version: '1.0.0',
      profile: 'application_dependency',
    });
    expect(r.matches).toEqual([]);
    expect(r.malicious).toBe(false);
  });
});
