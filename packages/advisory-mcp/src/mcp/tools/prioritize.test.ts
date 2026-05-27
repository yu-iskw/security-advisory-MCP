import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { openAdvisoryStore, type AdvisoryStore } from '../../store/store.js';

import { prioritize, PrioritizeInputSchema } from './prioritize.js';

function seed(store: AdvisoryStore): void {
  // Low-risk advisory: no KEV, no EPSS
  store.advisories.upsert({
    id: 'CVE-2023-1111',
    canonicalId: 'CVE-2023-1111',
    type: 'cve',
    mergedJson: '{}',
  });
  store.evidence.upsert({
    id: 'cve:CVE-2023-1111',
    advisoryId: 'CVE-2023-1111',
    source: 'cveproject',
    type: 'cve_record',
    fetchedAt: '2026-05-27T00:00:00.000Z',
    confidence: 0.95,
    trustTier: 'A',
    summary: 'minor bug',
    normalizedJson: '{}',
  });

  // High-risk advisory: KEV + EPSS high
  store.advisories.upsert({
    id: 'CVE-2021-44228',
    canonicalId: 'CVE-2021-44228',
    type: 'cve',
    mergedJson: '{}',
  });
  store.evidence.upsert({
    id: 'kev:CVE-2021-44228',
    advisoryId: 'CVE-2021-44228',
    source: 'cisa-kev',
    type: 'known_exploited',
    fetchedAt: '2026-05-27T00:00:00.000Z',
    confidence: 0.95,
    trustTier: 'A',
    summary: 'KEV',
    normalizedJson: '{}',
  });
  store.evidence.upsert({
    id: 'epss:CVE-2021-44228',
    advisoryId: 'CVE-2021-44228',
    source: 'first-epss',
    type: 'epss_score',
    fetchedAt: '2026-05-27T00:00:00.000Z',
    confidence: 0.9,
    trustTier: 'A',
    summary: 'EPSS',
    normalizedJson: JSON.stringify({ epss: 0.975, percentile: 0.999 }),
  });
}

describe('prioritize', () => {
  let store: AdvisoryStore;

  beforeEach(() => {
    store = openAdvisoryStore({ path: ':memory:', noWal: true });
    seed(store);
  });

  afterEach(() => {
    store.close();
  });

  it('rejects empty input', () => {
    expect(() => PrioritizeInputSchema.parse({ profile: 'default' })).toThrow();
  });

  it('ranks the KEV+EPSS advisory above the bare one', () => {
    const r = prioritize(store, {
      advisoryIds: ['CVE-2023-1111', 'CVE-2021-44228'],
      profile: 'internet_exposed',
    });
    expect(r.ranked).toHaveLength(2);
    expect(r.ranked[0]?.advisoryId).toBe('CVE-2021-44228');
    expect(r.ranked[0]?.knownExploited).toBe(true);
    expect(r.ranked[0]?.score).toBeGreaterThan(r.ranked[1]?.score ?? 0);
  });

  it('deduplicates ids that appear in both advisoryIds and packages', () => {
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
    const r = prioritize(store, {
      advisoryIds: ['CVE-2021-44228'],
      packages: [
        { ecosystem: 'maven', name: 'org.apache.logging.log4j:log4j-core', version: '2.14.0' },
      ],
      profile: 'application_dependency',
    });
    expect(r.ranked.filter((item) => item.advisoryId === 'CVE-2021-44228')).toHaveLength(1);
  });

  it('returns a no-results markdown when nothing matches', () => {
    const r = prioritize(store, {
      advisoryIds: ['CVE-9999-9999'],
      profile: 'default',
    });
    expect(r.markdown).toMatch(/No matching advisories/);
  });
});
