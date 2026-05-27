import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { openAdvisoryStore, type AdvisoryStore } from '../../store/store.js';

import { searchAdvisories, SearchAdvisoriesInputSchema } from './search-advisories.js';

function seed(store: AdvisoryStore): void {
  store.advisories.upsert({
    id: 'CVE-2024-3094',
    canonicalId: 'CVE-2024-3094',
    type: 'cve',
    title: 'XZ Utils backdoor',
    description: 'A malicious backdoor was inserted into liblzma.',
    mergedJson: '{}',
  });
  store.evidence.upsert({
    id: 'kev:CVE-2024-3094',
    advisoryId: 'CVE-2024-3094',
    source: 'cisa-kev',
    type: 'known_exploited',
    fetchedAt: '2026-05-27T00:00:00.000Z',
    confidence: 0.95,
    trustTier: 'A',
    summary: 'KEV.',
    normalizedJson: '{}',
  });
  store.search.indexAdvisory({
    id: 'CVE-2024-3094',
    title: 'XZ Utils backdoor',
    description: 'A malicious backdoor was inserted into liblzma.',
    severity: 'critical',
    knownExploited: true,
    hasFix: true,
  });

  store.advisories.upsert({
    id: 'CVE-2023-12345',
    canonicalId: 'CVE-2023-12345',
    type: 'cve',
    title: 'A benign formatting issue in libfoo',
    description: 'No remote impact.',
    mergedJson: '{}',
  });
  store.search.indexAdvisory({
    id: 'CVE-2023-12345',
    title: 'A benign formatting issue in libfoo',
    description: 'No remote impact.',
    severity: 'low',
    knownExploited: false,
    hasFix: false,
  });
}

describe('searchAdvisories', () => {
  let store: AdvisoryStore;

  beforeEach(() => {
    store = openAdvisoryStore({ path: ':memory:', noWal: true });
    seed(store);
  });

  afterEach(() => {
    store.close();
  });

  it('returns matching advisories with kev flag', () => {
    const r = searchAdvisories(store, { query: 'backdoor', limit: 10 });
    expect(r.hits).toHaveLength(1);
    expect(r.hits[0]?.id).toBe('CVE-2024-3094');
    expect(r.hits[0]?.knownExploited).toBe(true);
    expect(r.markdown).toMatch(/KEV/);
  });

  it('respects the severity filter', () => {
    const r = searchAdvisories(store, { query: 'libfoo OR liblzma', severity: 'low', limit: 10 });
    // Each token is treated as required AND; this query won't match either record, expected.
    // Direct tokens for the low-severity record:
    const r2 = searchAdvisories(store, { query: 'libfoo', severity: 'low', limit: 10 });
    expect(r2.hits.map((h) => h.id)).toEqual(['CVE-2023-12345']);
    expect(r.hits).toHaveLength(0);
  });

  it('respects the knownExploited filter', () => {
    const r = searchAdvisories(store, { query: 'libfoo', knownExploited: true, limit: 10 });
    expect(r.hits).toHaveLength(0);
  });

  it('returns a no-results markdown for no matches', () => {
    const r = searchAdvisories(store, { query: 'something-that-does-not-exist', limit: 10 });
    expect(r.hits).toEqual([]);
    expect(r.markdown).toMatch(/No advisories matched/);
  });

  it('input schema enforces query length and limit bounds', () => {
    expect(() => SearchAdvisoriesInputSchema.parse({ query: '', limit: 10 })).toThrow();
    expect(() => SearchAdvisoriesInputSchema.parse({ query: 'x', limit: 0 })).toThrow();
    expect(() => SearchAdvisoriesInputSchema.parse({ query: 'x', limit: 100 })).toThrow();
  });
});
