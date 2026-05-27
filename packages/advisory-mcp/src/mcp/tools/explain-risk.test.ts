import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { openAdvisoryStore, type AdvisoryStore } from '../../store/store.js';

import { explainRisk } from './explain-risk.js';

function seed(store: AdvisoryStore): void {
  store.advisories.upsert({
    id: 'CVE-2024-3094',
    canonicalId: 'CVE-2024-3094',
    type: 'cve',
    title: 'XZ',
    publishedAt: new Date(Date.now() - 86_400_000).toISOString(),
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
    summary: 'KEV',
    normalizedJson: '{}',
  });
  store.evidence.upsert({
    id: 'epss:CVE-2024-3094',
    advisoryId: 'CVE-2024-3094',
    source: 'first-epss',
    type: 'epss_score',
    fetchedAt: '2026-05-27T00:00:00.000Z',
    confidence: 0.9,
    trustTier: 'A',
    summary: 'EPSS',
    normalizedJson: JSON.stringify({ epss: 0.91, percentile: 0.998 }),
  });
}

describe('explainRisk', () => {
  let store: AdvisoryStore;

  beforeEach(() => {
    store = openAdvisoryStore({ path: ':memory:', noWal: true });
  });

  afterEach(() => {
    store.close();
  });

  it('returns found=false for an unknown id', () => {
    const r = explainRisk(store, { id: 'CVE-9999-9999', profile: 'default' });
    expect(r.found).toBe(false);
  });

  it('computes a non-zero risk with KEV + EPSS evidence', () => {
    seed(store);
    const r = explainRisk(store, { id: 'CVE-2024-3094', profile: 'default' });
    expect(r.found).toBe(true);
    expect(r.risk?.score).toBeGreaterThan(0);
    expect(r.risk?.drivers.some((d) => d.kind === 'known_exploited')).toBe(true);
    expect(r.risk?.drivers.some((d) => d.kind === 'epss')).toBe(true);
    expect(r.markdown).toMatch(/Risk explanation/);
  });

  it('respects the internet_exposed profile bias', () => {
    seed(store);
    const a = explainRisk(store, { id: 'CVE-2024-3094', profile: 'default' });
    const b = explainRisk(store, { id: 'CVE-2024-3094', profile: 'internet_exposed' });
    expect(b.risk?.score ?? 0).toBeGreaterThan(a.risk?.score ?? 0);
  });
});
