import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { openAdvisoryStore, type AdvisoryStore } from '../../store/store.js';

import { sourceStatus } from './source-status.js';

describe('sourceStatus', () => {
  let store: AdvisoryStore;

  beforeEach(() => {
    store = openAdvisoryStore({ path: ':memory:', noWal: true });
  });

  afterEach(() => {
    store.close();
  });

  it('returns an empty list before any sync', () => {
    const r = sourceStatus(store, {});
    expect(r.sources).toEqual([]);
    expect(r.markdown).toMatch(/No source state recorded/);
  });

  it('marks a fresh success as not stale', () => {
    store.sourceState.upsert({
      source: 'cisa-kev',
      enabled: true,
      preset: 'core',
      status: 'success',
      lastSuccessAt: new Date(Date.now() - 60_000).toISOString(),
    });
    const r = sourceStatus(store, { staleAfterHours: 24 });
    expect(r.sources).toHaveLength(1);
    expect(r.sources[0]?.stale).toBe(false);
  });

  it('marks an old success as stale', () => {
    store.sourceState.upsert({
      source: 'cisa-kev',
      enabled: true,
      preset: 'core',
      status: 'success',
      lastSuccessAt: new Date(Date.now() - 200 * 3_600_000).toISOString(),
    });
    const r = sourceStatus(store, { staleAfterHours: 24 });
    expect(r.sources[0]?.stale).toBe(true);
    expect(r.markdown).toMatch(/stale/);
  });

  it('filters by source when provided', () => {
    store.sourceState.upsert({ source: 'cisa-kev', enabled: true, preset: 'core', status: 'success', lastSuccessAt: new Date().toISOString() });
    store.sourceState.upsert({ source: 'first-epss', enabled: true, preset: 'core', status: 'never_synced' });
    const r = sourceStatus(store, { source: 'first-epss' });
    expect(r.sources.map((s) => s.source)).toEqual(['first-epss']);
  });

  it('treats never-synced sources as stale', () => {
    store.sourceState.upsert({ source: 'first-epss', enabled: true, preset: 'core', status: 'never_synced' });
    const r = sourceStatus(store, {});
    expect(r.sources[0]?.stale).toBe(true);
    expect(r.sources[0]?.ageHours).toBeNull();
  });
});
