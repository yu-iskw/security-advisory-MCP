import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { closeStore, openStore, type DatabaseHandle } from '../db.js';

import { SourceStateRepository } from './source-state-repository.js';

describe('SourceStateRepository', () => {
  let db: DatabaseHandle;
  let repo: SourceStateRepository;

  beforeEach(() => {
    db = openStore({ path: ':memory:', noWal: true });
    repo = new SourceStateRepository(db);
  });

  afterEach(() => {
    closeStore(db);
  });

  it('round-trips status, enabled flag, and timestamps', () => {
    repo.upsert({
      source: 'cisa-kev',
      enabled: true,
      preset: 'core',
      status: 'success',
      lastSyncStartedAt: '2026-05-27T00:00:00Z',
      lastSyncCompletedAt: '2026-05-27T00:00:05Z',
      lastSuccessAt: '2026-05-27T00:00:05Z',
      etag: 'abc123',
    });
    const row = repo.findBySource('cisa-kev');
    expect(row).toMatchObject({
      source: 'cisa-kev',
      enabled: true,
      preset: 'core',
      status: 'success',
      etag: 'abc123',
    });
  });

  it('preserves earlier success timestamps when a later upsert omits them', () => {
    repo.upsert({
      source: 'cisa-kev',
      enabled: true,
      preset: 'core',
      status: 'success',
      lastSuccessAt: '2026-05-27T00:00:00Z',
      etag: 'v1',
    });
    repo.upsert({
      source: 'cisa-kev',
      enabled: true,
      preset: 'core',
      status: 'error',
      lastError: 'connection timeout',
    });
    const row = repo.findBySource('cisa-kev');
    expect(row?.lastSuccessAt).toBe('2026-05-27T00:00:00Z');
    expect(row?.etag).toBe('v1');
    expect(row?.status).toBe('error');
    expect(row?.lastError).toBe('connection timeout');
  });

  it('listAll returns sources in stable order', () => {
    repo.upsert({ source: 'first-epss', enabled: true, preset: 'core', status: 'never_synced' });
    repo.upsert({ source: 'cisa-kev', enabled: true, preset: 'core', status: 'success' });
    expect(repo.listAll().map((r) => r.source)).toEqual(['cisa-kev', 'first-epss']);
  });
});
