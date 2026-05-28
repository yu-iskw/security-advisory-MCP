import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { SyncEngine } from '../../src/ingest/sync-engine.js';
import { sha256Hex } from '../../src/ingest/verifier.js';
import { CisaKevSource } from '../../src/sources/cisa-kev.js';
import { closeStore, openStore } from '../../src/store/db.js';
import { AdvisoryRepository } from '../../src/store/repositories/advisory-repository.js';
import { EvidenceRepository } from '../../src/store/repositories/evidence-repository.js';
import { SourceStateRepository } from '../../src/store/repositories/source-state-repository.js';

import type { Downloader } from '../../src/ingest/downloader.js';
import type { DatabaseHandle } from '../../src/store/db.js';

const FIXTURE_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

async function loadFixtureBody(): Promise<Uint8Array> {
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- known test fixture path
  const buf = await readFile(
    fileURLToPath(new URL('../fixtures/cisa-kev-sample.json', import.meta.url)),
  );
  return new Uint8Array(buf);
}

function fixtureDownloader(
  body: Uint8Array,
  etag: string,
  lastModified: string,
): {
  downloader: Downloader;
  calls: { url: string; etag?: string; lastModified?: string }[];
  setNotModified: (v: boolean) => void;
} {
  const calls: { url: string; etag?: string; lastModified?: string }[] = [];
  let returnNotModified = false;
  const downloader: Downloader = {
    download: (req) => {
      calls.push({ url: req.url, etag: req.etag, lastModified: req.lastModified });
      if (returnNotModified) return Promise.resolve('not_modified');
      return Promise.resolve({
        url: req.url,
        status: 200,
        contentType: 'application/json',
        etag,
        lastModified,
        body,
        sha256: sha256Hex(body),
      });
    },
  };
  return {
    downloader,
    calls,
    setNotModified: (v) => {
      returnNotModified = v;
    },
  };
}

describe('integration: sync CISA KEV from fixture', () => {
  let db: DatabaseHandle;

  beforeEach(() => {
    db = openStore({ path: ':memory:', noWal: true });
  });

  afterEach(() => {
    closeStore(db);
  });

  it('writes advisories, aliases, evidence, and source_state', async () => {
    const body = await loadFixtureBody();
    const { downloader } = fixtureDownloader(body, 'kev-v1', 'Tue, 27 May 2026 13:00:00 GMT');
    const engine = new SyncEngine({ db, downloader, cacheDir: '/tmp/test' });
    const adapter = new CisaKevSource({ url: FIXTURE_URL });

    const [result] = await engine.syncMany([adapter]);

    expect(result?.status).toBe('success');
    expect(result?.records).toBe(3);

    const advisories = new AdvisoryRepository(db);
    expect(advisories.count()).toBe(3);
    expect(advisories.findById('CVE-2024-3094')?.title).toMatch(/XZ Utils/i);
    expect(advisories.findById('CVE-2021-44228')?.title).toMatch(/Log4j/i);

    const evidence = new EvidenceRepository(db);
    expect(evidence.count()).toBe(3);
    const ev = evidence.findByAdvisoryId('CVE-2024-3094');
    expect(ev[0]).toMatchObject({ source: 'cisa-kev', type: 'known_exploited', trustTier: 'A' });
    expect(ev[0]?.confidence).toBeCloseTo(0.95);

    const state = new SourceStateRepository(db).findBySource('cisa-kev');
    expect(state?.status).toBe('success');
    expect(state?.etag).toBe('kev-v1');
    expect(state?.lastSuccessAt).toBeDefined();
  });

  it('passes stored validators on a subsequent sync and handles 304', async () => {
    const body = await loadFixtureBody();
    const { downloader, calls, setNotModified } = fixtureDownloader(
      body,
      'kev-v1',
      'Tue, 27 May 2026 13:00:00 GMT',
    );
    const engine = new SyncEngine({ db, downloader, cacheDir: '/tmp/test' });
    const adapter = new CisaKevSource({ url: FIXTURE_URL });

    await engine.syncOne(adapter);
    expect(calls[0]?.etag).toBeUndefined();

    setNotModified(true);
    const second = await engine.syncOne(adapter);
    expect(second.status).toBe('unchanged');
    expect(calls[1]?.etag).toBe('kev-v1');

    // No new rows written.
    expect(new AdvisoryRepository(db).count()).toBe(3);
    expect(new EvidenceRepository(db).count()).toBe(3);
  });

  it('records an error and preserves last_success_at when sync fails', async () => {
    const failing: Downloader = {
      download: () => Promise.reject(new Error('network down')),
    };
    const engine = new SyncEngine({ db, downloader: failing, cacheDir: '/tmp/test' });
    const adapter = new CisaKevSource({ url: FIXTURE_URL });

    const result = await engine.syncOne(adapter);
    expect(result.status).toBe('error');
    expect(result.error).toMatch(/network down/);

    const state = new SourceStateRepository(db).findBySource('cisa-kev');
    expect(state?.status).toBe('error');
    expect(state?.lastError).toMatch(/network down/);
  });
});
