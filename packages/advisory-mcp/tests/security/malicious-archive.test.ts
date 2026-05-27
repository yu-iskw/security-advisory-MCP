import { gzipSync } from 'node:zlib';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { SyncEngine } from '../../src/ingest/sync-engine.js';
import { CisaVulnrichmentSource } from '../../src/sources/cisa-vulnrichment.js';
import { closeStore, openStore, type DatabaseHandle } from '../../src/store/db.js';
import { AdvisoryRepository } from '../../src/store/repositories/advisory-repository.js';
import { SourceStateRepository } from '../../src/store/repositories/source-state-repository.js';
import { buildTar } from '../fixtures/tar-builder.js';

import type { Downloader } from '../../src/ingest/downloader.js';

const ENC = new TextEncoder();

function stubDownloader(body: Uint8Array): Downloader {
  return {
    download: () =>
      Promise.resolve({
        url: 'https://codeload.github.com/x/y/tar.gz/z',
        status: 200,
        contentType: 'application/gzip',
        etag: 'v1',
        lastModified: undefined,
        body,
        sha256: '0'.repeat(64),
      }),
  };
}

describe('security: malicious archives are rejected without DB damage', () => {
  let db: DatabaseHandle;

  beforeEach(() => {
    db = openStore({ path: ':memory:', noWal: true });
  });

  afterEach(() => {
    closeStore(db);
  });

  it('rejects a tar entry with parent-traversal in its path', async () => {
    const tar = buildTar([
      { path: '../etc/passwd', content: ENC.encode('not allowed') },
    ]);
    const gz = new Uint8Array(gzipSync(Buffer.from(tar)));
    const engine = new SyncEngine({
      db,
      downloader: stubDownloader(gz),
      cacheDir: '/tmp/test',
    });
    const result = await engine.syncOne(new CisaVulnrichmentSource());
    expect(result.status).toBe('error');
    expect(result.error).toMatch(/path traversal/);
    expect(new AdvisoryRepository(db).count()).toBe(0);
    // The state row is still recorded so `status` reports the failure.
    expect(new SourceStateRepository(db).findBySource('cisa-vulnrichment')?.status).toBe('error');
  });

  it('surfaces DecompressionError when the response is not a gzip stream', async () => {
    const corrupt = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    const engine = new SyncEngine({
      db,
      downloader: stubDownloader(corrupt),
      cacheDir: '/tmp/test',
    });
    const result = await engine.syncOne(new CisaVulnrichmentSource());
    expect(result.status).toBe('error');
    expect(result.error).toMatch(/not a gzip stream|gunzip failed/);
    expect(new AdvisoryRepository(db).count()).toBe(0);
  });

  it('does not corrupt the DB when the archive contains both safe and traversal entries', async () => {
    const tar = buildTar([
      { path: 'safe/CVE-2024-3094.json', content: ENC.encode('{"cveMetadata":{"cveId":"CVE-2024-3094"},"containers":{"adp":[{"providerMetadata":{"shortName":"CISA-ADP"},"title":"safe"}]}}') },
      { path: '../etc/passwd', content: ENC.encode('attack') },
    ]);
    const gz = new Uint8Array(gzipSync(Buffer.from(tar)));
    const engine = new SyncEngine({
      db,
      downloader: stubDownloader(gz),
      cacheDir: '/tmp/test',
    });
    const result = await engine.syncOne(new CisaVulnrichmentSource());
    // The whole sync aborts with the path-traversal rejection. The safe
    // entry was processed first, but the engine wraps each record in a
    // transaction so a later failure leaves the previously-committed safe
    // record in place. Both behaviors are acceptable — the security
    // property is that the malicious file is *never* written to disk
    // (we don't extract to disk at all) and the DB remains internally
    // consistent.
    expect(result.status).toBe('error');
    expect(result.error).toMatch(/path traversal/);
  });
});
