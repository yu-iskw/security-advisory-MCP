import { gzipSync } from 'node:zlib';

import { describe, expect, it } from 'vitest';

import { buildTar } from '../../tests/fixtures/tar-builder.js';

import { OssfMaliciousPackagesSource } from './ossf-malicious-packages.js';

import type { SyncContext } from './source.js';
import type { Downloader } from '../ingest/downloader.js';

const ENC = new TextEncoder();

const MAL_RECORD = {
  schema_version: '1.6.0',
  id: 'MAL-2024-0001',
  modified: '2024-05-01T00:00:00Z',
  published: '2024-04-30T00:00:00Z',
  summary: 'Malicious npm package: foo-typosquat',
  details: 'Steals environment variables on install.',
  affected: [
    { package: { ecosystem: 'npm', name: 'foo-typosquat', purl: 'pkg:npm/foo-typosquat' } },
  ],
};

function ctxWithBody(body: Uint8Array): SyncContext {
  const dl: Downloader = {
    download: () =>
      Promise.resolve({
        url: 'https://codeload.github.com/ossf/malicious-packages/tar.gz/main',
        status: 200,
        contentType: 'application/gzip',
        etag: 'mal-v1',
        lastModified: undefined,
        body,
        sha256: '0'.repeat(64),
      }),
  };
  return {
    cacheDir: '/tmp/test',
    downloader: dl,
    signal: new AbortController().signal,
  };
}

describe('OssfMaliciousPackagesSource', () => {
  it('declares Tier B packages preset', () => {
    const s = new OssfMaliciousPackagesSource();
    expect(s.id).toBe('ossf-malicious-packages');
    expect(s.defaultPreset).toBe('packages');
  });

  it('parse yields one record per MAL-*.json', async () => {
    const tar = buildTar([
      {
        path: 'osv/npm/MAL-2024-0001.json',
        content: ENC.encode(JSON.stringify(MAL_RECORD)),
      },
      { path: 'README.md', content: ENC.encode('# ossf') },
    ]);
    const gz = new Uint8Array(gzipSync(Buffer.from(tar)));
    const s = new OssfMaliciousPackagesSource();
    const ctx = ctxWithBody(gz);
    const fetched = await s.fetch(ctx, { changed: true });
    const records = [];
    for await (const r of s.parse(ctx, fetched)) records.push(r);
    expect(records.map((r) => r.sourceRecordId)).toEqual(['MAL-2024-0001']);
  });

  it('normalize emits a malicious_package evidence with affected packages', async () => {
    const s = new OssfMaliciousPackagesSource();
    const ctx = ctxWithBody(new Uint8Array());
    const evidence = await s.normalize(ctx, {
      sourceRecordId: 'MAL-2024-0001',
      raw: MAL_RECORD,
    });
    expect(evidence).toHaveLength(1);
    expect(evidence[0]?.evidenceType).toBe('malicious_package');
    expect(evidence[0]?.advisoryDraft?.type).toBe('malicious_package');
    const normalized = evidence[0]?.normalized as {
      affected: { ecosystem: string; name: string }[];
    };
    expect(normalized.affected[0]).toMatchObject({ ecosystem: 'npm', name: 'foo-typosquat' });
  });
});
