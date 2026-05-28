import { gzipSync } from 'node:zlib';

import { describe, expect, it } from 'vitest';

import { buildTar } from '../../tests/fixtures/tar-builder.js';

import { createGoVulnDbSource, createPypaSource, createRustSecSource } from './osv-ecosystem.js';

import type { SyncContext } from './source.js';
import type { Downloader } from '../ingest/downloader.js';

const ENC = new TextEncoder();

function makeCtx(body: Uint8Array): SyncContext {
  const dl: Downloader = {
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
  return {
    cacheDir: '/tmp/test',
    downloader: dl,
    signal: new AbortController().signal,
  };
}

const RUSTSEC_RECORD = {
  id: 'RUSTSEC-2024-0001',
  summary: 'Cargo crate uses-after-free',
  details: 'Details here.',
  modified: '2024-05-01T00:00:00Z',
  published: '2024-04-30T00:00:00Z',
  affected: [
    {
      package: { ecosystem: 'crates.io', name: 'foo-crate' },
      ranges: [{ events: [{ introduced: '1.0.0' }, { fixed: '1.2.0' }] }],
    },
  ],
};

const PYPA_RECORD = {
  id: 'PYSEC-2024-1234',
  summary: 'Django RCE',
  details: 'Details.',
  aliases: ['CVE-2024-5555'],
  affected: [
    {
      package: { ecosystem: 'PyPI', name: 'django' },
      ranges: [{ events: [{ introduced: '4.0' }, { fixed: '4.2.5' }] }],
    },
  ],
};

describe('OsvEcosystemSource', () => {
  it('RustSec adapter declares ecosystems preset and parses one record', async () => {
    const src = createRustSecSource();
    expect(src.id).toBe('rustsec');
    expect(src.defaultPreset).toBe('ecosystems');
    const tar = buildTar([
      {
        path: 'crates/foo-crate/RUSTSEC-2024-0001.json',
        content: ENC.encode(JSON.stringify(RUSTSEC_RECORD)),
      },
    ]);
    const ctx = makeCtx(new Uint8Array(gzipSync(Buffer.from(tar))));
    const fetched = await src.fetch(ctx, { changed: true });
    const records = [];
    for await (const r of src.parse(ctx, fetched)) records.push(r);
    expect(records.map((r) => r.sourceRecordId)).toEqual(['RUSTSEC-2024-0001']);
  });

  it('PyPA adapter resolves CVE alias as canonical id', async () => {
    const src = createPypaSource();
    const ctx = makeCtx(new Uint8Array());
    const evidence = await src.normalize(ctx, {
      sourceRecordId: 'PYSEC-2024-1234',
      raw: PYPA_RECORD,
    });
    expect(evidence[0]?.advisoryId).toBe('CVE-2024-5555');
    expect(evidence[0]?.advisoryDraft?.aliases).toContain('PYSEC-2024-1234');
  });

  it('Go vulndb adapter rejects unrelated JSON entries', async () => {
    const src = createGoVulnDbSource();
    const tar = buildTar([
      { path: 'README.md', content: ENC.encode('not osv') },
      {
        path: 'data/reports/GO-2024-0001.json',
        content: ENC.encode(JSON.stringify({ id: 'GO-2024-0001', summary: 'go' })),
      },
    ]);
    const ctx = makeCtx(new Uint8Array(gzipSync(Buffer.from(tar))));
    const fetched = await src.fetch(ctx, { changed: true });
    const records = [];
    for await (const r of src.parse(ctx, fetched)) records.push(r);
    expect(records.map((r) => r.sourceRecordId)).toEqual(['GO-2024-0001']);
  });

  it('normalizes RustSec ecosystem alias crates.io → cargo', async () => {
    const src = createRustSecSource();
    const ctx = makeCtx(new Uint8Array());
    const evidence = await src.normalize(ctx, {
      sourceRecordId: 'RUSTSEC-2024-0001',
      raw: RUSTSEC_RECORD,
    });
    const normalized = evidence[0]?.normalized as {
      affected: { ecosystem: string }[];
    };
    expect(normalized.affected[0]?.ecosystem).toBe('cargo');
  });
});
