import { gzipSync } from 'node:zlib';

import { describe, expect, it } from 'vitest';

import { buildTar } from '../../tests/fixtures/tar-builder.js';

import { CveProjectSource } from './cveproject.js';

import type { SyncContext } from './source.js';
import type { Downloader } from '../ingest/downloader.js';

const ENC = new TextEncoder();

const CVE_RECORD = {
  dataType: 'CVE_RECORD',
  dataVersion: '5.1',
  cveMetadata: {
    cveId: 'CVE-2024-3094',
    state: 'PUBLISHED',
    datePublished: '2024-03-29T00:00:00.000Z',
    dateUpdated: '2024-04-01T00:00:00.000Z',
  },
  containers: {
    cna: {
      title: 'XZ Utils Backdoor',
      descriptions: [
        { lang: 'es', value: 'Una puerta trasera maliciosa.' },
        { lang: 'en', value: 'A malicious backdoor was inserted into liblzma.' },
      ],
      affected: [
        {
          vendor: 'xz',
          product: 'xz-utils',
          versions: [{ version: '5.6.0', status: 'affected' }],
        },
      ],
      metrics: [
        { cvssV3_1: { vectorString: 'CVSS:3.1/AV:N/...', baseScore: 10.0 } },
      ],
      problemTypes: [
        { descriptions: [{ cweId: 'CWE-506', description: 'Embedded Malicious Code' }] },
      ],
      references: [{ url: 'https://example.test/advisory', tags: ['vendor-advisory'] }],
    },
  },
};

function ctxWithBody(body: Uint8Array): SyncContext {
  const dl: Downloader = {
    download: () =>
      Promise.resolve({
        url: 'https://codeload.github.com/CVEProject/cvelistV5/tar.gz/main',
        status: 200,
        contentType: 'application/gzip',
        etag: 'cve-v1',
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

describe('CveProjectSource', () => {
  it('declares Tier A core preset and never requires an API key', () => {
    const s = new CveProjectSource();
    expect(s.id).toBe('cveproject');
    expect(s.trustTier).toBe('A');
    expect(s.defaultPreset).toBe('core');
    expect(s.requiresApiKey).toBe(false);
  });

  it('parse yields one record per CVE-*.json file in the archive', async () => {
    const tar = buildTar([
      { path: 'cves/2024/CVE-2024-3094.json', content: ENC.encode(JSON.stringify(CVE_RECORD)) },
      { path: 'README.md', content: ENC.encode('# not a cve') },
    ]);
    const s = new CveProjectSource();
    const ctx = ctxWithBody(new Uint8Array(gzipSync(Buffer.from(tar))));
    const fetched = await s.fetch(ctx, { changed: true });
    const records = [];
    for await (const r of s.parse(ctx, fetched)) records.push(r);
    expect(records.map((r) => r.sourceRecordId)).toEqual(['CVE-2024-3094']);
  });

  it('normalize picks English description and tags provenance=cna', async () => {
    const s = new CveProjectSource();
    const ctx = ctxWithBody(new Uint8Array());
    const evidence = await s.normalize(ctx, {
      sourceRecordId: 'CVE-2024-3094',
      raw: CVE_RECORD,
    });
    expect(evidence).toHaveLength(1);
    expect(evidence[0]?.evidenceType).toBe('cve_record');
    expect(evidence[0]?.confidence).toBe(0.95);
    expect(evidence[0]?.advisoryDraft).toMatchObject({
      title: 'XZ Utils Backdoor',
      publishedAt: '2024-03-29T00:00:00.000Z',
    });
    expect(evidence[0]?.advisoryDraft?.description).toMatch(/malicious backdoor/);
    const normalized = evidence[0]?.normalized as { cwes: string[]; provenance: string };
    expect(normalized.cwes).toEqual(['CWE-506']);
    expect(normalized.provenance).toBe('cna');
  });

  it('skips records with no CNA container', async () => {
    const s = new CveProjectSource();
    const ctx = ctxWithBody(new Uint8Array());
    const evidence = await s.normalize(ctx, {
      sourceRecordId: 'CVE-2024-9999',
      raw: { cveMetadata: { cveId: 'CVE-2024-9999' }, containers: {} },
    });
    expect(evidence).toEqual([]);
  });

  it('falls back to the first description when no English entry exists', async () => {
    const s = new CveProjectSource();
    const ctx = ctxWithBody(new Uint8Array());
    const onlyEs: typeof CVE_RECORD = JSON.parse(JSON.stringify(CVE_RECORD)) as typeof CVE_RECORD;
    (onlyEs.containers.cna.descriptions as { lang: string; value: string }[]) = [
      { lang: 'es', value: 'Una puerta trasera maliciosa.' },
    ];
    const evidence = await s.normalize(ctx, {
      sourceRecordId: 'CVE-2024-3094',
      raw: onlyEs,
    });
    expect(evidence[0]?.advisoryDraft?.description).toMatch(/puerta trasera/);
  });
});
