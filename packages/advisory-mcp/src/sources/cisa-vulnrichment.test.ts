import { gzipSync } from 'node:zlib';

import { describe, expect, it } from 'vitest';

import { buildTar } from '../../tests/fixtures/tar-builder.js';

import { CisaVulnrichmentSource } from './cisa-vulnrichment.js';

import type { SyncContext } from './source.js';
import type { Downloader } from '../ingest/downloader.js';

const ENC = new TextEncoder();

const VULNRICHMENT_RECORD = {
  dataType: 'CVE_RECORD',
  dataVersion: '5.1',
  cveMetadata: { cveId: 'CVE-2024-3094' },
  containers: {
    cna: {},
    adp: [
      {
        providerMetadata: { shortName: 'CISA-ADP' },
        title: 'CISA ADP Vulnrichment',
        metrics: [
          { other: { type: 'ssvc', content: { Exploitation: 'active' } } },
          { cvssV3_1: { vectorString: 'CVSS:3.1/AV:N/...', baseScore: 10.0 } },
        ],
        problemTypes: [
          { descriptions: [{ cweId: 'CWE-506', description: 'Embedded Malicious Code' }] },
        ],
      },
    ],
  },
};

function ctxWithBody(body: Uint8Array): SyncContext {
  const dl: Downloader = {
    download: () =>
      Promise.resolve({
        url: 'https://codeload.github.com/x/y/tar.gz/z',
        status: 200,
        contentType: 'application/gzip',
        etag: 'vr-v1',
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

describe('CisaVulnrichmentSource', () => {
  it('declares Tier A core preset and never requires an API key', () => {
    const s = new CisaVulnrichmentSource();
    expect(s.id).toBe('cisa-vulnrichment');
    expect(s.trustTier).toBe('A');
    expect(s.defaultPreset).toBe('core');
    expect(s.requiresApiKey).toBe(false);
  });

  it('parse decompresses a gzipped tarball and yields one record per CVE JSON', async () => {
    const tar = buildTar([
      { path: '2024/CVE-2024/CVE-2024-3094.json', content: ENC.encode(JSON.stringify(VULNRICHMENT_RECORD)) },
      { path: 'README.md', content: ENC.encode('# not a cve record') },
    ]);
    const gz = new Uint8Array(gzipSync(Buffer.from(tar)));
    const s = new CisaVulnrichmentSource();
    const ctx = ctxWithBody(gz);
    const fetched = await s.fetch(ctx, { changed: true });
    const records = [];
    for await (const r of s.parse(ctx, fetched)) records.push(r);
    expect(records).toHaveLength(1);
    expect(records[0]?.sourceRecordId).toBe('CVE-2024-3094');
  });

  it('normalize extracts ADP enrichment with provenance=adp', async () => {
    const s = new CisaVulnrichmentSource();
    const ctx = ctxWithBody(new Uint8Array());
    const evidence = await s.normalize(ctx, {
      sourceRecordId: 'CVE-2024-3094',
      raw: VULNRICHMENT_RECORD,
    });
    expect(evidence).toHaveLength(1);
    expect(evidence[0]?.evidenceType).toBe('cisa_adp_enrichment');
    expect(evidence[0]?.confidence).toBe(0.85);
    const normalized = evidence[0]?.normalized as {
      cwes: string[];
      ssvc?: unknown;
      cvss?: unknown;
      provenance: string;
    };
    expect(normalized.cwes).toEqual(['CWE-506']);
    expect(normalized.provenance).toBe('adp');
    expect(normalized.ssvc).toBeDefined();
    expect(normalized.cvss).toBeDefined();
  });

  it('skips records with no ADP container', async () => {
    const s = new CisaVulnrichmentSource();
    const ctx = ctxWithBody(new Uint8Array());
    const evidence = await s.normalize(ctx, {
      sourceRecordId: 'CVE-2020-1234',
      raw: { cveMetadata: { cveId: 'CVE-2020-1234' }, containers: { cna: {} } },
    });
    expect(evidence).toEqual([]);
  });

  it('skips malformed JSON files in the archive without failing the whole sync', async () => {
    const tar = buildTar([
      { path: '2024/CVE-2024/CVE-2024-3094.json', content: ENC.encode('not json') },
      { path: '2024/CVE-2024/CVE-2024-3400.json', content: ENC.encode(JSON.stringify(VULNRICHMENT_RECORD)) },
    ]);
    const gz = new Uint8Array(gzipSync(Buffer.from(tar)));
    const s = new CisaVulnrichmentSource();
    const ctx = ctxWithBody(gz);
    const fetched = await s.fetch(ctx, { changed: true });
    const records = [];
    for await (const r of s.parse(ctx, fetched)) records.push(r);
    expect(records).toHaveLength(1);
  });
});
