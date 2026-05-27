import { gzipSync } from 'node:zlib';

import { describe, expect, it } from 'vitest';

import { FirstEpssSource, parseEpssCsv } from './first-epss.js';

import type { SyncContext } from './source.js';
import type { Downloader } from '../ingest/downloader.js';

const SAMPLE_CSV = `#model_version:v2024.07.01,score_date:2026-05-27T00:00:00+0000
cve,epss,percentile
CVE-2024-3094,0.91234,0.99876
CVE-2021-44228,0.97500,0.99990
CVE-2023-12345,0.00045,0.13420
not-a-cve,0.5,0.5
CVE-2020-9999,bad,number
CVE-2020-0001,1.5,0.5
`;

function ctxWithBody(body: Uint8Array): SyncContext {
  const dl: Downloader = {
    download: () =>
      Promise.resolve({
        url: 'https://epss.cyentia.com/test.csv.gz',
        status: 200,
        contentType: 'application/gzip',
        etag: 'epss-v1',
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

describe('parseEpssCsv', () => {
  it('returns three valid rows and skips invalid lines', () => {
    const rows = parseEpssCsv(SAMPLE_CSV);
    expect(rows).toHaveLength(3);
    expect(rows[0]?.cve).toBe('CVE-2024-3094');
    expect(rows[0]?.epss).toBeCloseTo(0.91234, 5);
  });

  it('rejects out-of-range probabilities and percentiles', () => {
    const rows = parseEpssCsv('cve,epss,percentile\nCVE-2020-0001,1.5,0.5\n');
    expect(rows).toEqual([]);
  });

  it('lowercase CVE ids are normalized to upper case', () => {
    const rows = parseEpssCsv('cve,epss,percentile\ncve-2024-3094,0.5,0.5\n');
    expect(rows[0]?.cve).toBe('CVE-2024-3094');
  });
});

describe('FirstEpssSource', () => {
  it('declares Tier A core preset and never requires an API key', () => {
    const s = new FirstEpssSource();
    expect(s.id).toBe('first-epss');
    expect(s.trustTier).toBe('A');
    expect(s.defaultPreset).toBe('core');
    expect(s.requiresApiKey).toBe(false);
  });

  it('parse decompresses a gzipped CSV body and yields rows', async () => {
    const s = new FirstEpssSource();
    const gz = gzipSync(Buffer.from(SAMPLE_CSV, 'utf-8'));
    const ctx = ctxWithBody(new Uint8Array(gz));
    const fetched = await s.fetch(ctx, { changed: true });
    const out = [];
    for await (const r of s.parse(ctx, fetched)) out.push(r);
    expect(out).toHaveLength(3);
  });

  it('parse handles a raw (non-gzipped) CSV body', async () => {
    const s = new FirstEpssSource();
    const ctx = ctxWithBody(new TextEncoder().encode(SAMPLE_CSV));
    const fetched = await s.fetch(ctx, { changed: true });
    const out = [];
    for await (const r of s.parse(ctx, fetched)) out.push(r);
    expect(out).toHaveLength(3);
  });

  it('normalize emits an EPSS evidence row with advisoryDraft shell', async () => {
    const s = new FirstEpssSource();
    const ctx = ctxWithBody(new Uint8Array());
    const evidence = await s.normalize(ctx, {
      sourceRecordId: 'CVE-2024-3094',
      raw: { cve: 'CVE-2024-3094', epss: 0.91234, percentile: 0.99876 },
    });
    expect(evidence).toHaveLength(1);
    expect(evidence[0]?.id).toBe('epss:CVE-2024-3094');
    expect(evidence[0]?.evidenceType).toBe('epss_score');
    expect(evidence[0]?.advisoryDraft?.id).toBe('CVE-2024-3094');
    expect(evidence[0]?.summary).toMatch(/0.91234/);
  });
});
