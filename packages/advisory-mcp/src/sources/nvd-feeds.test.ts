import { gzipSync } from 'node:zlib';

import { describe, expect, it } from 'vitest';

import { sha256Hex } from '../ingest/verifier.js';

import { NvdFeedsSource, parseNvdMeta } from './nvd-feeds.js';

import type { SyncContext } from './source.js';
import type { Downloader } from '../ingest/downloader.js';

const SAMPLE_FEED = {
  vulnerabilities: [
    {
      cve: {
        id: 'CVE-2024-3094',
        published: '2024-03-29T00:00:00.000',
        lastModified: '2024-04-01T00:00:00.000',
        vulnStatus: 'Modified',
        descriptions: [{ lang: 'en', value: 'Malicious code in liblzma.' }],
        metrics: {
          cvssMetricV31: [
            {
              source: 'nvd@nist.gov',
              type: 'Primary',
              cvssData: {
                baseScore: 10.0,
                baseSeverity: 'CRITICAL',
                vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
              },
            },
          ],
        },
        weaknesses: [{ description: [{ lang: 'en', value: 'CWE-506' }] }],
        references: [{ url: 'https://example.test/x', tags: ['third-party-advisory'] }],
      },
    },
  ],
};

function makeMeta(body: Uint8Array): { meta: string; sha: string } {
  const sha = sha256Hex(body);
  const meta =
    `lastModifiedDate:2026-05-27T00:00:00-04:00\n` +
    `size:${body.length.toString()}\n` +
    `sha256:${sha.toUpperCase()}\n`;
  return { meta, sha };
}

interface DownloaderStubResponses {
  feed: Uint8Array;
  meta: string;
}

function makeDownloader(responses: DownloaderStubResponses): Downloader {
  return {
    download: (req) => {
      if (req.url.endsWith('.meta')) {
        return Promise.resolve({
          url: req.url,
          status: 200,
          contentType: 'text/plain',
          etag: undefined,
          lastModified: undefined,
          body: new TextEncoder().encode(responses.meta),
          sha256: '0'.repeat(64),
        });
      }
      return Promise.resolve({
        url: req.url,
        status: 200,
        contentType: 'application/gzip',
        etag: undefined,
        lastModified: undefined,
        body: responses.feed,
        sha256: sha256Hex(responses.feed),
      });
    },
  };
}

function makeCtx(downloader: Downloader, overrides: Partial<SyncContext> = {}): SyncContext {
  return {
    cacheDir: '/tmp/test',
    downloader,
    signal: new AbortController().signal,
    ...overrides,
  };
}

describe('parseNvdMeta', () => {
  it('parses lastModifiedDate, size, and sha256', () => {
    const m = parseNvdMeta('lastModifiedDate:2024-01-01\nsize:42\nsha256:ABCDEF\n');
    expect(m.lastModifiedDate).toBe('2024-01-01');
    expect(m.size).toBe(42);
    expect(m.sha256).toBe('abcdef');
  });

  it('throws on incomplete META', () => {
    expect(() => parseNvdMeta('size:1\n')).toThrow(/invalid NVD META/);
  });
});

describe('NvdFeedsSource', () => {
  it('declares Tier A core preset and never requires an API key', () => {
    const s = new NvdFeedsSource();
    expect(s.id).toBe('nvd-feed');
    expect(s.trustTier).toBe('A');
  });

  it('checkForUpdates returns unchanged when META sha matches the stored version', async () => {
    const feed = new Uint8Array(gzipSync(Buffer.from(JSON.stringify(SAMPLE_FEED))));
    const { meta, sha } = makeMeta(feed);
    const s = new NvdFeedsSource();
    const ctx = makeCtx(makeDownloader({ feed, meta }), { lastVersion: sha });
    const upd = await s.checkForUpdates(ctx);
    expect(upd.changed).toBe(false);
  });

  it('end-to-end: META → fetch (sha-verified) → parse → normalize', async () => {
    const feed = new Uint8Array(gzipSync(Buffer.from(JSON.stringify(SAMPLE_FEED))));
    const { meta } = makeMeta(feed);
    const s = new NvdFeedsSource();
    const ctx = makeCtx(makeDownloader({ feed, meta }));

    const upd = await s.checkForUpdates(ctx);
    expect(upd.changed).toBe(true);

    const fetched = await s.fetch(ctx, upd);
    expect(fetched.artifacts).toHaveLength(1);

    const records = [];
    for await (const r of s.parse(ctx, fetched)) records.push(r);
    expect(records).toHaveLength(1);

    const evidence = await s.normalize(ctx, records[0] ?? { raw: undefined });
    expect(evidence[0]?.evidenceType).toBe('nvd_enrichment');
    expect(evidence[0]?.confidence).toBe(0.8);
    const normalized = evidence[0]?.normalized as {
      cwes: string[];
      cvss: unknown;
      provenance: string;
    };
    expect(normalized.cwes).toEqual(['CWE-506']);
    expect(normalized.provenance).toBe('nvd');
    expect((normalized.cvss as { baseSeverity?: string }).baseSeverity).toBe('CRITICAL');
  });

  it('fetch throws HashMismatchError when META sha does not match the .json.gz body', async () => {
    const feed = new Uint8Array(gzipSync(Buffer.from(JSON.stringify(SAMPLE_FEED))));
    const badMeta = `lastModifiedDate:2026-05-27\nsize:${feed.length.toString()}\nsha256:${'0'.repeat(64)}\n`;
    const s = new NvdFeedsSource();
    const ctx = makeCtx(makeDownloader({ feed, meta: badMeta }));
    const upd = await s.checkForUpdates(ctx);
    await expect(s.fetch(ctx, upd)).rejects.toMatchObject({ name: 'HashMismatchError' });
  });
});
