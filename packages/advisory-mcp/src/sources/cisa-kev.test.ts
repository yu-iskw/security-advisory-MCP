import { describe, expect, it } from 'vitest';

import { CisaKevSource } from './cisa-kev.js';

import type { SyncContext } from './source.js';
import type { Downloader } from '../ingest/downloader.js';

const SAMPLE_KEV = {
  title: 'CISA Catalog of Known Exploited Vulnerabilities',
  catalogVersion: '2026.05.27',
  dateReleased: '2026-05-27T13:00:00.000Z',
  count: 2,
  vulnerabilities: [
    {
      cveID: 'CVE-2024-3094',
      vendorProject: 'XZ Utils',
      product: 'liblzma',
      vulnerabilityName: 'XZ Utils Embedded Malicious Code Vulnerability',
      dateAdded: '2024-03-29',
      shortDescription: 'A malicious backdoor was inserted into liblzma.',
      requiredAction: 'Apply mitigations.',
      dueDate: '2024-04-19',
      knownRansomwareCampaignUse: 'Unknown',
      notes: '',
    },
    {
      cveID: 'CVE-2021-44228',
      vendorProject: 'Apache',
      product: 'Log4j2',
      vulnerabilityName: 'Apache Log4j2 RCE',
      dateAdded: '2021-12-10',
      shortDescription: 'Log4j2 JNDI lookup allows RCE.',
      requiredAction: 'Upgrade to a patched version.',
      dueDate: '2021-12-24',
      knownRansomwareCampaignUse: 'Known',
      notes: '',
    },
  ],
};

function makeContext(downloader: Downloader, overrides: Partial<SyncContext> = {}): SyncContext {
  return {
    cacheDir: '/tmp/test',
    downloader,
    signal: new AbortController().signal,
    ...overrides,
  };
}

function stubDownloader(body: unknown, etag = 'v1'): Downloader {
  return {
    download: () =>
      Promise.resolve({
        url: 'https://www.cisa.gov/test.json',
        status: 200,
        contentType: 'application/json',
        etag,
        lastModified: 'Tue, 27 May 2026 13:00:00 GMT',
        body: new TextEncoder().encode(JSON.stringify(body)),
        sha256: 'deadbeef'.repeat(8),
      }),
  };
}

describe('CisaKevSource', () => {
  it('declares Tier A core preset and never requires an API key', () => {
    const s = new CisaKevSource();
    expect(s.id).toBe('cisa-kev');
    expect(s.trustTier).toBe('A');
    expect(s.defaultPreset).toBe('core');
    expect(s.requiresApiKey).toBe(false);
  });

  it('checkForUpdates always returns changed=true (server short-circuits via 304)', async () => {
    const s = new CisaKevSource();
    const ctx = makeContext(stubDownloader({ vulnerabilities: [] }));
    const upd = await s.checkForUpdates(ctx);
    expect(upd.changed).toBe(true);
  });

  it('fetch returns artifacts on 200 and surfaces validator headers', async () => {
    const s = new CisaKevSource();
    const ctx = makeContext(stubDownloader(SAMPLE_KEV, 'etag-A'));
    const fetched = await s.fetch(ctx, { changed: true });
    expect(fetched.artifacts).toHaveLength(1);
    expect(fetched.etag).toBe('etag-A');
  });

  it('fetch returns empty artifacts on 304 not_modified', async () => {
    const s = new CisaKevSource();
    const dl: Downloader = { download: () => Promise.resolve('not_modified') };
    const ctx = makeContext(dl, { lastEtag: 'v1' });
    const fetched = await s.fetch(ctx, { changed: true });
    expect(fetched.artifacts).toHaveLength(0);
    expect(fetched.etag).toBe('v1');
  });

  it('parse yields one RawSourceRecord per vulnerability', async () => {
    const s = new CisaKevSource();
    const ctx = makeContext(stubDownloader(SAMPLE_KEV));
    const fetched = await s.fetch(ctx, { changed: true });
    const records = [];
    for await (const r of s.parse(ctx, fetched)) records.push(r);
    expect(records).toHaveLength(2);
    expect(records[0]?.sourceRecordId).toBe('CVE-2024-3094');
  });

  it('normalize produces NormalizedEvidence with advisoryDraft', async () => {
    const s = new CisaKevSource();
    const ctx = makeContext(stubDownloader(SAMPLE_KEV));
    const entry = SAMPLE_KEV.vulnerabilities[0];
    const evidence = await s.normalize(ctx, { sourceRecordId: entry?.cveID, raw: entry });
    expect(evidence).toHaveLength(1);
    expect(evidence[0]?.id).toBe('kev:CVE-2024-3094');
    expect(evidence[0]?.evidenceType).toBe('known_exploited');
    expect(evidence[0]?.confidence).toBe(0.95);
    expect(evidence[0]?.advisoryDraft).toMatchObject({
      id: 'CVE-2024-3094',
      canonicalId: 'CVE-2024-3094',
      type: 'cve',
      title: 'XZ Utils Embedded Malicious Code Vulnerability',
    });
  });

  it('parse rejects malformed payloads via Zod', async () => {
    const s = new CisaKevSource();
    const ctx = makeContext(stubDownloader({ vulnerabilities: [{ cveID: 1 }] }));
    const fetched = await s.fetch(ctx, { changed: true });
    const drain = async (): Promise<void> => {
      for await (const item of s.parse(ctx, fetched)) {
        void item;
      }
    };
    await expect(drain()).rejects.toThrow();
  });
});
