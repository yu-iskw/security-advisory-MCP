import { gzipSync } from 'node:zlib';

import { describe, expect, it } from 'vitest';

import { buildTar } from '../../tests/fixtures/tar-builder.js';

import { OsvGithubSource } from './osv-github.js';

import type { SyncContext } from './source.js';
import type { Downloader } from '../ingest/downloader.js';

const ENC = new TextEncoder();

const OSV_RECORD = {
  schema_version: '1.6.0',
  id: 'GHSA-jfh8-c2jp-5v3q',
  modified: '2024-04-01T00:00:00Z',
  published: '2021-12-10T00:00:00Z',
  aliases: ['CVE-2021-44228'],
  summary: 'Remote code execution in Apache Log4j',
  details: 'Apache Log4j2 JNDI lookup allows remote code execution by attackers.',
  database_specific: { severity: 'CRITICAL' },
  affected: [
    {
      package: { ecosystem: 'Maven', name: 'org.apache.logging.log4j:log4j-core' },
      ranges: [
        { type: 'ECOSYSTEM', events: [{ introduced: '2.0' }, { fixed: '2.17.0' }] },
      ],
    },
  ],
};

function ctxWithBody(body: Uint8Array): SyncContext {
  const dl: Downloader = {
    download: () =>
      Promise.resolve({
        url: 'https://codeload.github.com/github/advisory-database/tar.gz/main',
        status: 200,
        contentType: 'application/gzip',
        etag: 'osv-v1',
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

describe('OsvGithubSource', () => {
  it('declares Tier B packages preset and never requires an API key', () => {
    const s = new OsvGithubSource();
    expect(s.id).toBe('osv');
    expect(s.trustTier).toBe('B');
    expect(s.defaultPreset).toBe('packages');
    expect(s.requiresApiKey).toBe(false);
  });

  it('parse yields one record per GHSA-*.json', async () => {
    const tar = buildTar([
      {
        path: 'advisories/github-reviewed/2021/12/GHSA-jfh8-c2jp-5v3q/GHSA-jfh8-c2jp-5v3q.json',
        content: ENC.encode(JSON.stringify(OSV_RECORD)),
      },
      { path: 'README.md', content: ENC.encode('# not osv') },
    ]);
    const gz = new Uint8Array(gzipSync(Buffer.from(tar)));
    const s = new OsvGithubSource();
    const ctx = ctxWithBody(gz);
    const fetched = await s.fetch(ctx, { changed: true });
    const records = [];
    for await (const r of s.parse(ctx, fetched)) records.push(r);
    expect(records.map((r) => r.sourceRecordId)).toEqual(['GHSA-JFH8-C2JP-5V3Q']);
  });

  it('normalize prefers CVE alias as canonical id and keeps GHSA as alias', async () => {
    const s = new OsvGithubSource();
    const ctx = ctxWithBody(new Uint8Array());
    const evidence = await s.normalize(ctx, {
      sourceRecordId: 'GHSA-JFH8-C2JP-5V3Q',
      raw: OSV_RECORD,
    });
    expect(evidence).toHaveLength(1);
    expect(evidence[0]?.advisoryId).toBe('CVE-2021-44228');
    expect(evidence[0]?.advisoryDraft?.id).toBe('CVE-2021-44228');
    expect(evidence[0]?.advisoryDraft?.aliases).toEqual(['GHSA-JFH8-C2JP-5V3Q']);
    expect(evidence[0]?.advisoryDraft?.type).toBe('cve');
  });

  it('uses GHSA as canonical when no CVE alias exists', async () => {
    const s = new OsvGithubSource();
    const ctx = ctxWithBody(new Uint8Array());
    const noCve = { ...OSV_RECORD, aliases: [] };
    const evidence = await s.normalize(ctx, { sourceRecordId: 'GHSA-xxxx-xxxx-xxxx', raw: noCve });
    expect(evidence[0]?.advisoryId).toBe('GHSA-JFH8-C2JP-5V3Q');
    expect(evidence[0]?.advisoryDraft?.type).toBe('ghsa');
  });

  it('normalizes ecosystem name (Maven → maven)', async () => {
    const s = new OsvGithubSource();
    const ctx = ctxWithBody(new Uint8Array());
    const evidence = await s.normalize(ctx, {
      sourceRecordId: 'GHSA-JFH8-C2JP-5V3Q',
      raw: OSV_RECORD,
    });
    const normalized = evidence[0]?.normalized as { affected: { ecosystem: string }[] };
    expect(normalized.affected[0]?.ecosystem).toBe('maven');
  });

  it('collapses {introduced, fixed} into one range entry', async () => {
    const s = new OsvGithubSource();
    const ctx = ctxWithBody(new Uint8Array());
    const evidence = await s.normalize(ctx, {
      sourceRecordId: 'GHSA-JFH8-C2JP-5V3Q',
      raw: OSV_RECORD,
    });
    const normalized = evidence[0]?.normalized as {
      affected: { ranges: { introduced?: string; fixed?: string }[] }[];
    };
    expect(normalized.affected[0]?.ranges).toEqual([{ introduced: '2.0', fixed: '2.17.0' }]);
  });
});
