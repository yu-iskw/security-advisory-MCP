import { gzipSync } from 'node:zlib';

import { describe, expect, it } from 'vitest';

import { buildTar } from '../../tests/fixtures/tar-builder.js';

import { NucleiTemplatesSource } from './nuclei-templates.js';

import type { SyncContext } from './source.js';
import type { Downloader } from '../ingest/downloader.js';

const ENC = new TextEncoder();

const TEMPLATE_YAML = `id: CVE-2021-44228-log4shell
info:
  name: Apache Log4j2 RCE
  severity: critical
  classification:
    cve-id: CVE-2021-44228
`;

function ctxWithBody(body: Uint8Array): SyncContext {
  const dl: Downloader = {
    download: () =>
      Promise.resolve({
        url: 'https://codeload.github.com/projectdiscovery/nuclei-templates/tar.gz/main',
        status: 200,
        contentType: 'application/gzip',
        etag: 'nt-v1',
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

describe('NucleiTemplatesSource', () => {
  it('declares Tier C research preset', () => {
    const s = new NucleiTemplatesSource();
    expect(s.trustTier).toBe('C');
    expect(s.defaultPreset).toBe('research');
  });

  it('parse extracts id + cve-id from YAML templates', async () => {
    const tar = buildTar([
      {
        path: 'cves/2021/CVE-2021-44228-log4shell.yaml',
        content: ENC.encode(TEMPLATE_YAML),
      },
      { path: 'README.md', content: ENC.encode('not yaml') },
    ]);
    const s = new NucleiTemplatesSource();
    const ctx = ctxWithBody(new Uint8Array(gzipSync(Buffer.from(tar))));
    const fetched = await s.fetch(ctx, { changed: true });
    const records = [];
    for await (const r of s.parse(ctx, fetched)) records.push(r);
    expect(records).toHaveLength(1);
    expect((records[0]?.raw as { cveId?: string }).cveId).toBe('CVE-2021-44228');
  });

  it('normalize anchors evidence to the linked CVE', async () => {
    const s = new NucleiTemplatesSource();
    const ctx = ctxWithBody(new Uint8Array());
    const evidence = await s.normalize(ctx, {
      sourceRecordId: 'tpl-1',
      raw: { id: 'tpl-1', cveId: 'CVE-2021-44228', name: 'Log4Shell' },
    });
    expect(evidence[0]?.advisoryId).toBe('CVE-2021-44228');
    expect(evidence[0]?.evidenceType).toBe('detection_signature');
  });

  it('skips templates with no linked CVE', async () => {
    const s = new NucleiTemplatesSource();
    const ctx = ctxWithBody(new Uint8Array());
    const evidence = await s.normalize(ctx, {
      sourceRecordId: 'tpl-2',
      raw: { id: 'tpl-2', name: 'no cve' },
    });
    expect(evidence).toEqual([]);
  });
});
