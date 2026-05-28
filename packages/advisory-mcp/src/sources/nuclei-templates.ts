import { gunzipWithLimit } from '../ingest/decompressor.js';
import { readTar } from '../ingest/tar.js';
import { sanitizeText } from '../security/content-sanitizer.js';
import { nowIso } from '../util/time.js';

import type {
  NormalizedEvidence,
  RawSourceRecord,
  SourceAdapter,
  SyncContext,
  FetchResult,
  UpdateCheckResult,
} from './source.js';

/**
 * ProjectDiscovery Nuclei templates (RFC 6.3 / Tier C, research preset).
 *
 * Each template is a YAML file describing how to *detect* a vulnerability.
 * advisory-mcp never executes templates — it only indexes the metadata
 * (id, info.name, info.classification.cve-id) so analysts can see which
 * advisories have published detection content. Full template payloads are
 * left out of normalized JSON to keep the index lean.
 */

const NUCLEI_URL =
  'https://codeload.github.com/projectdiscovery/nuclei-templates/tar.gz/main';
export const NUCLEI_HOST = 'codeload.github.com';

const TEMPLATE_PATH_RE = /\/([\w-]+)\.yaml$/;
// Pull `id: ...` and any `cve-id: CVE-YYYY-NNNN` lines out of the YAML head
// without a full YAML parser. Templates have a stable schema where these
// appear at the document root.
const ID_RE = /^id:\s*([\w.-]+)/m;
const CVE_RE = /cve-id:\s*([\w-]+)/i;
const NAME_RE = /^\s*name:\s*(.+)$/m;

interface NucleiSourceOptions {
  url?: string;
}

export class NucleiTemplatesSource implements SourceAdapter {
  readonly id = 'nuclei-templates';
  readonly displayName = 'Nuclei Templates';
  readonly trustTier = 'C' as const;
  readonly defaultPreset = 'research' as const;
  readonly requiresApiKey = false as const;

  private readonly url: string;

  constructor(options: NucleiSourceOptions = {}) {
    this.url = options.url ?? NUCLEI_URL;
  }

  checkForUpdates(_ctx: SyncContext): Promise<UpdateCheckResult> {
    return Promise.resolve({ changed: true });
  }

  async fetch(ctx: SyncContext, _update: UpdateCheckResult): Promise<FetchResult> {
    const res = await ctx.downloader.download({
      url: this.url,
      etag: ctx.lastEtag,
      lastModified: ctx.lastModified,
      signal: ctx.signal,
    });
    if (res === 'not_modified') {
      return { artifacts: [], etag: ctx.lastEtag, lastModified: ctx.lastModified };
    }
    return {
      artifacts: [
        {
          url: res.url,
          contentType: res.contentType,
          bytes: res.body,
          sha256: res.sha256,
          fetchedAt: nowIso(),
        },
      ],
      etag: res.etag,
      lastModified: res.lastModified,
    };
  }

  // eslint-disable-next-line @typescript-eslint/require-await -- AsyncIterable contract
  async *parse(_ctx: SyncContext, fetched: FetchResult): AsyncIterable<RawSourceRecord> {
    for (const artifact of fetched.artifacts) {
      const tarBytes = gunzipWithLimit(artifact.bytes);
      for (const entry of readTar(tarBytes)) {
        if (!TEMPLATE_PATH_RE.test(entry.path)) continue;
        const text = new TextDecoder('utf-8', { fatal: false }).decode(entry.content);
        const idMatch = ID_RE.exec(text);
        if (!idMatch?.[1]) continue;
        const cveMatch = CVE_RE.exec(text);
        const nameMatch = NAME_RE.exec(text);
        yield {
          sourceRecordId: idMatch[1],
          raw: {
            id: idMatch[1],
            cveId: cveMatch?.[1]?.toUpperCase(),
            name: nameMatch?.[1]?.trim(),
          },
        };
      }
    }
  }

  normalize(_ctx: SyncContext, record: RawSourceRecord): Promise<NormalizedEvidence[]> {
    const r = record.raw as { id: string; cveId?: string; name?: string };
    if (!r.cveId) return Promise.resolve([]); // require a CVE link to anchor evidence
    return Promise.resolve<NormalizedEvidence[]>([
      {
        id: `nuclei:${r.id}`,
        advisoryId: r.cveId,
        evidenceType: 'detection_signature',
        confidence: 0.4,
        summary: sanitizeText(`Nuclei template ${r.id}: ${r.name ?? r.cveId}`),
        normalized: { templateId: r.id, cveId: r.cveId, provenance: 'nuclei' },
        advisoryDraft: {
          id: r.cveId,
          canonicalId: r.cveId,
          type: 'cve',
          aliases: [],
        },
      },
    ]);
  }
}
