import { gunzipWithLimit } from '../ingest/decompressor.js';
import { assertSha256 } from '../ingest/verifier.js';
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
 * NVD CVE 2.0 feeds (RFC 6.3 / Tier A). META files publish lastModifiedDate +
 * SHA-256, so we conditional-skip the .json.gz fetch when the META hash matches
 * the value persisted in source_state.sha256.
 *
 * The default URL points at the `modified` feed (eight-day rolling window),
 * which keeps incremental syncs cheap. Yearly feeds are equally valid; pass
 * `{ url, metaUrl }` to point at one.
 */
const NVD_FEED_BASE = 'https://nvd.nist.gov/feeds/json/cve/2.0';
const DEFAULT_FEED = 'nvdcve-2.0-modified.json.gz';
const DEFAULT_META = 'nvdcve-2.0-modified.meta';
export const NVD_HOST = 'nvd.nist.gov';

interface NvdMeta {
  lastModifiedDate: string;
  size: number;
  sha256: string;
}

interface NvdSourceOptions {
  url?: string;
  metaUrl?: string;
}

interface NvdCveDescription {
  lang?: string;
  value?: string;
}

interface NvdCvssData {
  baseScore?: number;
  baseSeverity?: string;
  vectorString?: string;
}

interface NvdCveMetric {
  source?: string;
  type?: string;
  cvssData?: NvdCvssData;
}

interface NvdCveRecord {
  cve: {
    id: string;
    published?: string;
    lastModified?: string;
    vulnStatus?: string;
    descriptions?: ReadonlyArray<NvdCveDescription>;
    metrics?: {
      cvssMetricV31?: ReadonlyArray<NvdCveMetric>;
      cvssMetricV30?: ReadonlyArray<NvdCveMetric>;
      cvssMetricV2?: ReadonlyArray<NvdCveMetric>;
    };
    weaknesses?: ReadonlyArray<{
      description?: ReadonlyArray<{ lang?: string; value?: string }>;
    }>;
    references?: ReadonlyArray<{ url?: string; tags?: ReadonlyArray<string> }>;
  };
}

interface NvdFeed {
  vulnerabilities?: ReadonlyArray<NvdCveRecord>;
}

export class NvdFeedsSource implements SourceAdapter {
  readonly id = 'nvd-feed';
  readonly displayName = 'NVD JSON Feeds 2.0';
  readonly trustTier = 'A' as const;
  readonly defaultPreset = 'core' as const;
  readonly requiresApiKey = false as const;

  private readonly feedUrl: string;
  private readonly metaUrl: string;
  // Carry the freshly-fetched META forward so syncOne records its sha256.
  private currentMetaSha256: string | undefined;

  constructor(options: NvdSourceOptions = {}) {
    this.feedUrl = options.url ?? `${NVD_FEED_BASE}/${DEFAULT_FEED}`;
    this.metaUrl = options.metaUrl ?? `${NVD_FEED_BASE}/${DEFAULT_META}`;
  }

  async checkForUpdates(ctx: SyncContext): Promise<UpdateCheckResult> {
    const res = await ctx.downloader.download({
      url: this.metaUrl,
      etag: ctx.lastEtag,
      lastModified: ctx.lastModified,
      signal: ctx.signal,
    });
    if (res === 'not_modified') return { changed: false };
    const meta = parseNvdMeta(new TextDecoder('utf-8').decode(res.body));
    const previousSha = ctx.lastVersion; // we store the previous META sha256 here
    if (previousSha && previousSha === meta.sha256) {
      return { changed: false, version: meta.sha256 };
    }
    this.currentMetaSha256 = meta.sha256;
    return {
      changed: true,
      etag: res.etag,
      lastModified: res.lastModified,
      version: meta.sha256,
      hint: { meta },
    };
  }

  async fetch(ctx: SyncContext, update: UpdateCheckResult): Promise<FetchResult> {
    const meta = (update.hint?.meta as NvdMeta | undefined) ?? undefined;
    const res = await ctx.downloader.download({
      url: this.feedUrl,
      signal: ctx.signal,
    });
    if (res === 'not_modified') {
      return { artifacts: [] };
    }
    if (meta) {
      // SHA-256 on the .json.gz body (not the decompressed payload), per NVD.
      assertSha256(res.body, meta.sha256);
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
    };
  }

  // eslint-disable-next-line @typescript-eslint/require-await -- AsyncIterable contract
  async *parse(_ctx: SyncContext, fetched: FetchResult): AsyncIterable<RawSourceRecord> {
    for (const artifact of fetched.artifacts) {
      const json = gunzipWithLimit(artifact.bytes);
      const text = new TextDecoder('utf-8', { fatal: false }).decode(json);
      const feed = JSON.parse(text) as NvdFeed;
      for (const rec of feed.vulnerabilities ?? []) {
        yield { sourceRecordId: rec.cve.id, raw: rec };
      }
    }
  }

  normalize(_ctx: SyncContext, record: RawSourceRecord): Promise<NormalizedEvidence[]> {
    const data = record.raw as NvdCveRecord;
    const cve = data.cve.id.toUpperCase();
    if (!cve.startsWith('CVE-')) return Promise.resolve([]);

    const description = pickEnglish(data.cve.descriptions);
    const cwes = (data.cve.weaknesses ?? [])
      .flatMap((w) => w.description ?? [])
      .map((d) => d.value)
      .filter((v): v is string => typeof v === 'string' && v.startsWith('CWE-'));
    const cvss = pickCvss(data.cve.metrics);

    return Promise.resolve<NormalizedEvidence[]>([
      {
        id: `nvd:${cve}`,
        advisoryId: cve,
        evidenceType: 'nvd_enrichment',
        observedAt: data.cve.published,
        sourceModifiedAt: data.cve.lastModified,
        confidence: 0.8, // NVD enrichment; CNA still wins per RFC 16.2
        summary: sanitizeText(description ?? cve),
        normalized: {
          cveId: cve,
          vulnStatus: data.cve.vulnStatus,
          cwes,
          cvss,
          references: data.cve.references,
          provenance: 'nvd',
        },
        advisoryDraft: {
          id: cve,
          canonicalId: cve,
          type: 'cve',
          description: description ? sanitizeText(description) : undefined,
          publishedAt: data.cve.published,
          modifiedAt: data.cve.lastModified,
          aliases: [],
        },
      },
    ]);
  }

  takeMetaSha256(): string | undefined {
    return this.currentMetaSha256;
  }
}

export function parseNvdMeta(text: string): NvdMeta {
  const out: Partial<NvdMeta> = {};
  for (const line of text.split(/\r?\n/)) {
    if (line === '') continue;
    const idx = line.indexOf(':');
    if (idx < 0) continue;
    const key = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (key === 'lastModifiedDate') out.lastModifiedDate = value;
    else if (key === 'sha256') out.sha256 = value.toLowerCase();
    else if (key === 'size') out.size = Number(value);
  }
  if (!out.sha256 || !out.lastModifiedDate || out.size === undefined) {
    throw new Error('invalid NVD META payload');
  }
  return out as NvdMeta;
}

function pickEnglish(
  descriptions: ReadonlyArray<NvdCveDescription> | undefined,
): string | undefined {
  if (!descriptions) return undefined;
  const en = descriptions.find((d) => (d.lang ?? '').toLowerCase().startsWith('en'));
  return en?.value ?? descriptions[0]?.value;
}

function pickCvss(metrics: NvdCveRecord['cve']['metrics']): NvdCvssData | undefined {
  const list = metrics?.cvssMetricV31 ?? metrics?.cvssMetricV30 ?? metrics?.cvssMetricV2 ?? [];
  const primary = list.find((m) => m.type === 'Primary') ?? list[0];
  return primary?.cvssData;
}
