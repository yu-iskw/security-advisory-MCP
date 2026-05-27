import { gunzipWithLimit } from '../ingest/decompressor.js';
import { readTar, type TarEntry } from '../ingest/tar.js';
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
 * CISA Vulnrichment (RFC 6.3 / Tier A). The repository archive ships every
 * branch tarball at codeload.github.com.
 */
const CISA_VULNRICHMENT_URL =
  'https://codeload.github.com/cisagov/vulnrichment/tar.gz/develop';
export const CISA_VULNRICHMENT_HOST = 'codeload.github.com';

const CVE_FILENAME_RE = /(CVE-\d{4}-\d{4,7})\.json$/i;

interface VulnrichmentSourceOptions {
  url?: string;
}

/**
 * The shape of a CISA Vulnrichment-enriched CVE record. CVE Record Format 5.1
 * with `containers.adp[]` carrying CISA's enrichment (SSVC + CVSS + CWE).
 * We parse only the fields we surface; unknown fields are passed through in
 * `normalized` so the merger (M16) can re-inspect them.
 */
interface VulnrichmentCveRecord {
  cveMetadata?: { cveId?: string };
  containers?: {
    cna?: unknown;
    adp?: ReadonlyArray<{
      providerMetadata?: { shortName?: string };
      title?: string;
      metrics?: ReadonlyArray<unknown>;
      problemTypes?: ReadonlyArray<{
        descriptions?: ReadonlyArray<{ cweId?: string; description?: string }>;
      }>;
    }>;
  };
}

export class CisaVulnrichmentSource implements SourceAdapter {
  readonly id = 'cisa-vulnrichment';
  readonly displayName = 'CISA Vulnrichment';
  readonly trustTier = 'A' as const;
  readonly defaultPreset = 'core' as const;
  readonly requiresApiKey = false as const;

  private readonly url: string;

  constructor(options: VulnrichmentSourceOptions = {}) {
    this.url = options.url ?? CISA_VULNRICHMENT_URL;
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
      const entries = readTar(tarBytes);
      for (const entry of entries) {
        yield* this.parseEntry(entry);
      }
    }
  }

  normalize(_ctx: SyncContext, record: RawSourceRecord): Promise<NormalizedEvidence[]> {
    const cve = (record.sourceRecordId ?? '').toUpperCase();
    if (!cve.startsWith('CVE-')) return Promise.resolve([]);
    const data = record.raw as VulnrichmentCveRecord;
    const adp = data.containers?.adp ?? [];
    const cisaEntry =
      adp.find((a) => a.providerMetadata?.shortName === 'CISA-ADP') ?? adp[0];
    if (!cisaEntry) return Promise.resolve([]);

    const cwes = (cisaEntry.problemTypes ?? [])
      .flatMap((p) => p.descriptions ?? [])
      .map((d) => d.cweId)
      .filter((c): c is string => typeof c === 'string');
    const metrics = (cisaEntry.metrics ?? []) as readonly Record<string, unknown>[];
    const ssvcContent = metrics.find(
      (m) =>
        typeof m.other === 'object' &&
        m.other !== null &&
        (m.other as { type?: unknown }).type === 'ssvc',
    );
    const cvss = metrics.find((m) =>
      Object.keys(m).some((k) => k.toLowerCase().startsWith('cvssv')),
    );

    const summary = sanitizeText(
      cisaEntry.title ??
        `CISA-ADP enrichment for ${cve}` + (cwes.length > 0 ? ` (${cwes.join(', ')})` : ''),
    );

    return Promise.resolve<NormalizedEvidence[]>([
      {
        id: `vulnrichment:${cve}`,
        advisoryId: cve,
        evidenceType: 'cisa_adp_enrichment',
        confidence: 0.85, // ADP — defer to CNA in the merger (RFC 16.2)
        summary,
        normalized: {
          cveId: cve,
          providerShortName: cisaEntry.providerMetadata?.shortName,
          cwes,
          ssvc: ssvcContent,
          cvss,
          provenance: 'adp', // signal for the merger
        },
        advisoryDraft: {
          id: cve,
          canonicalId: cve,
          type: 'cve',
          aliases: [],
        },
      },
    ]);
  }

  private *parseEntry(entry: TarEntry): Generator<RawSourceRecord> {
    const match = CVE_FILENAME_RE.exec(entry.path);
    if (!match?.[1]) return;
    const text = new TextDecoder('utf-8', { fatal: false }).decode(entry.content);
    let parsed: VulnrichmentCveRecord;
    try {
      parsed = JSON.parse(text) as VulnrichmentCveRecord;
    } catch {
      return; // skip malformed files; they're logged at sync level
    }
    yield {
      sourceRecordId: match[1].toUpperCase(),
      raw: parsed,
    };
  }
}
