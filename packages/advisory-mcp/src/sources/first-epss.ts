import { gunzipWithLimit } from '../ingest/decompressor.js';
import { nowIso } from '../util/time.js';

import type {
  NormalizedEvidence,
  RawSourceRecord,
  SourceAdapter,
  SyncContext,
  FetchResult,
  UpdateCheckResult,
} from './source.js';

/** FIRST EPSS daily bulk CSV (gzipped). RFC 6.3 / Tier A. */
const FIRST_EPSS_URL = 'https://epss.cyentia.com/epss_scores-current.csv.gz';
export const FIRST_EPSS_HOST = 'epss.cyentia.com';

const CVE_RE = /^CVE-\d{4}-\d{4,7}$/i;

interface EpssRow {
  cve: string;
  epss: number;
  percentile: number;
}

interface FirstEpssSourceOptions {
  url?: string;
}

export class FirstEpssSource implements SourceAdapter {
  readonly id = 'first-epss';
  readonly displayName = 'FIRST EPSS';
  readonly trustTier = 'A' as const;
  readonly defaultPreset = 'core' as const;
  readonly requiresApiKey = false as const;

  private readonly url: string;

  constructor(options: FirstEpssSourceOptions = {}) {
    this.url = options.url ?? FIRST_EPSS_URL;
  }

  // EPSS publishes a new bulk CSV daily; rely on conditional requests
  // and let the server return 304 when the daily file hasn't changed.
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
      const decompressed = decompressIfGzip(artifact.bytes);
      const text = new TextDecoder('utf-8', { fatal: false }).decode(decompressed);
      for (const row of parseEpssCsv(text)) {
        yield { sourceRecordId: row.cve, raw: row };
      }
    }
  }

  normalize(_ctx: SyncContext, record: RawSourceRecord): Promise<NormalizedEvidence[]> {
    const row = record.raw as EpssRow;
    return Promise.resolve<NormalizedEvidence[]>([
      {
        id: `epss:${row.cve}`,
        advisoryId: row.cve,
        evidenceType: 'epss_score',
        observedAt: undefined,
        confidence: 0.9,
        summary: `EPSS for ${row.cve}: probability=${row.epss.toFixed(5)}, percentile=${row.percentile.toFixed(5)}`,
        normalized: { cve: row.cve, epss: row.epss, percentile: row.percentile },
        advisoryDraft: {
          id: row.cve,
          canonicalId: row.cve,
          type: 'cve',
          aliases: [],
        },
      },
    ]);
  }
}

function decompressIfGzip(bytes: Uint8Array): Uint8Array {
  // gzip magic header 0x1f 0x8b
  if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) {
    return gunzipWithLimit(bytes);
  }
  return bytes;
}

export function parseEpssCsv(text: string): EpssRow[] {
  const rows: EpssRow[] = [];
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    if (line === '' || line.startsWith('#')) continue;
    // Skip the column header
    if (line.toLowerCase().startsWith('cve,')) continue;
    const parts = line.split(',');
    if (parts.length < 3) continue;
    const cve = (parts[0] ?? '').trim();
    if (!CVE_RE.test(cve)) continue;
    const epss = Number((parts[1] ?? '').trim());
    const percentile = Number((parts[2] ?? '').trim());
    if (!Number.isFinite(epss) || !Number.isFinite(percentile)) continue;
    if (epss < 0 || epss > 1 || percentile < 0 || percentile > 1) continue;
    rows.push({ cve: cve.toUpperCase(), epss, percentile });
  }
  return rows;
}
