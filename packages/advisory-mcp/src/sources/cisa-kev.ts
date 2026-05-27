import { z } from 'zod';

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

/** Public CISA KEV catalog endpoint. RFC 6.3 / Tier A. */
const CISA_KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

export const CISA_KEV_HOST = 'www.cisa.gov';

const KevEntrySchema = z.object({
  cveID: z.string().min(1),
  vendorProject: z.string().optional(),
  product: z.string().optional(),
  vulnerabilityName: z.string().optional(),
  dateAdded: z.string().optional(),
  shortDescription: z.string().optional(),
  requiredAction: z.string().optional(),
  dueDate: z.string().optional(),
  knownRansomwareCampaignUse: z.string().optional(),
  notes: z.string().optional(),
});

const KevCatalogSchema = z.object({
  catalogVersion: z.string().optional(),
  dateReleased: z.string().optional(),
  vulnerabilities: z.array(KevEntrySchema),
});

type KevEntry = z.infer<typeof KevEntrySchema>;

interface KevSourceOptions {
  url?: string;
}

export class CisaKevSource implements SourceAdapter {
  readonly id = 'cisa-kev';
  readonly displayName = 'CISA Known Exploited Vulnerabilities';
  readonly trustTier = 'A' as const;
  readonly defaultPreset = 'core' as const;
  readonly requiresApiKey = false as const;

  private readonly url: string;

  constructor(options: KevSourceOptions = {}) {
    this.url = options.url ?? CISA_KEV_URL;
  }

  // KEV does not publish a separate metadata endpoint; we always issue a
  // conditional request and let the server's 304 short-circuit when nothing
  // has changed. `changed: true` means "ask fetch() to attempt the conditional
  // request"; fetch() returns no artifacts when the response is 304.
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

  // eslint-disable-next-line @typescript-eslint/require-await -- contract is async iterable; future adapters stream
  async *parse(_ctx: SyncContext, fetched: FetchResult): AsyncIterable<RawSourceRecord> {
    for (const artifact of fetched.artifacts) {
      const text = new TextDecoder('utf-8', { fatal: false }).decode(artifact.bytes);
      const parsed = KevCatalogSchema.parse(JSON.parse(text));
      for (const entry of parsed.vulnerabilities) {
        yield { sourceRecordId: entry.cveID, raw: entry };
      }
    }
  }

  normalize(_ctx: SyncContext, record: RawSourceRecord): Promise<NormalizedEvidence[]> {
    const entry = KevEntrySchema.parse(record.raw);
    const summary = sanitizeText(
      `${entry.vulnerabilityName ?? entry.cveID}: ${entry.shortDescription ?? ''}`,
    );
    const observedAt = entry.dateAdded ? `${entry.dateAdded}T00:00:00.000Z` : undefined;

    return Promise.resolve<NormalizedEvidence[]>([
      {
        id: `kev:${entry.cveID}`,
        advisoryId: entry.cveID,
        evidenceType: 'known_exploited',
        observedAt,
        confidence: 0.95,
        summary,
        normalized: normalizedKev(entry),
        advisoryDraft: {
          id: entry.cveID,
          canonicalId: entry.cveID,
          type: 'cve',
          title: entry.vulnerabilityName,
          description: entry.shortDescription,
          publishedAt: observedAt,
          aliases: [],
        },
      },
    ]);
  }
}

function normalizedKev(entry: KevEntry): Record<string, unknown> {
  return {
    cveID: entry.cveID,
    vendorProject: entry.vendorProject,
    product: entry.product,
    dateAdded: entry.dateAdded,
    dueDate: entry.dueDate,
    requiredAction: entry.requiredAction,
    knownRansomwareCampaignUse: entry.knownRansomwareCampaignUse,
    notes: entry.notes,
  };
}
