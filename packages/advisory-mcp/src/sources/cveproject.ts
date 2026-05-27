import { gunzipWithLimit } from '../ingest/decompressor.js';
import { readTar, type TarEntry } from '../ingest/tar.js';
import { sanitizeText } from '../security/content-sanitizer.js';
import { LIMITS } from '../security/limits.js';
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
 * Canonical CVE List v5 (RFC 6.3 / Tier A). The repository is published as a
 * git tarball at codeload.github.com. The default URL points at the develop
 * branch; it is multi-GB in practice and intended to be overridden by the
 * user (config.maxDownloadBytes / a tagged daily release URL).
 */
const CVEPROJECT_URL = 'https://codeload.github.com/CVEProject/cvelistV5/tar.gz/main';
export const CVEPROJECT_HOST = 'codeload.github.com';

const CVE_FILENAME_RE = /(CVE-\d{4}-\d{4,7})\.json$/i;

interface CveDescription {
  lang?: string;
  value?: string;
}

interface CveCnaContainer {
  title?: string;
  descriptions?: ReadonlyArray<CveDescription>;
  affected?: ReadonlyArray<unknown>;
  metrics?: ReadonlyArray<Record<string, unknown>>;
  problemTypes?: ReadonlyArray<{
    descriptions?: ReadonlyArray<{ cweId?: string; description?: string }>;
  }>;
  references?: ReadonlyArray<{ url?: string; tags?: ReadonlyArray<string> }>;
}

interface CveRecord {
  cveMetadata?: {
    cveId?: string;
    datePublished?: string;
    dateUpdated?: string;
    state?: string;
  };
  containers?: {
    cna?: CveCnaContainer;
    adp?: ReadonlyArray<unknown>;
  };
}

interface CveProjectSourceOptions {
  url?: string;
}

export class CveProjectSource implements SourceAdapter {
  readonly id = 'cveproject';
  readonly displayName = 'CVE Project (cvelistV5)';
  readonly trustTier = 'A' as const;
  readonly defaultPreset = 'core' as const;
  readonly requiresApiKey = false as const;

  private readonly url: string;

  constructor(options: CveProjectSourceOptions = {}) {
    this.url = options.url ?? CVEPROJECT_URL;
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
      // Allow the full default download cap; users can raise it via config.
      maxBytes: LIMITS.defaultMaxDownloadBytes,
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
        yield* this.parseEntry(entry);
      }
    }
  }

  normalize(_ctx: SyncContext, record: RawSourceRecord): Promise<NormalizedEvidence[]> {
    const cve = (record.sourceRecordId ?? '').toUpperCase();
    if (!cve.startsWith('CVE-')) return Promise.resolve([]);
    const data = record.raw as CveRecord;
    const cna = data.containers?.cna;
    if (!cna) return Promise.resolve([]);

    const description = pickEnglishDescription(cna.descriptions);
    const cwes = (cna.problemTypes ?? [])
      .flatMap((p) => p.descriptions ?? [])
      .map((d) => d.cweId)
      .filter((c): c is string => typeof c === 'string');
    const metrics = cna.metrics ?? [];
    const cvss = metrics.find((m) =>
      Object.keys(m).some((k) => k.toLowerCase().startsWith('cvssv')),
    );

    const title = sanitizeText(cna.title ?? cve, { maxChars: 256 });
    const sanitizedDescription = sanitizeText(description ?? '');

    return Promise.resolve<NormalizedEvidence[]>([
      {
        id: `cveproject:${cve}`,
        advisoryId: cve,
        evidenceType: 'cve_record',
        observedAt: data.cveMetadata?.datePublished,
        sourceModifiedAt: data.cveMetadata?.dateUpdated,
        confidence: 0.95, // CNA-authored data has the highest precedence
        summary: title,
        normalized: {
          cveId: cve,
          state: data.cveMetadata?.state,
          cwes,
          cvss,
          affected: cna.affected,
          references: cna.references,
          provenance: 'cna', // signal for the merger (RFC 16.2)
        },
        advisoryDraft: {
          id: cve,
          canonicalId: cve,
          type: 'cve',
          title,
          description: sanitizedDescription,
          publishedAt: data.cveMetadata?.datePublished,
          modifiedAt: data.cveMetadata?.dateUpdated,
          aliases: [],
        },
      },
    ]);
  }

  private *parseEntry(entry: TarEntry): Generator<RawSourceRecord> {
    const match = CVE_FILENAME_RE.exec(entry.path);
    if (!match?.[1]) return;
    const text = new TextDecoder('utf-8', { fatal: false }).decode(entry.content);
    let parsed: CveRecord;
    try {
      parsed = JSON.parse(text) as CveRecord;
    } catch {
      return;
    }
    yield { sourceRecordId: match[1].toUpperCase(), raw: parsed };
  }
}

function pickEnglishDescription(
  descriptions: ReadonlyArray<CveDescription> | undefined,
): string | undefined {
  if (!descriptions) return undefined;
  const en = descriptions.find((d) => (d.lang ?? '').toLowerCase().startsWith('en'));
  return en?.value ?? descriptions[0]?.value;
}
