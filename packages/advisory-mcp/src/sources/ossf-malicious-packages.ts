import { gunzipWithLimit } from '../ingest/decompressor.js';
import { readTar, type TarEntry } from '../ingest/tar.js';
import { sanitizeText } from '../security/content-sanitizer.js';
import { canonicalEcosystem } from '../util/ecosystems.js';
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
 * OpenSSF malicious-packages (Tier B, packages preset). Same archive format
 * as the OSV adapter — codeload.github.com tarball of OSV-format JSON. The
 * difference is that each record represents a *malicious* package (typo-
 * squat, post-install supply-chain attack, etc.), not a vulnerable one.
 *
 * Surfaced as `malicious_package` evidence with its own advisoryDraft so the
 * analyze_package tool can flag any matching package immediately.
 */
const OSSF_MALICIOUS_URL = 'https://codeload.github.com/ossf/malicious-packages/tar.gz/main';
export const OSSF_MALICIOUS_HOST = 'codeload.github.com';

const MAL_FILENAME_RE = /(MAL-[\w-]+|GHSA-[\w-]+)\.json$/i;

interface OsvMalRecord {
  id: string;
  modified?: string;
  published?: string;
  summary?: string;
  details?: string;
  affected?: ReadonlyArray<{
    package?: { ecosystem?: string; name?: string; purl?: string };
  }>;
}

interface OssfMaliciousSourceOptions {
  url?: string;
}

export class OssfMaliciousPackagesSource implements SourceAdapter {
  readonly id = 'ossf-malicious-packages';
  readonly displayName = 'OpenSSF Malicious Packages';
  readonly trustTier = 'B' as const;
  readonly defaultPreset = 'packages' as const;
  readonly requiresApiKey = false as const;

  private readonly url: string;

  constructor(options: OssfMaliciousSourceOptions = {}) {
    this.url = options.url ?? OSSF_MALICIOUS_URL;
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
        yield* this.parseEntry(entry);
      }
    }
  }

  normalize(_ctx: SyncContext, record: RawSourceRecord): Promise<NormalizedEvidence[]> {
    const data = record.raw as OsvMalRecord;
    const id = data.id.toUpperCase();
    const affected = (data.affected ?? [])
      .map((a) => a.package)
      .filter((p): p is NonNullable<typeof p> => p !== undefined && typeof p.name === 'string')
      .map((p) => ({
        ecosystem: canonicalEcosystem(p.ecosystem ?? '') ?? (p.ecosystem ?? '').toLowerCase(),
        name: p.name ?? '',
        purl: p.purl,
      }));

    return Promise.resolve<NormalizedEvidence[]>([
      {
        id: `malicious:${id}`,
        advisoryId: id,
        evidenceType: 'malicious_package',
        observedAt: data.published,
        sourceModifiedAt: data.modified,
        confidence: 0.9,
        summary: sanitizeText(data.summary ?? `Malicious package ${id}`),
        normalized: {
          maliciousId: id,
          affected,
          provenance: 'ossf-malicious',
        },
        advisoryDraft: {
          id,
          canonicalId: id,
          type: 'malicious_package',
          title: sanitizeText(data.summary ?? `Malicious package ${id}`),
          description: sanitizeText(data.details ?? ''),
          publishedAt: data.published,
          modifiedAt: data.modified,
          aliases: [],
        },
      },
    ]);
  }

  private *parseEntry(entry: TarEntry): Generator<RawSourceRecord> {
    const match = MAL_FILENAME_RE.exec(entry.path);
    if (!match?.[1]) return;
    const text = new TextDecoder('utf-8', { fatal: false }).decode(entry.content);
    let parsed: OsvMalRecord;
    try {
      parsed = JSON.parse(text) as OsvMalRecord;
    } catch {
      return;
    }
    if (typeof parsed.id !== 'string') return;
    yield { sourceRecordId: match[1].toUpperCase(), raw: parsed };
  }
}
