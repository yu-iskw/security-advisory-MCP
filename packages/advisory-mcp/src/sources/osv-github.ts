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
 * github/advisory-database publishes GHSA advisories in OSV JSON format
 * (RFC 6.3 / Tier B). Each advisory has a stable `id` (e.g. GHSA-xxxx-xxxx-xxxx)
 * and lists CVE aliases plus `affected[]` package ranges, which the merger
 * combines with KEV / CVE record / NVD evidence to enable analyze_package.
 *
 * One adapter covers both M20 (OSV) and M21 (GHSA): the data is the same.
 */
const OSV_GITHUB_URL =
  'https://codeload.github.com/github/advisory-database/tar.gz/main';
export const OSV_GITHUB_HOST = 'codeload.github.com';

const GHSA_FILENAME_RE = /(GHSA-[\w-]+)\.json$/i;

interface OsvSeverity {
  type?: string;
  score?: string;
}

interface OsvRangeEventJson {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

interface OsvRange {
  type?: string;
  events?: ReadonlyArray<OsvRangeEventJson>;
}

interface OsvAffectedPackage {
  package?: { ecosystem?: string; name?: string; purl?: string };
  ranges?: ReadonlyArray<OsvRange>;
  versions?: ReadonlyArray<string>;
}

interface OsvRecord {
  id: string;
  modified?: string;
  published?: string;
  withdrawn?: string;
  aliases?: ReadonlyArray<string>;
  summary?: string;
  details?: string;
  severity?: ReadonlyArray<OsvSeverity>;
  affected?: ReadonlyArray<OsvAffectedPackage>;
  database_specific?: { severity?: string };
}

interface OsvSourceOptions {
  url?: string;
}

export class OsvGithubSource implements SourceAdapter {
  readonly id = 'osv';
  readonly displayName = 'OSV / GitHub Advisory Database';
  readonly trustTier = 'B' as const;
  readonly defaultPreset = 'packages' as const;
  readonly requiresApiKey = false as const;

  private readonly url: string;

  constructor(options: OsvSourceOptions = {}) {
    this.url = options.url ?? OSV_GITHUB_URL;
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
    const data = record.raw as OsvRecord;
    const ghsa = data.id.toUpperCase();
    const cveAliases = (data.aliases ?? []).filter((a) => a.toUpperCase().startsWith('CVE-'));

    // Canonical id selection (RFC 16.1): CVE preferred when present, else GHSA.
    const canonicalId = cveAliases[0] ?? ghsa;
    const aliases = [ghsa, ...cveAliases].filter((id) => id !== canonicalId);

    const summary = sanitizeText(data.summary ?? '', { maxChars: 256 });
    const details = sanitizeText(data.details ?? '');
    const affectedPackages = normalizeAffected(data.affected ?? []);

    return Promise.resolve<NormalizedEvidence[]>([
      {
        id: `osv:${ghsa}`,
        advisoryId: canonicalId,
        evidenceType: 'osv_record',
        observedAt: data.published,
        sourceModifiedAt: data.modified,
        confidence: 0.85,
        summary: summary || ghsa,
        normalized: {
          ghsaId: ghsa,
          cveAliases,
          severity: data.database_specific?.severity,
          affected: affectedPackages,
          provenance: 'osv',
        },
        advisoryDraft: {
          id: canonicalId,
          canonicalId,
          type: cveAliases.length > 0 ? 'cve' : 'ghsa',
          title: summary,
          description: details,
          publishedAt: data.published,
          modifiedAt: data.modified,
          aliases,
        },
      },
    ]);
  }

  private *parseEntry(entry: TarEntry): Generator<RawSourceRecord> {
    const match = GHSA_FILENAME_RE.exec(entry.path);
    if (!match?.[1]) return;
    const text = new TextDecoder('utf-8', { fatal: false }).decode(entry.content);
    let parsed: OsvRecord;
    try {
      parsed = JSON.parse(text) as OsvRecord;
    } catch {
      return;
    }
    if (typeof parsed.id !== 'string') return;
    yield { sourceRecordId: match[1].toUpperCase(), raw: parsed };
  }
}

interface NormalizedAffected {
  ecosystem: string;
  name: string;
  purl?: string;
  ranges: ReadonlyArray<{ introduced?: string; fixed?: string; lastAffected?: string }>;
  versions: ReadonlyArray<string>;
}

function normalizeAffected(
  list: ReadonlyArray<OsvAffectedPackage>,
): NormalizedAffected[] {
  const out: NormalizedAffected[] = [];
  for (const item of list) {
    const pkg = item.package;
    if (!pkg?.name || !pkg.ecosystem) continue;
    const canonical = canonicalEcosystem(pkg.ecosystem) ?? pkg.ecosystem.toLowerCase();
    const ranges: { introduced?: string; fixed?: string; lastAffected?: string }[] = [];
    for (const range of item.ranges ?? []) {
      const collapsed = collapseEvents(range.events ?? []);
      if (collapsed.length > 0) ranges.push(...collapsed);
    }
    out.push({
      ecosystem: canonical,
      name: pkg.name,
      purl: pkg.purl,
      ranges,
      versions: item.versions ?? [],
    });
  }
  return out;
}

function collapseEvents(
  events: ReadonlyArray<OsvRangeEventJson>,
): { introduced?: string; fixed?: string; lastAffected?: string }[] {
  const out: { introduced?: string; fixed?: string; lastAffected?: string }[] = [];
  let current: { introduced?: string; fixed?: string; lastAffected?: string } = {};
  for (const ev of events) {
    if (ev.introduced !== undefined) {
      if (current.introduced !== undefined) {
        out.push(current);
        current = {};
      }
      current.introduced = ev.introduced;
    }
    if (ev.fixed !== undefined) current.fixed = ev.fixed;
    if (ev.last_affected !== undefined) current.lastAffected = ev.last_affected;
  }
  if (Object.keys(current).length > 0) out.push(current);
  return out;
}
