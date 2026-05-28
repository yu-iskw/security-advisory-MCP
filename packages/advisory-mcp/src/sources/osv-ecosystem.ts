import { gunzipWithLimit } from '../ingest/decompressor.js';
import { readTar, type TarEntry } from '../ingest/tar.js';
import { sanitizeText } from '../security/content-sanitizer.js';
import { canonicalEcosystem } from '../util/ecosystems.js';
import { nowIso } from '../util/time.js';

import type {
  NormalizedEvidence,
  RawSourceRecord,
  SourceAdapter,
  SyncPreset,
  SyncContext,
  FetchResult,
  TrustTier,
  UpdateCheckResult,
} from './source.js';

/**
 * Generic OSV-tarball ecosystem source. Used to surface RustSec, Go vulndb,
 * and PyPA advisory databases — all of which publish their data as OSV-format
 * JSON in a GitHub repository (RFC 6.3 / Tier B, ecosystems preset).
 *
 * Each instance is parameterized with the upstream URL, the source id, and
 * a filename regex (most repos use `.json` directly; RustSec uses `.md` for
 * details + `.toml` for metadata so we look for matching ids in the path).
 */

interface OsvRecord {
  id: string;
  modified?: string;
  published?: string;
  aliases?: ReadonlyArray<string>;
  summary?: string;
  details?: string;
  database_specific?: { severity?: string };
  affected?: ReadonlyArray<{
    package?: { ecosystem?: string; name?: string; purl?: string };
    ranges?: ReadonlyArray<{
      events?: ReadonlyArray<{ introduced?: string; fixed?: string; last_affected?: string }>;
    }>;
    versions?: ReadonlyArray<string>;
  }>;
}

interface OsvEcosystemSourceConfig {
  id: string;
  displayName: string;
  url: string;
  /** Regex applied to each tar entry's path. The first capture group is the id. */
  recordPathRe: RegExp;
  /** Tier B by default; subclasses can override. */
  trustTier?: TrustTier;
  preset?: SyncPreset;
}

class OsvEcosystemSource implements SourceAdapter {
  readonly id: string;
  readonly displayName: string;
  readonly trustTier: TrustTier;
  readonly defaultPreset: SyncPreset;
  readonly requiresApiKey = false as const;

  private readonly url: string;
  private readonly recordPathRe: RegExp;

  constructor(config: OsvEcosystemSourceConfig) {
    this.id = config.id;
    this.displayName = config.displayName;
    this.url = config.url;
    this.recordPathRe = config.recordPathRe;
    this.trustTier = config.trustTier ?? 'B';
    this.defaultPreset = config.preset ?? 'ecosystems';
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
    const recordId = data.id.toUpperCase();
    const cveAliases = (data.aliases ?? []).filter((a) => a.toUpperCase().startsWith('CVE-'));
    const canonicalId = cveAliases[0] ?? recordId;
    const aliases = [recordId, ...cveAliases].filter((id) => id !== canonicalId);

    return Promise.resolve<NormalizedEvidence[]>([
      {
        id: `${this.id}:${recordId}`,
        advisoryId: canonicalId,
        evidenceType: 'osv_record',
        observedAt: data.published,
        sourceModifiedAt: data.modified,
        confidence: 0.85,
        summary: sanitizeText(data.summary ?? recordId, { maxChars: 256 }),
        normalized: {
          recordId,
          cveAliases,
          severity: data.database_specific?.severity,
          affected: normalizeAffected(data.affected ?? []),
          provenance: 'osv',
        },
        advisoryDraft: {
          id: canonicalId,
          canonicalId,
          type: cveAliases.length > 0 ? 'cve' : 'ecosystem',
          title: sanitizeText(data.summary ?? '', { maxChars: 256 }),
          description: sanitizeText(data.details ?? ''),
          publishedAt: data.published,
          modifiedAt: data.modified,
          aliases,
        },
      },
    ]);
  }

  private *parseEntry(entry: TarEntry): Generator<RawSourceRecord> {
    const match = this.recordPathRe.exec(entry.path);
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

interface OsvRangeEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
}

interface NormalizedRange {
  introduced?: string;
  fixed?: string;
  lastAffected?: string;
}

function normalizeAffected(
  list: ReadonlyArray<NonNullable<OsvRecord['affected']>[number]>,
): NormalizedAffected[] {
  const out: NormalizedAffected[] = [];
  for (const item of list) {
    const pkg = item.package;
    if (!pkg?.name || !pkg.ecosystem) continue;
    const canonical = canonicalEcosystem(pkg.ecosystem) ?? pkg.ecosystem.toLowerCase();
    const ranges: NormalizedRange[] = [];
    for (const range of item.ranges ?? []) {
      ranges.push(...collapseRangeEvents(range.events ?? []));
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

function collapseRangeEvents(events: ReadonlyArray<OsvRangeEvent>): NormalizedRange[] {
  const out: NormalizedRange[] = [];
  let current: NormalizedRange = {};
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

export function createRustSecSource(): SourceAdapter {
  return new OsvEcosystemSource({
    id: 'rustsec',
    displayName: 'RustSec advisory-db',
    url: 'https://codeload.github.com/rustsec/advisory-db/tar.gz/main',
    recordPathRe: /(RUSTSEC-\d{4}-\d{4})\.json$/i,
  });
}

export function createPypaSource(): SourceAdapter {
  return new OsvEcosystemSource({
    id: 'pypa',
    displayName: 'PyPA advisory-database',
    url: 'https://codeload.github.com/pypa/advisory-database/tar.gz/main',
    recordPathRe: /(PYSEC-\d{4}-\d+)\.json$/i,
  });
}

export function createGoVulnDbSource(): SourceAdapter {
  return new OsvEcosystemSource({
    id: 'go-vulndb',
    displayName: 'Go Vulnerability Database',
    url: 'https://codeload.github.com/golang/vulndb/tar.gz/master',
    recordPathRe: /(GO-\d{4}-\d+)\.json$/i,
  });
}
