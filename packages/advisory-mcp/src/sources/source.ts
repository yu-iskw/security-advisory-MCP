/**
 * Source adapter contract (RFC section 15.1).
 *
 * Adapters expose a uniform sync surface to the ingest pipeline:
 * checkForUpdates → fetch → parse → normalize. The pipeline runs each
 * stage in isolation so partial failures (e.g. one feed unavailable)
 * do not block other sources, and so individual stages can be unit-tested
 * with fixtures.
 *
 * Implementations MUST:
 *  - declare a stable, kebab-case `id`;
 *  - report `requiresApiKey: false` (the project rejects key-required feeds);
 *  - perform no network I/O in `parse` or `normalize`.
 */
export type TrustTier = 'A' | 'B' | 'C' | 'D';

export type SyncPreset = 'core' | 'packages' | 'ecosystems' | 'context' | 'research';

import type { Downloader } from '../ingest/downloader.js';

export interface SyncContext {
  /** Absolute cache directory dedicated to this source. */
  cacheDir: string;
  /** HTTPS downloader (URL-policy-checked). Tests inject a stub. */
  downloader: Downloader;
  /** Used to short-circuit if the server is shutting down. */
  signal: AbortSignal;
  /** Conditional-request validators from the last successful sync. */
  lastEtag?: string;
  lastModified?: string;
  lastVersion?: string;
}

export interface UpdateCheckResult {
  /** Whether `fetch` should run. */
  changed: boolean;
  /** Caller-opaque metadata to pass through to `fetch`. */
  hint?: Record<string, unknown>;
  /** Conditional-request validators stored on next success. */
  etag?: string;
  lastModified?: string;
  /** Optional declared version (e.g. CVE feed version). */
  version?: string;
}

export interface FetchedArtifact {
  url: string;
  contentType: string | undefined;
  bytes: Uint8Array;
  sha256: string;
  fetchedAt: string;
}

export interface FetchResult {
  artifacts: FetchedArtifact[];
  /** Conditional-request validators returned by the server, if any. */
  etag?: string;
  lastModified?: string;
}

export interface RawSourceRecord {
  /** Source-defined identifier (e.g. "CVE-2024-3094", "GHSA-xxxx"). */
  sourceRecordId?: string;
  /** Original raw payload as parsed JSON / structured value. */
  raw: unknown;
}

export interface NormalizedEvidence {
  /** Stable evidence row id (e.g. "kev:CVE-2024-3094"). */
  id: string;
  /** Canonical advisory id this evidence attaches to. */
  advisoryId: string;
  evidenceType: string;
  sourceModifiedAt?: string;
  observedAt?: string;
  confidence: number;
  summary: string;
  normalized: unknown;
  /** Pass-through to advisories on first sighting. */
  advisoryDraft?: AdvisoryDraft;
}

export interface AdvisoryDraft {
  id: string;
  canonicalId: string;
  type: string;
  title?: string;
  description?: string;
  publishedAt?: string;
  modifiedAt?: string;
  aliases?: string[];
}

export interface SourceAdapter {
  readonly id: string;
  readonly displayName: string;
  readonly trustTier: TrustTier;
  readonly defaultPreset: SyncPreset;
  readonly requiresApiKey: false;

  checkForUpdates(ctx: SyncContext): Promise<UpdateCheckResult>;
  fetch(ctx: SyncContext, update: UpdateCheckResult): Promise<FetchResult>;
  parse(ctx: SyncContext, fetched: FetchResult): AsyncIterable<RawSourceRecord>;
  normalize(ctx: SyncContext, record: RawSourceRecord): Promise<NormalizedEvidence[]>;
}
