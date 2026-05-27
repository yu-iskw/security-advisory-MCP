import { AdvisoryRepository } from '../store/repositories/advisory-repository.js';
import { EvidenceRepository } from '../store/repositories/evidence-repository.js';
import { SourceStateRepository } from '../store/repositories/source-state-repository.js';
import { SearchIndex } from '../store/search-index.js';
import { nowIso } from '../util/time.js';

import type { Downloader } from './downloader.js';
import type { SourceAdapter, SyncContext } from '../sources/source.js';
import type { DatabaseHandle } from '../store/db.js';

interface SyncEngineDeps {
  db: DatabaseHandle;
  downloader: Downloader;
  cacheDir: string;
  signal?: AbortSignal;
}

interface SyncSourceResult {
  source: string;
  status: 'success' | 'unchanged' | 'error';
  records?: number;
  error?: string;
  durationMs: number;
}

export class SyncEngine {
  private readonly advisoryRepo: AdvisoryRepository;
  private readonly evidenceRepo: EvidenceRepository;
  private readonly stateRepo: SourceStateRepository;
  private readonly search: SearchIndex;

  constructor(private readonly deps: SyncEngineDeps) {
    this.advisoryRepo = new AdvisoryRepository(deps.db);
    this.evidenceRepo = new EvidenceRepository(deps.db);
    this.stateRepo = new SourceStateRepository(deps.db);
    this.search = new SearchIndex(deps.db);
  }

  async syncOne(adapter: SourceAdapter): Promise<SyncSourceResult> {
    const startedAt = nowIso();
    const startNs = process.hrtime.bigint();
    const previous = this.stateRepo.findBySource(adapter.id);

    this.stateRepo.upsert({
      source: adapter.id,
      enabled: true,
      preset: adapter.defaultPreset,
      status: 'syncing',
      lastSyncStartedAt: startedAt,
    });

    const ctx: SyncContext = {
      cacheDir: this.deps.cacheDir,
      downloader: this.deps.downloader,
      signal: this.deps.signal ?? new AbortController().signal,
      lastEtag: previous?.etag ?? undefined,
      lastModified: previous?.lastModified ?? undefined,
      lastVersion: previous?.version ?? undefined,
    };

    try {
      const update = await adapter.checkForUpdates(ctx);
      if (!update.changed) {
        return this.finish(adapter, 'unchanged', startedAt, startNs, 0, undefined, update);
      }

      const fetched = await adapter.fetch(ctx, update);
      if (fetched.artifacts.length === 0) {
        // 304 / not_modified: preserve previous validators, mark unchanged.
        return this.finish(adapter, 'unchanged', startedAt, startNs, 0, undefined, {
          ...update,
          etag: fetched.etag ?? update.etag,
          lastModified: fetched.lastModified ?? update.lastModified,
        });
      }

      let records = 0;
      const fetchedAt = fetched.artifacts[0]?.fetchedAt ?? nowIso();
      for await (const record of adapter.parse(ctx, fetched)) {
        const evidences = await adapter.normalize(ctx, record);
        records += this.applyRecord(adapter, evidences, fetchedAt);
      }

      return this.finish(adapter, 'success', startedAt, startNs, records, undefined, {
        ...update,
        etag: fetched.etag ?? update.etag,
        lastModified: fetched.lastModified ?? update.lastModified,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return this.finish(adapter, 'error', startedAt, startNs, 0, message);
    }
  }

  async syncMany(adapters: readonly SourceAdapter[]): Promise<SyncSourceResult[]> {
    const out: SyncSourceResult[] = [];
    for (const a of adapters) out.push(await this.syncOne(a));
    return out;
  }

  private applyRecord(
    adapter: SourceAdapter,
    evidences: { id: string; advisoryId: string; evidenceType: string; observedAt?: string; sourceModifiedAt?: string; confidence: number; summary: string; normalized: unknown; advisoryDraft?: { id: string; canonicalId: string; type: string; title?: string; description?: string; publishedAt?: string; modifiedAt?: string; aliases?: string[] } }[],
    fetchedAt: string,
  ): number {
    const indexedAdvisoryIds = new Set<string>();
    let written = 0;
    for (const ev of evidences) {
      if (ev.advisoryDraft) {
        this.advisoryRepo.upsert({
          ...ev.advisoryDraft,
          mergedJson: JSON.stringify(ev.advisoryDraft),
        });
        indexedAdvisoryIds.add(ev.advisoryId);
      }
      this.evidenceRepo.upsert({
        id: ev.id,
        advisoryId: ev.advisoryId,
        source: adapter.id,
        type: ev.evidenceType,
        fetchedAt,
        observedAt: ev.observedAt,
        sourceModifiedAt: ev.sourceModifiedAt,
        confidence: ev.confidence,
        trustTier: adapter.trustTier,
        summary: ev.summary,
        normalizedJson: JSON.stringify(ev.normalized),
      });
      written++;
    }
    for (const advisoryId of indexedAdvisoryIds) {
      this.reindexAdvisory(advisoryId);
    }
    return written;
  }

  // Re-index the FTS row from the current DB state. Filter facets (severity,
  // hasFix) come from the merger in M16; knownExploited is derivable now from
  // KEV evidence rows.
  private reindexAdvisory(advisoryId: string): void {
    const advisory = this.advisoryRepo.findById(advisoryId);
    if (!advisory) return;
    const evidenceRows = this.evidenceRepo.findByAdvisoryId(advisoryId);
    const knownExploited = evidenceRows.some(
      (e) => e.source === 'cisa-kev' && e.type === 'known_exploited',
    );
    this.search.indexAdvisory({
      id: advisory.id,
      title: advisory.title ?? undefined,
      description: advisory.description ?? undefined,
      aliases: this.advisoryRepo.aliasesFor(advisoryId),
      knownExploited,
    });
  }

  private finish(
    adapter: SourceAdapter,
    status: SyncSourceResult['status'],
    startedAt: string,
    startNs: bigint,
    records: number,
    error?: string,
    validators?: { etag?: string; lastModified?: string; version?: string },
  ): SyncSourceResult {
    const completedAt = nowIso();
    const durationMs = Number((process.hrtime.bigint() - startNs) / 1_000_000n);

    this.stateRepo.upsert({
      source: adapter.id,
      enabled: true,
      preset: adapter.defaultPreset,
      status: status === 'unchanged' ? 'success' : status,
      lastSyncStartedAt: startedAt,
      lastSyncCompletedAt: completedAt,
      lastSuccessAt: status === 'error' ? undefined : completedAt,
      lastError: error,
      etag: validators?.etag,
      lastModified: validators?.lastModified,
      version: validators?.version,
    });

    return { source: adapter.id, status, records, error, durationMs };
  }
}
