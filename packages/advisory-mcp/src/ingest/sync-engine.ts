import { AdvisoryRepository } from '../store/repositories/advisory-repository.js';
import { EvidenceRepository } from '../store/repositories/evidence-repository.js';
import { SourceStateRepository } from '../store/repositories/source-state-repository.js';
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

  constructor(private readonly deps: SyncEngineDeps) {
    this.advisoryRepo = new AdvisoryRepository(deps.db);
    this.evidenceRepo = new EvidenceRepository(deps.db);
    this.stateRepo = new SourceStateRepository(deps.db);
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
      for await (const record of adapter.parse(ctx, fetched)) {
        const evidences = await adapter.normalize(ctx, record);
        for (const ev of evidences) {
          if (ev.advisoryDraft) {
            this.advisoryRepo.upsert({
              ...ev.advisoryDraft,
              mergedJson: JSON.stringify(ev.advisoryDraft),
            });
          }
          this.evidenceRepo.upsert({
            id: ev.id,
            advisoryId: ev.advisoryId,
            source: adapter.id,
            type: ev.evidenceType,
            fetchedAt: fetched.artifacts[0]?.fetchedAt ?? nowIso(),
            observedAt: ev.observedAt,
            sourceModifiedAt: ev.sourceModifiedAt,
            confidence: ev.confidence,
            trustTier: adapter.trustTier,
            summary: ev.summary,
            normalizedJson: JSON.stringify(ev.normalized),
          });
          records++;
        }
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
