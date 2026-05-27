import { AdvisoryRepository } from '../store/repositories/advisory-repository.js';
import { AffectedPackagesRepository } from '../store/repositories/affected-packages-repository.js';
import { EvidenceRepository } from '../store/repositories/evidence-repository.js';
import { SourceStateRepository } from '../store/repositories/source-state-repository.js';
import { SearchIndex } from '../store/search-index.js';
import { nowIso } from '../util/time.js';

import { mergeAdvisory } from './merger.js';

import type { Downloader } from './downloader.js';
import type { SourceAdapter, SyncContext } from '../sources/source.js';
import type { DatabaseHandle } from '../store/db.js';

interface AffectedRangeNorm {
  introduced?: string;
  fixed?: string;
}

interface AffectedPackageNorm {
  ecosystem: string;
  name: string;
  purl?: string;
  ranges?: ReadonlyArray<AffectedRangeNorm>;
}

interface PackageRowOut {
  advisoryId: string;
  ecosystem: string;
  name: string;
  purl?: string;
  vulnerableRange?: string;
  fixedVersion?: string;
  source: string;
  confidence: number;
}

function extractAffectedPackages(
  evidenceRows: ReadonlyArray<{ source: string; normalizedJson: string; confidence: number }>,
  advisoryId: string,
): ReadonlyArray<PackageRowOut> {
  const out: PackageRowOut[] = [];
  for (const ev of evidenceRows) {
    if (ev.source !== 'osv' && ev.source !== 'ossf-malicious-packages') continue;
    const pkgs = readAffectedFromEvidence(ev.normalizedJson);
    for (const pkg of pkgs) {
      pushPackageRows(out, advisoryId, pkg, ev.source, ev.confidence);
    }
  }
  return out;
}

function readAffectedFromEvidence(normalizedJson: string): ReadonlyArray<AffectedPackageNorm> {
  let parsed: { affected?: unknown };
  try {
    parsed = JSON.parse(normalizedJson) as { affected?: unknown };
  } catch {
    return [];
  }
  if (!Array.isArray(parsed.affected)) return [];
  const out: AffectedPackageNorm[] = [];
  for (const a of parsed.affected) {
    if (typeof a !== 'object' || a === null) continue;
    const rec = a as Record<string, unknown>;
    if (typeof rec.ecosystem !== 'string' || typeof rec.name !== 'string') continue;
    const ranges = Array.isArray(rec.ranges)
      ? (rec.ranges as ReadonlyArray<Record<string, unknown>>).map((r) => ({
          introduced: typeof r.introduced === 'string' ? r.introduced : undefined,
          fixed: typeof r.fixed === 'string' ? r.fixed : undefined,
        }))
      : undefined;
    out.push({
      ecosystem: rec.ecosystem,
      name: rec.name,
      purl: typeof rec.purl === 'string' ? rec.purl : undefined,
      ranges,
    });
  }
  return out;
}

function pushPackageRows(
  out: PackageRowOut[],
  advisoryId: string,
  pkg: AffectedPackageNorm,
  source: string,
  confidence: number,
): void {
  const ranges = pkg.ranges ?? [];
  if (ranges.length === 0) {
    out.push({
      advisoryId,
      ecosystem: pkg.ecosystem,
      name: pkg.name,
      purl: pkg.purl,
      source,
      confidence,
    });
    return;
  }
  for (const r of ranges) {
    out.push({
      advisoryId,
      ecosystem: pkg.ecosystem,
      name: pkg.name,
      purl: pkg.purl,
      vulnerableRange: r.introduced !== undefined ? `>=${r.introduced}` : undefined,
      fixedVersion: r.fixed,
      source,
      confidence,
    });
  }
}

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
  private readonly affectedRepo: AffectedPackagesRepository;
  private readonly evidenceRepo: EvidenceRepository;
  private readonly stateRepo: SourceStateRepository;
  private readonly search: SearchIndex;

  constructor(private readonly deps: SyncEngineDeps) {
    this.advisoryRepo = new AdvisoryRepository(deps.db);
    this.affectedRepo = new AffectedPackagesRepository(deps.db);
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

  // Re-merge all evidence for `advisoryId`, persist the merged JSON +
  // denormalized filter columns, and re-index the FTS row. Called after each
  // record write so multi-source coverage stays consistent.
  private reindexAdvisory(advisoryId: string): void {
    const advisory = this.advisoryRepo.findById(advisoryId);
    if (!advisory) return;
    const evidenceRows = this.evidenceRepo.findByAdvisoryId(advisoryId);
    const merged = mergeAdvisory(
      advisory.canonicalId,
      evidenceRows.map((e) => ({
        source: e.source,
        evidenceType: e.type,
        normalizedJson: e.normalizedJson,
      })),
    );
    // Re-upsert the advisory with merged fields so subsequent reads see the
    // canonical values regardless of which source wrote last.
    this.advisoryRepo.upsert({
      id: advisory.id,
      canonicalId: advisory.canonicalId,
      type: advisory.type,
      title: merged.title ?? advisory.title ?? undefined,
      description: merged.description ?? advisory.description ?? undefined,
      publishedAt: merged.publishedAt ?? advisory.publishedAt ?? undefined,
      modifiedAt: merged.modifiedAt ?? advisory.modifiedAt ?? undefined,
      mergedJson: JSON.stringify(merged),
      aliases: this.advisoryRepo.aliasesFor(advisoryId),
    });
    this.search.indexAdvisory({
      id: advisory.id,
      title: merged.title ?? advisory.title ?? undefined,
      description: merged.description ?? advisory.description ?? undefined,
      aliases: this.advisoryRepo.aliasesFor(advisoryId),
      severity: merged.severity === 'none' ? undefined : merged.severity,
      knownExploited: merged.knownExploited,
    });

    // Update affected_packages from package-bearing evidence (OSV + malicious).
    const packageRows = extractAffectedPackages(evidenceRows, advisory.id);
    this.affectedRepo.replaceForAdvisory(advisory.id, packageRows);
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
