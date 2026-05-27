import fs from 'node:fs';
import path from 'node:path';

import { loadFixtureRecords } from '../sources/fixture-loader.js';
import { sourcesForPreset } from '../sources/registry.js';
import { upsertAdvisory } from '../store/repositories/advisory-repository.js';
import { storeRawRecord, upsertEvidence } from '../store/repositories/evidence-repository.js';
import { getBundledFixturesPath } from '../util/fixtures-path.js';
import { logEvent } from '../util/logger.js';

import { hashPayload, mergeRecords } from './merger.js';

import type { NormalizedRecord } from './merger.js';
import type { SourceId, SourceStatus, SyncPreset } from '../schemas/source.js';
import type { SourceDefinition, SyncSourceResult } from '../sources/source.js';
import type { AdvisoryStore } from '../store/db.js';

export interface SyncEngineOptions {
  store: AdvisoryStore;
  preset: SyncPreset;
  fixtureRoot: string;
}

export interface SyncEngineResult {
  preset: SyncPreset;
  sources: SyncSourceResult[];
  advisoriesUpserted: number;
  durationMs: number;
}

export function runSyncEngine(options: SyncEngineOptions): SyncEngineResult {
  const started = Date.now();
  const sources = sourcesForPreset(options.preset);
  const { sourceResults, records } = collectRecordsFromSources(options, sources);
  const advisoriesUpserted = persistMergedRecords(options.store, records);
  return {
    preset: options.preset,
    sources: sourceResults,
    advisoriesUpserted,
    durationMs: Date.now() - started,
  };
}

function collectRecordsFromSources(
  options: SyncEngineOptions,
  sources: SourceDefinition[],
): { sourceResults: SyncSourceResult[]; records: NormalizedRecord[] } {
  const sourceResults: SyncSourceResult[] = [];
  const records: NormalizedRecord[] = [];

  for (const source of sources) {
    const sourceStarted = Date.now();
    try {
      updateSourceState(options.store, source.id, 'syncing', options.preset);
      const loaded = loadFixtureRecords(options.fixtureRoot, source);
      records.push(...loaded);
      for (const record of loaded) {
        const payload = Buffer.from(JSON.stringify(record.evidence.normalizedJson));
        storeRawRecord(options.store, {
          id: record.evidence.rawRef ?? hashPayload(payload),
          source: source.id,
          sourceRecordId: record.evidence.sourceRecordId,
          fetchedAt: record.evidence.fetchedAt,
          sha256: hashPayload(payload),
          payload,
        });
      }
      updateSourceState(options.store, source.id, 'ok', options.preset, {
        completed: true,
        records: loaded.length,
      });
      logEvent({
        level: 'info',
        event: 'source_sync_completed',
        source: source.id,
        recordsProcessed: loaded.length,
        recordsChanged: loaded.length,
        durationMs: Date.now() - sourceStarted,
      });
      sourceResults.push({
        source: source.id,
        recordsProcessed: loaded.length,
        recordsChanged: loaded.length,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      updateSourceState(options.store, source.id, 'error', options.preset, { error: message });
      sourceResults.push({
        source: source.id,
        recordsProcessed: 0,
        recordsChanged: 0,
        error: message,
      });
    }
  }

  return { sourceResults, records };
}

function persistMergedRecords(store: AdvisoryStore, records: NormalizedRecord[]): number {
  const merged = mergeRecords(records);
  const mergeTx = store.db.transaction(() => {
    for (const advisory of merged) {
      upsertAdvisory(store, advisory);
    }
    for (const record of records) {
      upsertEvidence(store, record.evidence);
    }
  });
  mergeTx();
  return merged.length;
}

function updateSourceState(
  store: AdvisoryStore,
  source: SourceId,
  status: SourceStatus,
  preset: SyncPreset,
  extra?: { completed?: boolean; records?: number; error?: string },
): void {
  const now = new Date().toISOString();
  store.db
    .prepare(
      `INSERT INTO source_state (source, enabled, preset, status, last_sync_started_at, last_sync_completed_at, last_success_at, last_error)
       VALUES (@source, 1, @preset, @status, @started, @completed, @success, @error)
       ON CONFLICT(source) DO UPDATE SET
         status = excluded.status,
         preset = excluded.preset,
         last_sync_started_at = COALESCE(source_state.last_sync_started_at, excluded.last_sync_started_at),
         last_sync_completed_at = excluded.last_sync_completed_at,
         last_success_at = excluded.last_success_at,
         last_error = excluded.last_error`,
    )
    .run({
      source,
      preset,
      status,
      started: now,
      completed: extra?.completed ? now : null,
      success: extra?.completed ? now : null,
      error: extra?.error ?? null,
    });
}

export function resolveFixtureRoot(explicit?: string): string {
  if (explicit) {
    return path.resolve(explicit);
  }
  const bundled = getBundledFixturesPath();
  if (fs.existsSync(bundled)) {
    return bundled;
  }
  throw new Error(
    'Fixture root not found. Pass --fixtures <path> or run from package with tests/fixtures.',
  );
}
