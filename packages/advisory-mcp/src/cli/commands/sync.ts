import { syncPresetSchema, type SyncPreset } from '../../schemas/source.js';
import { assertStoreReady, openStore, seedCoreSourceStates } from '../../store/db.js';
import { runSyncEngine, resolveFixtureRoot } from '../../ingest/sync-engine.js';
import { getBundledFixturesPath } from '../../util/fixtures-path.js';
import { resolvePaths } from '../../util/paths.js';

export interface SyncOptions {
  preset: string;
  databasePath?: string;
  fixturesPath?: string;
}

export interface SyncResult {
  preset: SyncPreset;
  message: string;
  recordsProcessed: number;
  advisoriesUpserted: number;
}

export function runSync(options: SyncOptions): SyncResult {
  const preset = syncPresetSchema.parse(options.preset);
  const paths = resolvePaths({ databasePath: options.databasePath });
  const store = openStore({ databasePath: paths.databasePath });

  if (preset === 'core') {
    seedCoreSourceStates(store, preset);
  }
  assertStoreReady(store);

  try {
    const fixtureRoot = resolveFixtureRoot(options.fixturesPath ?? getBundledFixturesPath());
    const result = runSyncEngine({ store, preset, fixtureRoot });
    const recordsProcessed = result.sources.reduce((s, r) => s + r.recordsProcessed, 0);
    const errors = result.sources.filter((s) => s.error);
    const message = [
      `Sync preset "${preset}" completed in ${result.durationMs}ms.`,
      `Advisories upserted: ${result.advisoriesUpserted}.`,
      `Records processed: ${recordsProcessed}.`,
      errors.length > 0 ? `Optional source errors: ${errors.map((e) => e.source).join(', ')}` : '',
      options.fixturesPath ? `Fixtures: ${fixtureRoot}` : 'Using bundled fixtures.',
    ]
      .filter(Boolean)
      .join('\n');

    return {
      preset,
      message,
      recordsProcessed,
      advisoriesUpserted: result.advisoriesUpserted,
    };
  } finally {
    store.close();
  }
}
