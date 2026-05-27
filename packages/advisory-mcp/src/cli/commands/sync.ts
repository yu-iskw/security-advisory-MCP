import { syncPresetSchema, type SyncPreset } from '../../schemas/source.js';
import { assertStoreReady, openStore } from '../../store/db.js';
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
}

export function runSync(options: SyncOptions): SyncResult {
  const preset = syncPresetSchema.parse(options.preset);
  const paths = resolvePaths({ databasePath: options.databasePath });
  const store = openStore({ databasePath: paths.databasePath });
  assertStoreReady(store);

  try {
    if (options.fixturesPath) {
      return fixtureSyncMessage(preset, options.fixturesPath);
    }

    return {
      preset,
      message:
        'Network sync is not implemented in this scaffold yet. Use `--fixtures <path>` in tests or wait for the next incremental step.',
      recordsProcessed: 0,
    };
  } finally {
    store.close();
  }
}

function fixtureSyncMessage(preset: SyncPreset, fixturesPath: string): SyncResult {
  return {
    preset,
    message: `Fixture sync from ${fixturesPath} is planned in the next implementation step.`,
    recordsProcessed: 0,
  };
}
