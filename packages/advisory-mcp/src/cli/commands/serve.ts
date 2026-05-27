import { serveHttp } from '../../mcp/transports/http.js';
import { serveStdio } from '../../mcp/transports/stdio.js';
import { DatabaseNotInitializedError, isStoreInitialized, openStore } from '../../store/db.js';
import { countAdvisories } from '../../store/repositories/advisory-repository.js';
import { loadConfig } from '../../util/config.js';
import { getBundledFixturesPath } from '../../util/fixtures-path.js';
import { resolvePaths } from '../../util/paths.js';

import { runSync } from './sync.js';

export interface ServeOptions {
  transport: 'stdio' | 'http';
  databasePath?: string;
  autoSyncIfEmpty?: boolean;
  port?: number;
}

export async function runServe(options: ServeOptions): Promise<void> {
  const config = loadConfig();
  const paths = resolvePaths({ databasePath: options.databasePath ?? config.databasePath });

  if (!isStoreInitialized(paths.databasePath)) {
    if (options.autoSyncIfEmpty ?? config.autoSyncIfEmpty) {
      runSync({
        preset: config.defaultPreset,
        databasePath: paths.databasePath,
        fixturesPath: getBundledFixturesPath(),
      });
    } else {
      throw new DatabaseNotInitializedError(paths.databasePath);
    }
  }

  const store = openStore({ databasePath: paths.databasePath });
  if (options.autoSyncIfEmpty && countAdvisories(store) === 0) {
    store.close();
    runSync({
      preset: config.defaultPreset,
      databasePath: paths.databasePath,
      fixturesPath: getBundledFixturesPath(),
    });
    const refreshed = openStore({ databasePath: paths.databasePath });
    if (options.transport === 'http') {
      await serveHttp(options.port ?? 8765);
      refreshed.close();
      return;
    }
    await serveStdio({ store: refreshed, requireInitialized: true });
    return;
  }

  if (options.transport === 'http') {
    await serveHttp(options.port ?? 8765);
    store.close();
    return;
  }

  await serveStdio({ store, requireInitialized: true });
}
