import { serveStdio } from '../../mcp/transports/stdio.js';
import { DatabaseNotInitializedError, isStoreInitialized, openStore } from '../../store/db.js';
import { resolvePaths } from '../../util/paths.js';

export interface ServeOptions {
  transport: 'stdio' | 'http';
  databasePath?: string;
  autoSyncIfEmpty?: boolean;
  port?: number;
}

export async function runServe(options: ServeOptions): Promise<void> {
  if (options.transport === 'http') {
    throw new Error('HTTP transport is planned for a later RFC phase.');
  }

  const paths = resolvePaths({ databasePath: options.databasePath });
  if (!isStoreInitialized(paths.databasePath)) {
    throw new DatabaseNotInitializedError(paths.databasePath);
  }
  const store = openStore({ databasePath: paths.databasePath });

  if (options.autoSyncIfEmpty) {
    // Explicit opt-in only; fixture/network sync wired in a later step.
    void options.autoSyncIfEmpty;
  }

  await serveStdio({ store, requireInitialized: true });
}
