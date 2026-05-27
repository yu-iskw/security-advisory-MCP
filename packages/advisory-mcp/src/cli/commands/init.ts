import fs from 'node:fs';

import { openStore, seedCoreSourceStates } from '../../store/db.js';
import { resolvePaths } from '../../util/paths.js';

export interface InitOptions {
  databasePath?: string;
  cachePath?: string;
  preset?: string;
}

export function runInit(options: InitOptions = {}): { databasePath: string; cachePath: string } {
  const paths = resolvePaths({
    databasePath: options.databasePath,
    cachePath: options.cachePath,
  });

  fs.mkdirSync(paths.configDir, { recursive: true });
  fs.mkdirSync(paths.cachePath, { recursive: true });

  const store = openStore({ databasePath: paths.databasePath });
  seedCoreSourceStates(store, options.preset ?? 'core');
  store.close();

  return {
    databasePath: paths.databasePath,
    cachePath: paths.cachePath,
  };
}
