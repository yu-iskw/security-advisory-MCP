import { homedir } from 'node:os';
import path from 'node:path';

export const DEFAULT_CONFIG_DIR = path.join(homedir(), '.advisory-mcp');
export const DEFAULT_DATABASE_PATH = path.join(DEFAULT_CONFIG_DIR, 'advisory.db');
export const DEFAULT_CACHE_PATH = path.join(DEFAULT_CONFIG_DIR, 'cache');

export interface AdvisoryMcpPaths {
  configDir: string;
  databasePath: string;
  cachePath: string;
}

export function resolvePaths(overrides?: Partial<AdvisoryMcpPaths>): AdvisoryMcpPaths {
  return {
    configDir: overrides?.configDir ?? DEFAULT_CONFIG_DIR,
    databasePath: overrides?.databasePath ?? DEFAULT_DATABASE_PATH,
    cachePath: overrides?.cachePath ?? DEFAULT_CACHE_PATH,
  };
}

export function expandHome(filePath: string): string {
  if (filePath.startsWith('~/')) {
    return path.join(homedir(), filePath.slice(2));
  }
  if (filePath === '~') {
    return homedir();
  }
  return filePath;
}
