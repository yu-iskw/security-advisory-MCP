import { homedir, platform } from 'node:os';
import { join, resolve } from 'node:path';

const APP_DIR_NAME = 'advisory-mcp';

function expandHome(input: string): string {
  if (input === '~' || input.startsWith('~/')) {
    return join(homedir(), input.slice(2));
  }
  return input;
}

export function resolvePath(input: string): string {
  return resolve(expandHome(input));
}

interface DefaultPaths {
  appDir: string;
  configPath: string;
  databasePath: string;
  cachePath: string;
  logPath: string;
}

export function defaultPaths(home: string = homedir()): DefaultPaths {
  const xdgConfig = process.env.XDG_CONFIG_HOME;
  const xdgData = process.env.XDG_DATA_HOME;
  const xdgCache = process.env.XDG_CACHE_HOME;

  const isLinux = platform() === 'linux';

  const appDir =
    isLinux && xdgConfig ? join(xdgConfig, APP_DIR_NAME) : join(home, `.${APP_DIR_NAME}`);

  const dataDir = isLinux && xdgData ? join(xdgData, APP_DIR_NAME) : appDir;

  const cacheDir = isLinux && xdgCache ? join(xdgCache, APP_DIR_NAME) : join(appDir, 'cache');

  return {
    appDir,
    configPath: join(appDir, 'config.json'),
    databasePath: join(dataDir, 'advisory.db'),
    cachePath: cacheDir,
    logPath: join(dataDir, 'audit.log'),
  };
}
