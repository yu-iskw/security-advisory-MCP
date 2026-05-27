import { readFile } from 'node:fs/promises';

import { z } from 'zod';

import { defaultPaths, resolvePath } from '../util/paths.js';

const SOURCE_IDS = [
  'cveproject',
  'nvd-feed',
  'cisa-kev',
  'cisa-vulnrichment',
  'first-epss',
  'osv',
  'github-advisory',
  'ossf-malicious-packages',
  'mitre-cwe',
  'mitre-capec',
  'debian',
  'ubuntu',
  'alpine',
  'rustsec',
  'go-vulndb',
  'pypa',
] as const;

type SourceId = (typeof SOURCE_IDS)[number];

const PRESETS = [
  'core',
  'packages',
  'ecosystems',
  'context',
  'all',
  'research',
] as const;

const SourceConfigSchema = z.object({
  enabled: z.boolean(),
});

export const ConfigSchema = z.object({
  databasePath: z.string().min(1),
  cachePath: z.string().min(1),
  defaultPreset: z.enum(PRESETS).default('core'),
  autoSyncIfEmpty: z.boolean().default(false),
  maxDownloadBytes: z.number().int().positive().default(1_000_000_000),
  maxDecompressedBytes: z.number().int().positive().default(5_000_000_000),
  logLevel: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
  sources: z.record(z.enum(SOURCE_IDS), SourceConfigSchema).default({}),
});

type Config = z.infer<typeof ConfigSchema>;

const DEFAULT_SOURCE_ENABLED: Record<SourceId, boolean> = {
  cveproject: true,
  'nvd-feed': true,
  'cisa-kev': true,
  'cisa-vulnrichment': true,
  'first-epss': true,
  osv: false,
  'github-advisory': false,
  'ossf-malicious-packages': false,
  'mitre-cwe': false,
  'mitre-capec': false,
  debian: false,
  ubuntu: false,
  alpine: false,
  rustsec: false,
  'go-vulndb': false,
  pypa: false,
};

export function defaultConfig(): Config {
  const paths = defaultPaths();
  const sources: Partial<Record<SourceId, { enabled: boolean }>> = {};
  for (const id of SOURCE_IDS) {
    // eslint-disable-next-line security/detect-object-injection -- `id` is constrained to SOURCE_IDS members
    sources[id] = { enabled: DEFAULT_SOURCE_ENABLED[id] };
  }
  return ConfigSchema.parse({
    databasePath: paths.databasePath,
    cachePath: paths.cachePath,
    sources,
  });
}

interface LoadConfigOptions {
  configPath?: string;
}

export async function loadConfig(options: LoadConfigOptions = {}): Promise<Config> {
  const paths = defaultPaths();
  const configPath = options.configPath
    ? resolvePath(options.configPath)
    : paths.configPath;

  let fileContent: string | undefined;
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- configPath is the documented input
    fileContent = await readFile(configPath, 'utf8');
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code !== 'ENOENT') throw err;
  }

  if (fileContent === undefined) {
    return applyEnv(defaultConfig());
  }

  const parsed = JSON.parse(fileContent) as unknown;
  const base = defaultConfig();
  const merged = mergeConfig(base, parsed);
  const validated = ConfigSchema.parse(merged);
  return applyEnv(validated);
}

function mergeConfig(base: Config, override: unknown): unknown {
  if (typeof override !== 'object' || override === null) return base;
  const o = override as Record<string, unknown>;
  const sources = {
    ...base.sources,
    ...((o.sources as Record<string, unknown> | undefined) ?? {}),
  };
  return { ...base, ...o, sources };
}

function applyEnv(config: Config): Config {
  const next = { ...config };
  const envDb = process.env.ADVISORY_MCP_DATABASE_PATH;
  if (envDb) next.databasePath = resolvePath(envDb);
  const envCache = process.env.ADVISORY_MCP_CACHE_PATH;
  if (envCache) next.cachePath = resolvePath(envCache);
  const envLog = process.env.ADVISORY_MCP_LOG_LEVEL;
  if (envLog && ['debug', 'info', 'warn', 'error'].includes(envLog)) {
    next.logLevel = envLog as Config['logLevel'];
  }
  return next;
}
