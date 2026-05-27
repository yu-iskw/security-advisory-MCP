import fs from 'node:fs';
import path from 'node:path';

import { z } from 'zod';

import { DEFAULT_MAX_DECOMPRESSED_BYTES, DEFAULT_MAX_DOWNLOAD_BYTES } from '../security/limits.js';

import { expandHome, resolvePaths, type AdvisoryMcpPaths } from './paths.js';

const configSchema = z.object({
  databasePath: z.string().optional(),
  cachePath: z.string().optional(),
  defaultPreset: z
    .enum(['core', 'packages', 'ecosystems', 'context', 'all', 'research'])
    .default('core'),
  autoSyncIfEmpty: z.boolean().default(false),
  maxDownloadBytes: z.number().default(DEFAULT_MAX_DOWNLOAD_BYTES),
  maxDecompressedBytes: z.number().default(DEFAULT_MAX_DECOMPRESSED_BYTES),
});

export type AdvisoryMcpConfig = z.infer<typeof configSchema>;

export function loadConfig(configPath?: string): AdvisoryMcpConfig & AdvisoryMcpPaths {
  const paths = resolvePaths();
  const file = configPath ?? path.join(paths.configDir, 'config.json');
  if (!fs.existsSync(file)) {
    return {
      ...configSchema.parse({}),
      ...paths,
    };
  }
  const raw = JSON.parse(fs.readFileSync(file, 'utf8')) as unknown;
  const parsed = configSchema.parse(raw);
  return {
    ...parsed,
    configDir: paths.configDir,
    databasePath: expandHome(parsed.databasePath ?? paths.databasePath),
    cachePath: expandHome(parsed.cachePath ?? paths.cachePath),
  };
}

export function writeDefaultConfig(configDir: string): void {
  const file = path.join(configDir, 'config.json');
  if (fs.existsSync(file)) {
    return;
  }
  const paths = resolvePaths({ configDir });
  const payload = configSchema.parse({});
  fs.mkdirSync(configDir, { recursive: true });
  fs.writeFileSync(
    file,
    JSON.stringify(
      {
        databasePath: paths.databasePath,
        cachePath: paths.cachePath,
        defaultPreset: payload.defaultPreset,
        autoSyncIfEmpty: payload.autoSyncIfEmpty,
        maxDownloadBytes: payload.maxDownloadBytes,
        maxDecompressedBytes: payload.maxDecompressedBytes,
      },
      null,
      2,
    ),
  );
}
