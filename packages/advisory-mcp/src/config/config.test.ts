import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { ConfigSchema, defaultConfig, loadConfig } from './config.js';

describe('config', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    delete process.env.ADVISORY_MCP_DATABASE_PATH;
    delete process.env.ADVISORY_MCP_CACHE_PATH;
    delete process.env.ADVISORY_MCP_LOG_LEVEL;
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it('defaultConfig produces a schema-valid config with core preset', () => {
    const config = defaultConfig();
    expect(config.defaultPreset).toBe('core');
    expect(config.autoSyncIfEmpty).toBe(false);
    expect(config.sources['cisa-kev']?.enabled).toBe(true);
    expect(config.sources.osv?.enabled).toBe(false);
    expect(() => ConfigSchema.parse(config)).not.toThrow();
  });

  it('rejects invalid log levels', () => {
    expect(() =>
      ConfigSchema.parse({
        ...defaultConfig(),
        logLevel: 'verbose',
      }),
    ).toThrow();
  });

  it('rejects non-positive maxDownloadBytes', () => {
    expect(() =>
      ConfigSchema.parse({
        ...defaultConfig(),
        maxDownloadBytes: -1,
      }),
    ).toThrow();
  });

  it('loadConfig returns defaults when the config file is absent', async () => {
    const config = await loadConfig({
      configPath: '/nonexistent/path/does/not/exist.json',
    });
    expect(config.defaultPreset).toBe('core');
  });

  it('loadConfig merges a user config file over defaults', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'advisory-mcp-cfg-'));
    const file = join(dir, 'config.json');
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- test fixture path
    await writeFile(
      file,
      JSON.stringify({
        defaultPreset: 'packages',
        autoSyncIfEmpty: true,
        sources: { osv: { enabled: true } },
      }),
    );
    const config = await loadConfig({ configPath: file });
    expect(config.defaultPreset).toBe('packages');
    expect(config.autoSyncIfEmpty).toBe(true);
    expect(config.sources.osv?.enabled).toBe(true);
    expect(config.sources['cisa-kev']?.enabled).toBe(true);
  });

  it('environment variables override config file values', async () => {
    process.env.ADVISORY_MCP_DATABASE_PATH = '/tmp/override.db';
    process.env.ADVISORY_MCP_LOG_LEVEL = 'debug';
    const config = await loadConfig({
      configPath: '/nonexistent/path.json',
    });
    expect(config.databasePath).toBe('/tmp/override.db');
    expect(config.logLevel).toBe('debug');
  });
});
