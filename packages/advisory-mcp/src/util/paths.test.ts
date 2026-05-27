import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { defaultPaths, resolvePath } from './paths.js';

describe('paths', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    delete process.env.XDG_CONFIG_HOME;
    delete process.env.XDG_DATA_HOME;
    delete process.env.XDG_CACHE_HOME;
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  describe('resolvePath', () => {
    it('expands a leading tilde to the home directory', () => {
      const expanded = resolvePath('~/foo/bar');
      expect(expanded.endsWith('/foo/bar')).toBe(true);
      expect(expanded.startsWith('/')).toBe(true);
    });

    it('passes absolute paths through', () => {
      expect(resolvePath('/etc/hosts')).toBe('/etc/hosts');
    });

    it('resolves relative paths to absolute', () => {
      const out = resolvePath('foo');
      expect(out.startsWith('/')).toBe(true);
    });
  });

  describe('defaultPaths', () => {
    it('uses ~/.advisory-mcp by default', () => {
      const paths = defaultPaths('/home/u');
      expect(paths.appDir).toBe('/home/u/.advisory-mcp');
      expect(paths.configPath).toBe('/home/u/.advisory-mcp/config.json');
      expect(paths.databasePath).toBe('/home/u/.advisory-mcp/advisory.db');
      expect(paths.cachePath).toBe('/home/u/.advisory-mcp/cache');
    });

    it('honors XDG_CONFIG_HOME on Linux', () => {
      if (process.platform !== 'linux') return;
      process.env.XDG_CONFIG_HOME = '/custom/cfg';
      const paths = defaultPaths('/home/u');
      expect(paths.appDir).toBe('/custom/cfg/advisory-mcp');
    });
  });
});
