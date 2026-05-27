import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { runInit } from './init.js';

describe('runInit', () => {
  let dir: string;
  let configPath: string;
  const writes: string[] = [];
  const originalWrite = process.stdout.write.bind(process.stdout);

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'advisory-mcp-init-'));
    configPath = join(dir, 'config.json');
    writes.length = 0;
    process.stdout.write = (chunk: string | Uint8Array) => {
      writes.push(typeof chunk === 'string' ? chunk : new TextDecoder().decode(chunk));
      return true;
    };
  });

  afterEach(async () => {
    process.stdout.write = originalWrite;
    await rm(dir, { recursive: true, force: true });
  });

  it('writes a default config when none exists', async () => {
    await runInit({ config: configPath });
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- test temp file
    const raw = await readFile(configPath, 'utf8');
    const parsed = JSON.parse(raw) as { defaultPreset: string };
    expect(parsed.defaultPreset).toBe('core');
    expect(writes.join('')).toMatch(/Initialized advisory-mcp/);
  });

  it('refuses to overwrite without --force', async () => {
    await runInit({ config: configPath });
    writes.length = 0;
    await runInit({ config: configPath });
    expect(writes.join('')).toMatch(/already exists/);
  });

  it('overwrites with --force', async () => {
    await runInit({ config: configPath });
    writes.length = 0;
    await runInit({ config: configPath, force: true });
    expect(writes.join('')).toMatch(/Initialized advisory-mcp/);
  });
});
