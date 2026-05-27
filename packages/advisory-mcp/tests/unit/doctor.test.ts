import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { runDoctor } from '../../src/cli/commands/doctor.js';
import { runInit } from '../../src/cli/commands/init.js';

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe('doctor', () => {
  it('reports uninitialized database before init', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'advisory-mcp-doctor-'));
    tempDirs.push(dir);
    const databasePath = path.join(dir, 'missing.db');
    const report = runDoctor({ databasePath });
    const dbCheck = report.checks.find((c) => c.name === 'database-initialized');
    expect(dbCheck?.ok).toBe(false);
  });

  it('passes node and fts checks after init', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'advisory-mcp-doctor-init-'));
    tempDirs.push(dir);
    const databasePath = path.join(dir, 'advisory.db');
    runInit({ databasePath, cachePath: path.join(dir, 'cache') });
    const report = runDoctor({ databasePath });
    const nodeCheck = report.checks.find((c) => c.name === 'node-version');
    const ftsCheck = report.checks.find((c) => c.name === 'sqlite-fts5');
    expect(nodeCheck?.ok).toBe(true);
    expect(ftsCheck?.ok).toBe(true);
  });
});
