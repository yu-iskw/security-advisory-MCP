import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { runInit } from '../../src/cli/commands/init.js';
import { openStore } from '../../src/store/db.js';
import { buildSourceStatusSummary } from '../../src/store/repositories/source-state-repository.js';

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe('source status summary', () => {
  it('returns core sources after init', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'advisory-mcp-status-'));
    tempDirs.push(dir);
    const databasePath = path.join(dir, 'advisory.db');
    runInit({ databasePath, cachePath: path.join(dir, 'cache') });

    const store = openStore({ databasePath });
    try {
      const summary = buildSourceStatusSummary(store, { includeDisabled: false });
      expect(summary.sources.length).toBe(5);
      expect(summary.advisoryCount).toBe(0);
      expect(summary.markdownSummary).toContain('cveproject');
    } finally {
      store.close();
    }
  });
});
