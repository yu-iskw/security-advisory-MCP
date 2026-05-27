import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { runInit } from '../../src/cli/commands/init.js';
import { runSourceStatus } from '../../src/mcp/tools/source-status.js';
import { openStore } from '../../src/store/db.js';

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe('source_status', () => {
  it('returns core sources after init', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'advisory-mcp-status-'));
    tempDirs.push(dir);
    const databasePath = path.join(dir, 'advisory.db');
    runInit({ databasePath, cachePath: path.join(dir, 'cache') });

    const store = openStore({ databasePath });
    try {
      const result = runSourceStatus(store, { includeDisabled: false });
      expect(result.structured.sources.length).toBe(5);
      expect(result.structured.advisoryCount).toBe(0);
      expect(result.markdownSummary).toContain('cveproject');
    } finally {
      store.close();
    }
  });
});
