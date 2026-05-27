import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { runInit } from '../../src/cli/commands/init.js';
import { runSync } from '../../src/cli/commands/sync.js';
import { openStore } from '../../src/store/db.js';
import { countAdvisories } from '../../src/store/repositories/advisory-repository.js';
import { getBundledFixturesPath } from '../../src/util/fixtures-path.js';

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe('all presets sync', () => {
  it('syncs core, packages, ecosystems, and context presets', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'advisory-mcp-all-'));
    tempDirs.push(dir);
    const databasePath = path.join(dir, 'advisory.db');
    runInit({ databasePath, cachePath: path.join(dir, 'cache') });
    const fixtures = getBundledFixturesPath();

    for (const preset of ['core', 'packages', 'ecosystems', 'context'] as const) {
      runSync({ preset, databasePath, fixturesPath: fixtures });
    }

    const store = openStore({ databasePath });
    try {
      expect(countAdvisories(store)).toBeGreaterThanOrEqual(3);
    } finally {
      store.close();
    }
  });
});
