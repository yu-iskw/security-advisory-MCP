import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { runInit } from '../../src/cli/commands/init.js';
import { runSync } from '../../src/cli/commands/sync.js';
import { runAnalyzeAdvisory } from '../../src/mcp/tools/analyze-advisory.js';
import { openStore } from '../../src/store/db.js';
import { countAdvisories } from '../../src/store/repositories/advisory-repository.js';
import { getBundledFixturesPath } from '../../src/util/fixtures-path.js';

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe('core sync from fixtures', () => {
  it('loads advisories and analyzes CVE-2021-44228 offline', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'advisory-mcp-core-'));
    tempDirs.push(dir);
    const databasePath = path.join(dir, 'advisory.db');
    runInit({ databasePath, cachePath: path.join(dir, 'cache') });
    const sync = runSync({
      preset: 'core',
      databasePath,
      fixturesPath: getBundledFixturesPath(),
    });
    expect(sync.advisoriesUpserted).toBeGreaterThan(0);

    const store = openStore({ databasePath });
    try {
      expect(countAdvisories(store)).toBeGreaterThan(0);
      const result = runAnalyzeAdvisory(store, {
        id: 'CVE-2021-44228',
        profile: 'default',
        includeEvidence: true,
        includeRaw: false,
      });
      expect(result.structured.advisory.id).toBe('CVE-2021-44228');
      expect(result.structured.risk.score).toBeGreaterThan(50);
      expect(result.markdown).toContain('UNTRUSTED ADVISORY DATA');
    } finally {
      store.close();
    }
  });
});
