import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { runInit } from '../../src/cli/commands/init.js';
import { runSync } from '../../src/cli/commands/sync.js';
import { analyzePackageCoordinate } from '../../src/mcp/tools/package-analysis.js';
import { openStore } from '../../src/store/db.js';
import { getBundledFixturesPath } from '../../src/util/fixtures-path.js';

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe('package analysis version matching', () => {
  it('does not flag log4j-core 2.16.0 against GHSA <2.15.4 range', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'advisory-mcp-pkg-ver-'));
    tempDirs.push(dir);
    const databasePath = path.join(dir, 'advisory.db');
    runInit({ databasePath, cachePath: path.join(dir, 'cache') });
    runSync({ preset: 'packages', databasePath, fixturesPath: getBundledFixturesPath() });

    const store = openStore({ databasePath });
    try {
      const analysis = analyzePackageCoordinate(
        store,
        {
          key: 'maven|log4j-core|2.16.0',
          ecosystem: 'maven',
          name: 'log4j-core',
          version: '2.16.0',
        },
        { includeMaliciousPackageReports: true },
      );
      const log4jFinding = analysis.findings.find((f) =>
        f.advisoryId.includes('GHSA-jfhm-5ghh-2f97'),
      );
      expect(log4jFinding).toBeUndefined();
    } finally {
      store.close();
    }
  });
});
