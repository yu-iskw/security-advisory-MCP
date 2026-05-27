import fs from 'node:fs';
import path from 'node:path';

import { FIXTURE_ADAPTERS } from './fixture-adapters.js';

import type { SourceDefinition } from './source.js';
import type { NormalizedRecord } from '../ingest/merger.js';

export function loadFixtureRecords(
  fixtureRoot: string,
  source: SourceDefinition,
): NormalizedRecord[] {
  const dir = path.join(fixtureRoot, source.fixtureSubdir);
  if (!fs.existsSync(dir)) {
    return [];
  }
  const adapter = FIXTURE_ADAPTERS[source.id];
  return adapter({
    dir,
    sourceId: source.id,
    trustTier: source.trustTier,
    fetchedAt: new Date().toISOString(),
  });
}
