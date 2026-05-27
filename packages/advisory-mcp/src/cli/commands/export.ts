import fs from 'node:fs';

import { openStore } from '../../store/db.js';
import { countAdvisories } from '../../store/repositories/advisory-repository.js';
import { buildSourceStatusSummary } from '../../store/repositories/source-state-repository.js';
import { resolvePaths } from '../../util/paths.js';

export function runExport(options: {
  format: string;
  databasePath?: string;
  outputPath?: string;
}): string {
  if (options.format !== 'json') {
    throw new Error('Only --format json is supported in v1');
  }
  const paths = resolvePaths({ databasePath: options.databasePath });
  const store = openStore({ databasePath: paths.databasePath, readonly: true });
  try {
    const advisories = store.db
      .prepare('SELECT merged_json FROM advisories ORDER BY id')
      .all() as Array<{ merged_json: string }>;
    const payload = {
      exportedAt: new Date().toISOString(),
      advisoryCount: countAdvisories(store),
      sourceStatus: buildSourceStatusSummary(store, { includeDisabled: true }),
      advisories: advisories.map((r) => JSON.parse(r.merged_json) as unknown),
    };
    const text = JSON.stringify(payload, null, 2);
    if (options.outputPath) {
      fs.writeFileSync(options.outputPath, text);
    }
    return text;
  } finally {
    store.close();
  }
}
