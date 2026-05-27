import { openStore } from '../../store/db.js';
import { buildSourceStatusSummary } from '../../store/repositories/source-state-repository.js';
import { resolvePaths } from '../../util/paths.js';

export interface StatusOptions {
  databasePath?: string;
}

export function runStatus(options: StatusOptions = {}): string {
  const paths = resolvePaths({ databasePath: options.databasePath });
  const store = openStore({ databasePath: paths.databasePath });
  try {
    const summary = buildSourceStatusSummary(store, { includeDisabled: true });
    return summary.markdownSummary;
  } finally {
    store.close();
  }
}
