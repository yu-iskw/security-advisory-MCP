import { loadConfig } from '../../config/config.js';
import { sourceStatus } from '../../mcp/tools/source-status.js';
import { openAdvisoryStore } from '../../store/store.js';

export interface StatusOptions {
  config?: string;
}

export async function runStatus(options: StatusOptions): Promise<void> {
  const config = await loadConfig({ configPath: options.config });
  let store;
  try {
    store = openAdvisoryStore({ path: config.databasePath });
  } catch (err) {
    process.stderr.write(
      `Could not open ${config.databasePath}: ${err instanceof Error ? err.message : String(err)}.\n` +
        `Run \`advisory-mcp init\` and \`advisory-mcp sync --preset core\` first.\n`,
    );
    process.exit(1);
  }
  try {
    const status = sourceStatus(store, {});
    process.stdout.write(`${status.markdown}\n`);
    process.stdout.write(
      `\nAdvisories: ${store.advisories.count().toString()}, evidence rows: ${store.evidence.count().toString()}.\n`,
    );
  } finally {
    store.close();
  }
}
