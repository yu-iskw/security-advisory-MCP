import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { loadConfig } from '../../config/config.js';
import { createMcpServer, SERVER_NAME, SERVER_VERSION } from '../../mcp/server.js';
import { openAdvisoryStore, type AdvisoryStore } from '../../store/store.js';
import { createLogger } from '../../util/logger.js';

export interface ServeOptions {
  transport: string;
  config?: string;
}

export async function runServe(options: ServeOptions): Promise<void> {
  if (options.transport !== 'stdio') {
    process.stderr.write(
      `Unsupported transport: ${options.transport}. Supported: stdio\n`,
    );
    process.exit(2);
  }

  const config = await loadConfig({ configPath: options.config });
  const logger = createLogger({
    level: config.logLevel,
    baseFields: { server: SERVER_NAME, version: SERVER_VERSION },
  });

  let store: AdvisoryStore | undefined;
  try {
    store = openAdvisoryStore({ path: config.databasePath });
  } catch (err) {
    logger.warn('store_open_failed', {
      databasePath: config.databasePath,
      error: err instanceof Error ? err.message : String(err),
    });
    process.stderr.write(
      `Could not open the advisory database at ${config.databasePath}.\n` +
        `Run \`advisory-mcp sync --preset core\` first.\n`,
    );
  }

  logger.info('server_starting', { transport: options.transport, hasStore: store !== undefined });

  const server = createMcpServer({ store });
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
