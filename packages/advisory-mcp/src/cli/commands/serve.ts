import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { loadConfig } from '../../config/config.js';
import { createMcpServer, SERVER_NAME, SERVER_VERSION } from '../../mcp/server.js';
import { serveStreamableHttp } from '../../mcp/transports/http.js';
import { openAdvisoryStore, type AdvisoryStore } from '../../store/store.js';
import { createLogger } from '../../util/logger.js';

export interface ServeOptions {
  transport: string;
  port?: number;
  host?: string;
  config?: string;
}

export async function runServe(options: ServeOptions): Promise<void> {
  if (options.transport !== 'stdio' && options.transport !== 'http') {
    process.stderr.write(
      `Unsupported transport: ${options.transport}. Supported: stdio, http\n`,
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

  if (options.transport === 'http') {
    const port = options.port ?? 8765;
    const host = options.host ?? '127.0.0.1';
    await serveStreamableHttp({ port, host, store, sbomRoots: config.sbomRoots });
    logger.info('http_listening', { host, port });
    process.stdout.write(`advisory-mcp HTTP listening at http://${host}:${port.toString()}\n`);
    await new Promise<void>((resolve) => {
      const shutdown = (): void => {
        resolve();
      };
      process.once('SIGINT', shutdown);
      process.once('SIGTERM', shutdown);
    });
    return;
  }

  const server = createMcpServer({ store, sbomRoots: config.sbomRoots });
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
