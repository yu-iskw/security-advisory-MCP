import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { loadConfig } from '../../config/config.js';
import { createMcpServer, SERVER_NAME, SERVER_VERSION } from '../../mcp/server.js';
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
  logger.info('server_starting', { transport: options.transport });

  const server = createMcpServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
