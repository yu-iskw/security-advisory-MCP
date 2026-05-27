import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { createMcpServer } from '../server.js';

import type { AdvisoryStore } from '../../store/db.js';

export interface ServeStdioOptions {
  store: AdvisoryStore;
  requireInitialized?: boolean;
}

export async function serveStdio(options: ServeStdioOptions): Promise<void> {
  const server = createMcpServer({
    store: options.store,
    requireInitialized: options.requireInitialized,
  });
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
