import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import { ping } from './tools/ping.js';

export const SERVER_NAME = 'advisory-mcp';
export const SERVER_VERSION = '0.1.0';

export function createMcpServer(): McpServer {
  const server = new McpServer({
    name: SERVER_NAME,
    version: SERVER_VERSION,
  });

  server.registerTool(
    'ping',
    {
      title: 'Ping',
      description:
        'Health check. Returns the server name and version. Does not access the network.',
      inputSchema: {},
    },
    () => {
      const result = ping(SERVER_NAME, SERVER_VERSION);
      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(result),
          },
        ],
      };
    },
  );

  return server;
}
