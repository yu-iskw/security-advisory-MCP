#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { Command } from 'commander';

import { createMcpServer, SERVER_NAME, SERVER_VERSION } from '../mcp/server.js';

interface ServeOptions {
  transport: string;
}

async function runServe(options: ServeOptions): Promise<void> {
  if (options.transport !== 'stdio') {
    process.stderr.write(
      `Unsupported transport: ${options.transport}. Supported: stdio\n`,
    );
    process.exit(2);
  }
  const server = createMcpServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

const program = new Command();

program
  .name(SERVER_NAME)
  .description('Local-first security advisory MCP server')
  .version(SERVER_VERSION);

program
  .command('serve')
  .description('Start the MCP server')
  .option('--transport <transport>', 'Transport to use (stdio)', 'stdio')
  .action(async (options: ServeOptions) => {
    await runServe(options);
  });

await program.parseAsync(process.argv);
