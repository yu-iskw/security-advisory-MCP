#!/usr/bin/env node
import { Command } from 'commander';

import { SERVER_NAME, SERVER_VERSION } from '../mcp/server.js';

import { runServe, type ServeOptions } from './commands/serve.js';
import { runSync, type SyncOptions } from './commands/sync.js';

const program = new Command();

program
  .name(SERVER_NAME)
  .description('Local-first security advisory MCP server')
  .version(SERVER_VERSION);

program
  .command('serve')
  .description('Start the MCP server')
  .option('--transport <transport>', 'Transport to use (stdio)', 'stdio')
  .option('--config <path>', 'Path to a custom config.json')
  .action(async (options: ServeOptions) => {
    await runServe(options);
  });

program
  .command('sync')
  .description('Sync advisory sources into the local database')
  .option('--preset <preset>', 'Source preset (core|packages|ecosystems|context|all|research)', 'core')
  .option('--config <path>', 'Path to a custom config.json')
  .action(async (options: SyncOptions) => {
    await runSync(options);
  });

await program.parseAsync(process.argv);
