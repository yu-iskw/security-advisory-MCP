#!/usr/bin/env node
import { Command } from 'commander';

import { SERVER_NAME, SERVER_VERSION } from '../mcp/server.js';

import { runDoctor, type DoctorOptions } from './commands/doctor.js';
import { runExport, type ExportOptions } from './commands/export.js';
import { runInit, type InitOptions } from './commands/init.js';
import { runServe, type ServeOptions } from './commands/serve.js';
import { runStatus, type StatusOptions } from './commands/status.js';
import { runSync, type SyncOptions } from './commands/sync.js';

const CONFIG_OPT = '--config <path>';
const CONFIG_DESC = 'Path to a custom config.json';

const program = new Command();

program
  .name(SERVER_NAME)
  .description('Local-first security advisory MCP server')
  .version(SERVER_VERSION);

program
  .command('serve')
  .description('Start the MCP server')
  .option('--transport <transport>', 'Transport to use (stdio)', 'stdio')
  .option(CONFIG_OPT, CONFIG_DESC)
  .action(async (options: ServeOptions) => {
    await runServe(options);
  });

program
  .command('sync')
  .description('Sync advisory sources into the local database')
  .option('--preset <preset>', 'Source preset (core|packages|ecosystems|context|all|research)', 'core')
  .option(CONFIG_OPT, CONFIG_DESC)
  .action(async (options: SyncOptions) => {
    await runSync(options);
  });

program
  .command('init')
  .description('Create the default config file and cache/db directories')
  .option(CONFIG_OPT, CONFIG_DESC)
  .option('--force', 'Overwrite an existing config file')
  .action(async (options: InitOptions) => {
    await runInit(options);
  });

program
  .command('doctor')
  .description('Check that the runtime environment can run advisory-mcp')
  .option(CONFIG_OPT, CONFIG_DESC)
  .action(async (options: DoctorOptions) => {
    await runDoctor(options);
  });

program
  .command('status')
  .description('Show local sync status and freshness for each source')
  .option(CONFIG_OPT, CONFIG_DESC)
  .action(async (options: StatusOptions) => {
    await runStatus(options);
  });

program
  .command('export')
  .description('Export the local advisory store as JSON')
  .option(CONFIG_OPT, CONFIG_DESC)
  .option('--format <format>', 'Output format (json)', 'json')
  .option('--limit <n>', 'Limit the number of advisories', (v) => Number.parseInt(v, 10), 0)
  .action(async (options: ExportOptions) => {
    await runExport(options);
  });

await program.parseAsync(process.argv);
