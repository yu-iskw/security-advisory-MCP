#!/usr/bin/env node
import { Command } from 'commander';

import { SERVER_VERSION } from '../mcp/server.js';

import { formatDoctorReport, runDoctor } from './commands/doctor.js';
import { runInit } from './commands/init.js';
import { runServe } from './commands/serve.js';
import { runStatus } from './commands/status.js';
import { runSync } from './commands/sync.js';

const DB_OPTION = '--database <path>';
const DB_OPTION_DESC = 'SQLite database path';

const program = new Command();

program
  .name('advisory-mcp')
  .description('Local-first security advisory MCP server')
  .version(SERVER_VERSION);

program
  .command('init')
  .description('Initialize local config, cache, and database schema')
  .option(DB_OPTION, DB_OPTION_DESC)
  .option('--cache <path>', 'Download cache path')
  .action((options: { database?: string; cache?: string }) => {
    const result = runInit({ databasePath: options.database, cachePath: options.cache });
    process.stdout.write(
      `Initialized advisory-mcp\nDatabase: ${result.databasePath}\nCache: ${result.cachePath}\n`,
    );
  });

program
  .command('sync')
  .description('Sync public keyless advisory feeds into the local database')
  .requiredOption(
    '--preset <preset>',
    'Sync preset: core, packages, ecosystems, context, all, research',
  )
  .option(DB_OPTION, DB_OPTION_DESC)
  .option('--fixtures <path>', 'Load deterministic fixture feeds (tests)')
  .action((options: { preset: string; database?: string; fixtures?: string }) => {
    const result = runSync({
      preset: options.preset,
      databasePath: options.database,
      fixturesPath: options.fixtures,
    });
    process.stdout.write(`${result.message}\n`);
  });

program
  .command('status')
  .description('Show local database and source freshness summary')
  .option(DB_OPTION, DB_OPTION_DESC)
  .action((options: { database?: string }) => {
    process.stdout.write(`${runStatus({ databasePath: options.database })}\n`);
  });

program
  .command('doctor')
  .description('Validate environment, SQLite FTS5, and database readiness')
  .option(DB_OPTION, DB_OPTION_DESC)
  .action((options: { database?: string }) => {
    const report = runDoctor({ databasePath: options.database });
    process.stdout.write(`${formatDoctorReport(report)}\n`);
    if (!report.ok) {
      process.exitCode = 1;
    }
  });

program
  .command('serve')
  .description('Start the MCP server')
  .option('--transport <transport>', 'Transport: stdio or http', 'stdio')
  .option('--port <port>', 'HTTP port (http transport only)', '8765')
  .option(DB_OPTION, DB_OPTION_DESC)
  .action(async (options: { transport: string; port: string; database?: string }) => {
    const transport = options.transport === 'http' ? 'http' : 'stdio';
    await runServe({
      transport,
      port: Number.parseInt(options.port, 10),
      databasePath: options.database,
    });
  });

program.parseAsync(process.argv).catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
