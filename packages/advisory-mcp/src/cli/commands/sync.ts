import { loadConfig } from '../../config/config.js';
import { HttpsDownloader } from '../../ingest/downloader.js';
import { SyncEngine } from '../../ingest/sync-engine.js';
import { UrlPolicy } from '../../security/url-policy.js';
import { CISA_KEV_HOST, CisaKevSource } from '../../sources/cisa-kev.js';
import { FIRST_EPSS_HOST, FirstEpssSource } from '../../sources/first-epss.js';
import { SourceRegistry } from '../../sources/registry.js';
import { openStore, closeStore } from '../../store/db.js';
import { createLogger } from '../../util/logger.js';

import type { SyncPreset } from '../../sources/source.js';

export interface SyncOptions {
  preset: string;
  config?: string;
}

const VALID_PRESETS = new Set<SyncPreset | 'all'>([
  'core',
  'packages',
  'ecosystems',
  'context',
  'all',
  'research',
]);

function isValidPreset(value: string): value is SyncPreset | 'all' {
  return (VALID_PRESETS as Set<string>).has(value);
}

export async function runSync(options: SyncOptions): Promise<void> {
  if (!isValidPreset(options.preset)) {
    process.stderr.write(
      `Unknown preset: ${options.preset}. Valid: ${[...VALID_PRESETS].join(', ')}\n`,
    );
    process.exit(2);
  }

  const config = await loadConfig({ configPath: options.config });
  const logger = createLogger({ level: config.logLevel });

  // Allowlisted hosts grow as adapters are added.
  const policy = new UrlPolicy({ allowedHosts: [CISA_KEV_HOST, FIRST_EPSS_HOST] });
  const downloader = new HttpsDownloader(policy);

  const registry = new SourceRegistry();
  if (config.sources['cisa-kev']?.enabled) {
    registry.register(new CisaKevSource());
  }
  if (config.sources['first-epss']?.enabled) {
    registry.register(new FirstEpssSource());
  }

  const adapters = registry.resolvePreset(options.preset);
  if (adapters.length === 0) {
    logger.warn('sync_no_adapters', { preset: options.preset });
    process.stdout.write(`No enabled sources for preset "${options.preset}".\n`);
    return;
  }

  const db = openStore({ path: config.databasePath });
  try {
    const engine = new SyncEngine({ db, downloader, cacheDir: config.cachePath });
    for (const adapter of adapters) {
      logger.info('sync_source_started', { source: adapter.id });
      const result = await engine.syncOne(adapter);
      logger.info('sync_source_completed', { ...result });
      process.stdout.write(
        `${adapter.id}: ${result.status}${result.records ? ` (${result.records} records)` : ''}` +
          ` in ${result.durationMs}ms${result.error ? ` — ${result.error}` : ''}\n`,
      );
    }
  } finally {
    closeStore(db);
  }
}
