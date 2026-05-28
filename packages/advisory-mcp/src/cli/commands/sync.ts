import { loadConfig } from '../../config/config.js';
import { HttpsDownloader } from '../../ingest/downloader.js';
import { SyncEngine } from '../../ingest/sync-engine.js';
import { FileAuditor, NoopAuditor } from '../../security/audit.js';
import { UrlPolicy } from '../../security/url-policy.js';
import { CISA_KEV_HOST, CisaKevSource } from '../../sources/cisa-kev.js';
import { CISA_VULNRICHMENT_HOST, CisaVulnrichmentSource } from '../../sources/cisa-vulnrichment.js';
import { CVEPROJECT_HOST, CveProjectSource } from '../../sources/cveproject.js';
import { FIRST_EPSS_HOST, FirstEpssSource } from '../../sources/first-epss.js';
import { NUCLEI_HOST, NucleiTemplatesSource } from '../../sources/nuclei-templates.js';
import { NVD_HOST, NvdFeedsSource } from '../../sources/nvd-feeds.js';
import { OSSF_MALICIOUS_HOST, OssfMaliciousPackagesSource } from '../../sources/ossf-malicious-packages.js';
import {
  createGoVulnDbSource,
  createPypaSource,
  createRustSecSource,
} from '../../sources/osv-ecosystem.js';
import { OSV_GITHUB_HOST, OsvGithubSource } from '../../sources/osv-github.js';
import { SourceRegistry } from '../../sources/registry.js';
import { openStore, closeStore } from '../../store/db.js';
import { createLogger } from '../../util/logger.js';

import type { SyncPreset } from '../../sources/source.js';

export interface SyncOptions {
  preset: string;
  config?: string;
  acceptResearchSources?: boolean;
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

function buildRegistry(
  sources: Record<string, { enabled: boolean } | undefined>,
  acceptResearch: boolean,
): SourceRegistry {
  const registry = new SourceRegistry();
  const enabled = (id: string): boolean =>
    // eslint-disable-next-line security/detect-object-injection -- id passed by buildRegistry, all literals
    sources[id]?.enabled === true;
  if (enabled('cisa-kev')) registry.register(new CisaKevSource());
  if (enabled('first-epss')) registry.register(new FirstEpssSource());
  if (enabled('cisa-vulnrichment')) registry.register(new CisaVulnrichmentSource());
  if (enabled('cveproject')) registry.register(new CveProjectSource());
  if (enabled('nvd-feed')) registry.register(new NvdFeedsSource());
  if (enabled('osv')) registry.register(new OsvGithubSource());
  if (enabled('ossf-malicious-packages')) registry.register(new OssfMaliciousPackagesSource());
  if (enabled('rustsec')) registry.register(createRustSecSource());
  if (enabled('pypa')) registry.register(createPypaSource());
  if (enabled('go-vulndb')) registry.register(createGoVulnDbSource());
  if (acceptResearch) registry.register(new NucleiTemplatesSource());
  return registry;
}

export async function runSync(options: SyncOptions): Promise<void> {
  if (!isValidPreset(options.preset)) {
    process.stderr.write(
      `Unknown preset: ${options.preset}. Valid: ${[...VALID_PRESETS].join(', ')}\n`,
    );
    process.exit(2);
  }
  if (options.preset === 'research' && options.acceptResearchSources !== true) {
    process.stderr.write(
      'The research preset includes lower-trust sources (Nuclei templates, ' +
        'Exploit-DB and Metasploit metadata). Re-run with ' +
        '`--accept-research-sources` to acknowledge and proceed.\n',
    );
    process.exit(2);
  }

  const config = await loadConfig({ configPath: options.config });
  const logger = createLogger({ level: config.logLevel });

  // Allowlisted hosts grow as adapters are added.
  const policy = new UrlPolicy({
    allowedHosts: [
      CISA_KEV_HOST,
      FIRST_EPSS_HOST,
      CISA_VULNRICHMENT_HOST,
      CVEPROJECT_HOST,
      NVD_HOST,
      OSV_GITHUB_HOST,
      OSSF_MALICIOUS_HOST,
      NUCLEI_HOST,
    ],
  });
  const downloader = new HttpsDownloader(policy);

  const registry = buildRegistry(config.sources, options.acceptResearchSources === true);

  const adapters = registry.resolvePreset(options.preset);
  if (adapters.length === 0) {
    logger.warn('sync_no_adapters', { preset: options.preset });
    process.stdout.write(`No enabled sources for preset "${options.preset}".\n`);
    return;
  }

  const auditor = config.auditLogPath
    ? new FileAuditor({ path: config.auditLogPath })
    : new NoopAuditor();
  const db = openStore({ path: config.databasePath });
  try {
    const engine = new SyncEngine({ db, downloader, cacheDir: config.cachePath, auditor });
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
