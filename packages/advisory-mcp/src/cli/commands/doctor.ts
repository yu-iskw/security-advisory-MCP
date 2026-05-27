import fs from 'node:fs';

import Database from 'better-sqlite3';

import { isStoreInitialized, openStore } from '../../store/db.js';
import { resolvePaths } from '../../util/paths.js';

export interface DoctorCheck {
  name: string;
  ok: boolean;
  detail: string;
}

export interface DoctorReport {
  checks: DoctorCheck[];
  ok: boolean;
}

export function runDoctor(options: { databasePath?: string } = {}): DoctorReport {
  const paths = resolvePaths({ databasePath: options.databasePath });
  const checks: DoctorCheck[] = [];

  const nodeMajor = Number.parseInt(process.versions.node.split('.')[0] ?? '0', 10);
  checks.push({
    name: 'node-version',
    ok: nodeMajor >= 20,
    detail: `Node.js ${process.version} (requires >=20)`,
  });

  checks.push({
    name: 'database-directory',
    ok: fs.existsSync(paths.configDir) || true,
    detail: paths.configDir,
  });

  let ftsOk = false;
  try {
    const probe = new Database(':memory:');
    probe.exec('CREATE VIRTUAL TABLE fts_probe USING fts5(content)');
    probe.close();
    ftsOk = true;
  } catch (error) {
    checks.push({
      name: 'sqlite-fts5',
      ok: false,
      detail: error instanceof Error ? error.message : String(error),
    });
  }
  if (ftsOk) {
    checks.push({
      name: 'sqlite-fts5',
      ok: true,
      detail: 'FTS5 available',
    });
  }

  const initialized = isStoreInitialized(paths.databasePath);
  checks.push({
    name: 'database-initialized',
    ok: initialized,
    detail: initialized
      ? `Database ready at ${paths.databasePath}`
      : `Not initialized — run advisory-mcp init && advisory-mcp sync --preset core`,
  });

  if (initialized) {
    const store = openStore({ databasePath: paths.databasePath, readonly: true });
    try {
      const stale = store.db
        .prepare(
          `SELECT COUNT(*) AS count FROM source_state WHERE status IN ('never_synced', 'stale', 'error')`,
        )
        .get() as { count: number };
      checks.push({
        name: 'source-freshness',
        ok: stale.count === 0,
        detail:
          stale.count === 0
            ? 'All sources report ok/synced state'
            : `${stale.count} source(s) need sync or attention`,
      });
    } finally {
      store.close();
    }
  }

  const ok = checks.every((check) => check.ok);
  return { checks, ok };
}

export function formatDoctorReport(report: DoctorReport): string {
  const lines = ['# advisory-mcp doctor', ''];
  for (const check of report.checks) {
    lines.push(`${check.ok ? '✓' : '✗'} ${check.name}: ${check.detail}`);
  }
  lines.push('', report.ok ? 'All checks passed.' : 'Some checks failed.');
  return lines.join('\n');
}
