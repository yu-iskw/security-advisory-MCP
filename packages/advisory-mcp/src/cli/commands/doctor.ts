import { access, constants } from 'node:fs/promises';
import { dirname } from 'node:path';

import { loadConfig } from '../../config/config.js';
import { SERVER_VERSION } from '../../mcp/server.js';
import { openAdvisoryStore } from '../../store/store.js';

export interface DoctorOptions {
  config?: string;
}

const NODE_MIN_MAJOR = 22;

interface Check {
  name: string;
  ok: boolean;
  detail: string;
}

export async function runDoctor(options: DoctorOptions): Promise<void> {
  const config = await loadConfig({ configPath: options.config });
  const checks: Check[] = [];

  checks.push(checkNodeVersion());
  checks.push(await checkDatabasePath(config.databasePath));
  checks.push(checkFts5AndStore(config.databasePath));
  checks.push({
    name: 'advisory-mcp version',
    ok: true,
    detail: SERVER_VERSION,
  });

  for (const c of checks) {
    const flag = c.ok ? '[ok]  ' : '[!]   ';
    process.stdout.write(`${flag}${c.name}: ${c.detail}\n`);
  }

  if (checks.some((c) => !c.ok)) process.exitCode = 1;
}

function checkNodeVersion(): Check {
  const major = Number.parseInt(process.versions.node.split('.')[0] ?? '0', 10);
  const ok = major >= NODE_MIN_MAJOR;
  return {
    name: 'Node.js',
    ok,
    detail: `${process.versions.node}${ok ? '' : ` (require >=${String(NODE_MIN_MAJOR)})`}`,
  };
}

async function checkDatabasePath(path: string): Promise<Check> {
  const parent = dirname(path);
  try {
    await access(parent, constants.W_OK);
    return { name: 'database parent dir writable', ok: true, detail: parent };
  } catch {
    return {
      name: 'database parent dir writable',
      ok: false,
      detail: `${parent} (not writable; run \`advisory-mcp init\`)`,
    };
  }
}

function checkFts5AndStore(databasePath: string): Check {
  try {
    const store = openAdvisoryStore({ path: ':memory:', noWal: true });
    try {
      // FTS5 was already exercised by openStore migrations; do an explicit insert
      // to confirm the binary supports it.
      store.search.indexAdvisory({ id: 'CVE-0000-0001', title: 'doctor', knownExploited: false });
      return {
        name: 'SQLite FTS5',
        ok: true,
        detail: `available; database at ${databasePath}`,
      };
    } finally {
      store.close();
    }
  } catch (err) {
    return {
      name: 'SQLite FTS5',
      ok: false,
      detail: `unavailable: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}
