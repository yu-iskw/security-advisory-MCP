import { loadConfig } from '../../config/config.js';
import { openAdvisoryStore } from '../../store/store.js';

export interface ExportOptions {
  config?: string;
  format?: string;
  limit?: number;
}

export async function runExport(options: ExportOptions): Promise<void> {
  const format = options.format ?? 'json';
  if (format !== 'json') {
    process.stderr.write(`Unsupported export format: ${format}. Supported: json\n`);
    process.exit(2);
  }
  const config = await loadConfig({ configPath: options.config });
  const store = openAdvisoryStore({ path: config.databasePath });
  try {
    const limit = options.limit ?? 0;
    const sql = limit > 0
      ? `SELECT id, canonical_id, merged_json FROM advisories LIMIT ${String(limit)}`
      : `SELECT id, canonical_id, merged_json FROM advisories`;
    const rows = store.db.prepare(sql).all() as {
      id: string;
      canonical_id: string;
      merged_json: string;
    }[];
    process.stdout.write('[\n');
    rows.forEach((row, i) => {
      const tail = i === rows.length - 1 ? '\n' : ',\n';
      process.stdout.write(`  ${row.merged_json}${tail}`);
    });
    process.stdout.write(']\n');
  } finally {
    store.close();
  }
}
