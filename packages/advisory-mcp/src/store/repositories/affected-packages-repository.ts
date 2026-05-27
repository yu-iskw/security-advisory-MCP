import type { DatabaseHandle } from '../db.js';

interface AffectedPackageInput {
  advisoryId: string;
  ecosystem: string;
  name: string;
  purl?: string;
  vulnerableRange?: string;
  fixedVersion?: string;
  source: string;
  confidence: number;
}

interface AffectedPackageRow {
  advisoryId: string;
  ecosystem: string;
  name: string;
  purl: string | null;
  vulnerableRange: string | null;
  fixedVersion: string | null;
  source: string;
  confidence: number;
}

interface DbAffectedPackageRow {
  advisory_id: string;
  ecosystem: string;
  name: string;
  purl: string | null;
  vulnerable_range: string | null;
  fixed_version: string | null;
  source: string;
  confidence: number;
}

function rowFromDb(row: DbAffectedPackageRow): AffectedPackageRow {
  return {
    advisoryId: row.advisory_id,
    ecosystem: row.ecosystem,
    name: row.name,
    purl: row.purl,
    vulnerableRange: row.vulnerable_range,
    fixedVersion: row.fixed_version,
    source: row.source,
    confidence: row.confidence,
  };
}

export class AffectedPackagesRepository {
  constructor(private readonly db: DatabaseHandle) {}

  replaceForAdvisory(advisoryId: string, packages: ReadonlyArray<AffectedPackageInput>): void {
    const del = this.db.prepare('DELETE FROM affected_packages WHERE advisory_id = ?');
    const ins = this.db.prepare(`
      INSERT INTO affected_packages
        (advisory_id, ecosystem, name, purl, vulnerable_range, fixed_version, source, confidence)
      VALUES
        (@advisoryId, @ecosystem, @name, @purl, @vulnerableRange, @fixedVersion, @source, @confidence)
    `);
    const tx = this.db.transaction((rows: ReadonlyArray<AffectedPackageInput>) => {
      del.run(advisoryId);
      for (const p of rows) {
        ins.run({
          advisoryId: p.advisoryId,
          ecosystem: p.ecosystem,
          name: p.name,
          purl: p.purl ?? null,
          vulnerableRange: p.vulnerableRange ?? null,
          fixedVersion: p.fixedVersion ?? null,
          source: p.source,
          confidence: p.confidence,
        });
      }
    });
    tx(packages);
  }

  findByEcosystemAndName(ecosystem: string, name: string): AffectedPackageRow[] {
    const rows = this.db
      .prepare(
        'SELECT * FROM affected_packages WHERE ecosystem = ? AND name = ? ORDER BY advisory_id',
      )
      .all(ecosystem, name) as DbAffectedPackageRow[];
    return rows.map(rowFromDb);
  }
}
