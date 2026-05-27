import type { DatabaseHandle } from './db.js';

type SeverityLabel = 'low' | 'medium' | 'high' | 'critical';

interface IndexAdvisoryInput {
  id: string;
  title?: string;
  description?: string;
  aliases?: string[];
  severity?: SeverityLabel;
  hasFix?: boolean;
  knownExploited?: boolean;
}

interface SearchQuery {
  /** FTS5 MATCH expression. Required. */
  query: string;
  severity?: SeverityLabel;
  hasFix?: boolean;
  knownExploited?: boolean;
  limit?: number;
}

interface SearchHit {
  id: string;
  rank: number;
}

/**
 * Escape a user-supplied query string for safe inclusion in an FTS5 MATCH.
 * Wraps each whitespace-separated token in double quotes and escapes any
 * embedded double quotes per the FTS5 syntax (`""` for a literal `"`).
 *
 * Without escaping, characters like `:` or `-` would be parsed by FTS5 as
 * column filters or operators and could either produce surprising results
 * or trigger syntax errors.
 */
export function escapeFtsQuery(input: string): string {
  const trimmed = input.trim();
  if (trimmed === '') return '""';
  return trimmed
    .split(/\s+/)
    .map((token) => `"${token.replace(/"/g, '""')}"`)
    .join(' ');
}

export class SearchIndex {
  constructor(private readonly db: DatabaseHandle) {}

  indexAdvisory(input: IndexAdvisoryInput): void {
    const updateFilters = this.db.prepare(`
      UPDATE advisories
      SET severity        = @severity,
          has_fix         = @hasFix,
          known_exploited = @knownExploited
      WHERE id = @id
    `);
    const deleteFts = this.db.prepare('DELETE FROM advisory_fts WHERE id = ?');
    const insertFts = this.db.prepare(`
      INSERT INTO advisory_fts (id, title, description, aliases)
      VALUES (@id, @title, @description, @aliases)
    `);

    const tx = this.db.transaction((data: IndexAdvisoryInput) => {
      updateFilters.run({
        id: data.id,
        severity: data.severity ?? null,
        hasFix: data.hasFix ? 1 : 0,
        knownExploited: data.knownExploited ? 1 : 0,
      });
      deleteFts.run(data.id);
      insertFts.run({
        id: data.id,
        title: data.title ?? '',
        description: data.description ?? '',
        aliases: (data.aliases ?? []).join(' '),
      });
    });

    tx(input);
  }

  search(query: SearchQuery): SearchHit[] {
    const limit = Math.min(Math.max(query.limit ?? 10, 1), 50);
    const match = escapeFtsQuery(query.query);

    const stmt = this.db.prepare(`
      SELECT a.id AS id, fts.rank AS rank
      FROM advisory_fts AS fts
      JOIN advisories   AS a ON a.id = fts.id
      WHERE advisory_fts MATCH @match
        AND (@severity        IS NULL OR a.severity        = @severity)
        AND (@hasFix          IS NULL OR a.has_fix         = @hasFix)
        AND (@knownExploited  IS NULL OR a.known_exploited = @knownExploited)
      ORDER BY fts.rank
      LIMIT @limit
    `);

    return stmt.all({
      match,
      severity: query.severity ?? null,
      hasFix: query.hasFix === undefined ? null : query.hasFix ? 1 : 0,
      knownExploited:
        query.knownExploited === undefined ? null : query.knownExploited ? 1 : 0,
      limit,
    }) as SearchHit[];
  }
}
