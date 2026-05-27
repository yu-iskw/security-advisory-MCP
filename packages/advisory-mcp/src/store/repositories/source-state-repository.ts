import type { DatabaseHandle } from '../db.js';

type SourceStatus = 'never_synced' | 'syncing' | 'success' | 'error';

interface SourceStateRow {
  source: string;
  enabled: boolean;
  preset: string;
  lastSyncStartedAt: string | null;
  lastSyncCompletedAt: string | null;
  lastSuccessAt: string | null;
  lastError: string | null;
  version: string | null;
  etag: string | null;
  lastModified: string | null;
  sha256: string | null;
  status: SourceStatus;
}

interface UpsertSourceStateInput {
  source: string;
  enabled: boolean;
  preset: string;
  status: SourceStatus;
  lastSyncStartedAt?: string;
  lastSyncCompletedAt?: string;
  lastSuccessAt?: string;
  lastError?: string;
  version?: string;
  etag?: string;
  lastModified?: string;
  sha256?: string;
}

interface DbSourceStateRow {
  source: string;
  enabled: number;
  preset: string;
  last_sync_started_at: string | null;
  last_sync_completed_at: string | null;
  last_success_at: string | null;
  last_error: string | null;
  version: string | null;
  etag: string | null;
  last_modified: string | null;
  sha256: string | null;
  status: string;
}

function rowFromDb(row: DbSourceStateRow): SourceStateRow {
  return {
    source: row.source,
    enabled: row.enabled !== 0,
    preset: row.preset,
    lastSyncStartedAt: row.last_sync_started_at,
    lastSyncCompletedAt: row.last_sync_completed_at,
    lastSuccessAt: row.last_success_at,
    lastError: row.last_error,
    version: row.version,
    etag: row.etag,
    lastModified: row.last_modified,
    sha256: row.sha256,
    status: row.status as SourceStatus,
  };
}

export class SourceStateRepository {
  constructor(private readonly db: DatabaseHandle) {}

  upsert(input: UpsertSourceStateInput): void {
    this.db
      .prepare(
        `
        INSERT INTO source_state (
          source, enabled, preset, status,
          last_sync_started_at, last_sync_completed_at, last_success_at, last_error,
          version, etag, last_modified, sha256
        ) VALUES (
          @source, @enabled, @preset, @status,
          @lastSyncStartedAt, @lastSyncCompletedAt, @lastSuccessAt, @lastError,
          @version, @etag, @lastModified, @sha256
        )
        ON CONFLICT(source) DO UPDATE SET
          enabled                = excluded.enabled,
          preset                 = excluded.preset,
          status                 = excluded.status,
          last_sync_started_at   = COALESCE(excluded.last_sync_started_at,   source_state.last_sync_started_at),
          last_sync_completed_at = COALESCE(excluded.last_sync_completed_at, source_state.last_sync_completed_at),
          last_success_at        = COALESCE(excluded.last_success_at,        source_state.last_success_at),
          last_error             = excluded.last_error,
          version                = COALESCE(excluded.version,       source_state.version),
          etag                   = COALESCE(excluded.etag,          source_state.etag),
          last_modified          = COALESCE(excluded.last_modified, source_state.last_modified),
          sha256                 = COALESCE(excluded.sha256,        source_state.sha256)
      `,
      )
      .run({
        source: input.source,
        enabled: input.enabled ? 1 : 0,
        preset: input.preset,
        status: input.status,
        lastSyncStartedAt: input.lastSyncStartedAt ?? null,
        lastSyncCompletedAt: input.lastSyncCompletedAt ?? null,
        lastSuccessAt: input.lastSuccessAt ?? null,
        lastError: input.lastError ?? null,
        version: input.version ?? null,
        etag: input.etag ?? null,
        lastModified: input.lastModified ?? null,
        sha256: input.sha256 ?? null,
      });
  }

  findBySource(source: string): SourceStateRow | undefined {
    const row = this.db
      .prepare('SELECT * FROM source_state WHERE source = ?')
      .get(source) as DbSourceStateRow | undefined;
    return row ? rowFromDb(row) : undefined;
  }

  listAll(): SourceStateRow[] {
    const rows = this.db
      .prepare('SELECT * FROM source_state ORDER BY source')
      .all() as DbSourceStateRow[];
    return rows.map(rowFromDb);
  }
}
