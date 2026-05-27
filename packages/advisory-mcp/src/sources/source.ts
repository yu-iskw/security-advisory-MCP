import type { NormalizedRecord } from '../ingest/merger.js';
import type { TrustTier } from '../schemas/evidence.js';
import type { SyncPreset, SourceId } from '../schemas/source.js';

export interface SourceDefinition {
  id: SourceId;
  displayName: string;
  trustTier: TrustTier;
  defaultPreset: SyncPreset;
  fixtureSubdir: string;
}

export interface SyncSourceResult {
  source: SourceId;
  recordsProcessed: number;
  recordsChanged: number;
  error?: string;
}

export type FixtureLoader = (fixtureRoot: string) => NormalizedRecord[];
