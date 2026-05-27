import { closeStore, openStore, type DatabaseHandle } from './db.js';
import { AdvisoryRepository } from './repositories/advisory-repository.js';
import { AffectedPackagesRepository } from './repositories/affected-packages-repository.js';
import { EvidenceRepository } from './repositories/evidence-repository.js';
import { SourceStateRepository } from './repositories/source-state-repository.js';
import { SearchIndex } from './search-index.js';

export interface AdvisoryStore {
  db: DatabaseHandle;
  advisories: AdvisoryRepository;
  affectedPackages: AffectedPackagesRepository;
  evidence: EvidenceRepository;
  sourceState: SourceStateRepository;
  search: SearchIndex;
  close(): void;
}

interface OpenAdvisoryStoreOptions {
  path: string;
  noWal?: boolean;
}

export function openAdvisoryStore(options: OpenAdvisoryStoreOptions): AdvisoryStore {
  const db = openStore(options);
  return {
    db,
    advisories: new AdvisoryRepository(db),
    affectedPackages: new AffectedPackagesRepository(db),
    evidence: new EvidenceRepository(db),
    sourceState: new SourceStateRepository(db),
    search: new SearchIndex(db),
    close: () => {
      closeStore(db);
    },
  };
}
