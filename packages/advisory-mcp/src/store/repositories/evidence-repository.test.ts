import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { closeStore, openStore, type DatabaseHandle } from '../db.js';

import { AdvisoryRepository } from './advisory-repository.js';
import { EvidenceRepository } from './evidence-repository.js';

describe('EvidenceRepository', () => {
  let db: DatabaseHandle;
  let evidence: EvidenceRepository;

  beforeEach(() => {
    db = openStore({ path: ':memory:', noWal: true });
    new AdvisoryRepository(db).upsert({
      id: 'CVE-2024-3094',
      canonicalId: 'CVE-2024-3094',
      type: 'cve',
      mergedJson: '{}',
    });
    evidence = new EvidenceRepository(db);
  });

  afterEach(() => {
    closeStore(db);
  });

  it('inserts and reads evidence rows', () => {
    evidence.upsert({
      id: 'kev:CVE-2024-3094',
      advisoryId: 'CVE-2024-3094',
      source: 'cisa-kev',
      type: 'known_exploited',
      fetchedAt: '2026-05-27T00:00:00.000Z',
      confidence: 0.95,
      trustTier: 'A',
      summary: 'XZ Utils backdoor listed in KEV.',
      normalizedJson: '{}',
    });

    expect(evidence.count()).toBe(1);
    const rows = evidence.findByAdvisoryId('CVE-2024-3094');
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      source: 'cisa-kev',
      confidence: 0.95,
      trustTier: 'A',
    });
  });

  it('upsert overwrites by evidence id', () => {
    evidence.upsert({
      id: 'kev:CVE-2024-3094',
      advisoryId: 'CVE-2024-3094',
      source: 'cisa-kev',
      type: 'known_exploited',
      fetchedAt: '2026-05-27T00:00:00.000Z',
      confidence: 0.5,
      trustTier: 'A',
      summary: 'first',
      normalizedJson: '{}',
    });
    evidence.upsert({
      id: 'kev:CVE-2024-3094',
      advisoryId: 'CVE-2024-3094',
      source: 'cisa-kev',
      type: 'known_exploited',
      fetchedAt: '2026-05-28T00:00:00.000Z',
      confidence: 0.95,
      trustTier: 'A',
      summary: 'updated',
      normalizedJson: '{}',
    });
    const rows = evidence.findByAdvisoryId('CVE-2024-3094');
    expect(rows).toHaveLength(1);
    expect(rows[0]?.summary).toBe('updated');
    expect(rows[0]?.confidence).toBe(0.95);
  });

  it('cascades on advisory delete', () => {
    evidence.upsert({
      id: 'e1',
      advisoryId: 'CVE-2024-3094',
      source: 'cisa-kev',
      type: 'known_exploited',
      fetchedAt: '2026-05-27T00:00:00.000Z',
      confidence: 0.95,
      trustTier: 'A',
      summary: 's',
      normalizedJson: '{}',
    });
    db.prepare('DELETE FROM advisories WHERE id = ?').run('CVE-2024-3094');
    expect(evidence.count()).toBe(0);
  });
});
