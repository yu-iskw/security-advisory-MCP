import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { closeStore, openStore, type DatabaseHandle } from '../db.js';

import { AdvisoryRepository } from './advisory-repository.js';

describe('AdvisoryRepository', () => {
  let db: DatabaseHandle;
  let repo: AdvisoryRepository;

  beforeEach(() => {
    db = openStore({ path: ':memory:', noWal: true });
    repo = new AdvisoryRepository(db);
  });

  afterEach(() => {
    closeStore(db);
  });

  it('inserts a new advisory with aliases', () => {
    repo.upsert({
      id: 'CVE-2024-3094',
      canonicalId: 'CVE-2024-3094',
      type: 'cve',
      title: 'XZ Utils backdoor',
      mergedJson: '{}',
      aliases: ['GHSA-abcd-1234-efgh'],
    });

    expect(repo.count()).toBe(1);
    const row = repo.findById('CVE-2024-3094');
    expect(row?.title).toBe('XZ Utils backdoor');
    expect(repo.aliasesFor('CVE-2024-3094')).toEqual(['GHSA-abcd-1234-efgh']);
  });

  it('updates an existing advisory on second upsert', () => {
    repo.upsert({
      id: 'CVE-2021-44228',
      canonicalId: 'CVE-2021-44228',
      type: 'cve',
      title: 'old title',
      mergedJson: '{}',
    });
    repo.upsert({
      id: 'CVE-2021-44228',
      canonicalId: 'CVE-2021-44228',
      type: 'cve',
      title: 'Log4Shell',
      mergedJson: '{}',
    });
    expect(repo.count()).toBe(1);
    expect(repo.findById('CVE-2021-44228')?.title).toBe('Log4Shell');
  });

  it('finds an advisory by alias', () => {
    repo.upsert({
      id: 'GHSA-aaaa-bbbb-cccc',
      canonicalId: 'CVE-2024-9999',
      type: 'cve',
      mergedJson: '{}',
      aliases: ['CVE-2024-9999'],
    });
    const row = repo.findByAlias('CVE-2024-9999');
    expect(row?.id).toBe('GHSA-aaaa-bbbb-cccc');
  });

  it('returns undefined when no advisory matches', () => {
    expect(repo.findById('missing')).toBeUndefined();
    expect(repo.findByAlias('missing')).toBeUndefined();
  });

  it('deduplicates aliases on repeated upsert', () => {
    repo.upsert({
      id: 'CVE-2020-0001',
      canonicalId: 'CVE-2020-0001',
      type: 'cve',
      mergedJson: '{}',
      aliases: ['ALIAS-1', 'ALIAS-1', 'ALIAS-2'],
    });
    expect(repo.aliasesFor('CVE-2020-0001')).toEqual(['ALIAS-1', 'ALIAS-2']);
  });
});
