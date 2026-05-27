import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { closeStore, openStore, type DatabaseHandle } from './db.js';
import { AdvisoryRepository } from './repositories/advisory-repository.js';
import { escapeFtsQuery, SearchIndex } from './search-index.js';

const SENTINEL = 'advisoryrecord';

function seed(repo: AdvisoryRepository): void {
  repo.upsert({
    id: 'CVE-2021-44228',
    canonicalId: 'CVE-2021-44228',
    type: 'cve',
    title: 'Log4Shell remote code execution in Apache Log4j',
    description: `${SENTINEL} Log4j 2.x JNDI lookup allows remote code execution by attackers.`,
    mergedJson: '{}',
    aliases: ['GHSA-jfh8-c2jp-5v3q'],
  });
  repo.upsert({
    id: 'CVE-2024-3094',
    canonicalId: 'CVE-2024-3094',
    type: 'cve',
    title: 'XZ Utils backdoor',
    description: `${SENTINEL} A malicious backdoor was inserted into liblzma in XZ Utils 5.6.0 and 5.6.1.`,
    mergedJson: '{}',
  });
  repo.upsert({
    id: 'CVE-2023-12345',
    canonicalId: 'CVE-2023-12345',
    type: 'cve',
    title: 'Benign formatting bug in libfoo',
    description: `${SENTINEL} A low-severity formatting issue with no remote impact.`,
    mergedJson: '{}',
  });
}

describe('escapeFtsQuery', () => {
  it('quotes tokens to neutralize FTS5 operators', () => {
    expect(escapeFtsQuery('foo')).toBe('"foo"');
    expect(escapeFtsQuery('foo bar')).toBe('"foo" "bar"');
    expect(escapeFtsQuery('col:value-')).toBe('"col:value-"');
    expect(escapeFtsQuery('a "b" c')).toBe('"a" """b""" "c"');
  });

  it('returns an empty quoted token for empty input', () => {
    expect(escapeFtsQuery('   ')).toBe('""');
  });
});

describe('SearchIndex', () => {
  let db: DatabaseHandle;
  let repo: AdvisoryRepository;
  let index: SearchIndex;

  beforeEach(() => {
    db = openStore({ path: ':memory:', noWal: true });
    repo = new AdvisoryRepository(db);
    index = new SearchIndex(db);
    seed(repo);
    index.indexAdvisory({
      id: 'CVE-2021-44228',
      title: 'Log4Shell remote code execution in Apache Log4j',
      description: `${SENTINEL} Log4j 2.x JNDI lookup allows remote code execution by attackers.`,
      aliases: ['GHSA-jfh8-c2jp-5v3q'],
      severity: 'critical',
      hasFix: true,
      knownExploited: true,
    });
    index.indexAdvisory({
      id: 'CVE-2024-3094',
      title: 'XZ Utils backdoor',
      description: `${SENTINEL} A malicious backdoor was inserted into liblzma in XZ Utils 5.6.0 and 5.6.1.`,
      severity: 'critical',
      hasFix: true,
      knownExploited: false,
    });
    index.indexAdvisory({
      id: 'CVE-2023-12345',
      title: 'Benign formatting bug in libfoo',
      description: `${SENTINEL} A low-severity formatting issue with no remote impact.`,
      severity: 'low',
      hasFix: false,
      knownExploited: false,
    });
  });

  afterEach(() => {
    closeStore(db);
  });

  it('finds advisories by title token', () => {
    const hits = index.search({ query: 'log4shell' });
    expect(hits.map((h) => h.id)).toEqual(['CVE-2021-44228']);
  });

  it('finds advisories by description token', () => {
    const hits = index.search({ query: 'backdoor' });
    expect(hits.map((h) => h.id)).toEqual(['CVE-2024-3094']);
  });

  it('finds advisories by alias', () => {
    const hits = index.search({ query: 'GHSA-jfh8-c2jp-5v3q' });
    expect(hits.map((h) => h.id)).toEqual(['CVE-2021-44228']);
  });

  it('filters by severity', () => {
    const hits = index.search({ query: SENTINEL, severity: 'critical' });
    expect(hits.map((h) => h.id).sort()).toEqual(['CVE-2021-44228', 'CVE-2024-3094']);
  });

  it('filters by knownExploited', () => {
    const hits = index.search({
      query: SENTINEL,
      knownExploited: true,
    });
    expect(hits.map((h) => h.id)).toEqual(['CVE-2021-44228']);
  });

  it('filters by hasFix=false', () => {
    const hits = index.search({ query: SENTINEL, hasFix: false });
    expect(hits.map((h) => h.id)).toEqual(['CVE-2023-12345']);
  });

  it('respects the limit cap', () => {
    const hits = index.search({ query: SENTINEL, limit: 2 });
    expect(hits.length).toBeLessThanOrEqual(2);
  });

  it('re-indexing the same advisory updates its row instead of duplicating', () => {
    index.indexAdvisory({
      id: 'CVE-2024-3094',
      title: 'XZ Utils backdoor (updated)',
      description: 'updated description',
      severity: 'critical',
      hasFix: true,
      knownExploited: true,
    });
    const hits = index.search({ query: 'updated' });
    expect(hits.map((h) => h.id)).toEqual(['CVE-2024-3094']);
    const exploited = index.search({ query: 'backdoor', knownExploited: true });
    expect(exploited.map((h) => h.id)).toEqual(['CVE-2024-3094']);
  });
});
