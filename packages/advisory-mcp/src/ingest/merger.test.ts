import { describe, expect, it } from 'vitest';

import { mergeAdvisory } from './merger.js';

import type { EvidenceRowForMerge } from './merger-types.js';

const KEV_ROW: EvidenceRowForMerge = {
  source: 'cisa-kev',
  evidenceType: 'known_exploited',
  title: 'XZ Utils Embedded Malicious Code Vulnerability',
  description: 'KEV-provided short description.',
  normalizedJson: JSON.stringify({ cveID: 'CVE-2024-3094', dateAdded: '2024-03-29' }),
};

const EPSS_ROW: EvidenceRowForMerge = {
  source: 'first-epss',
  evidenceType: 'epss_score',
  normalizedJson: JSON.stringify({ cve: 'CVE-2024-3094', epss: 0.91, percentile: 0.998 }),
};

const VULNRICHMENT_ROW: EvidenceRowForMerge = {
  source: 'cisa-vulnrichment',
  evidenceType: 'cisa_adp_enrichment',
  normalizedJson: JSON.stringify({
    cveId: 'CVE-2024-3094',
    provenance: 'adp',
    cwes: ['CWE-506'],
    ssvc: { other: { type: 'ssvc', content: { Exploitation: 'active' } } },
    cvss: { cvssV3_1: { baseScore: 9.8, baseSeverity: 'CRITICAL', vectorString: 'V3.1' } },
  }),
};

const CVEPROJECT_ROW: EvidenceRowForMerge = {
  source: 'cveproject',
  evidenceType: 'cve_record',
  title: 'XZ Utils Backdoor',
  description: 'A malicious backdoor was inserted into liblzma.',
  publishedAt: '2024-03-29T00:00:00.000Z',
  modifiedAt: '2024-04-01T00:00:00.000Z',
  normalizedJson: JSON.stringify({
    cveId: 'CVE-2024-3094',
    provenance: 'cna',
    cwes: ['CWE-506', 'CWE-94'],
    cvss: { cvssV3_1: { baseScore: 10.0, baseSeverity: 'CRITICAL', vectorString: 'CNA' } },
  }),
};

const NVD_ROW: EvidenceRowForMerge = {
  source: 'nvd-feed',
  evidenceType: 'nvd_enrichment',
  description: 'NVD enrichment description.',
  modifiedAt: '2024-05-01T00:00:00.000Z',
  normalizedJson: JSON.stringify({
    cveId: 'CVE-2024-3094',
    provenance: 'nvd',
    cwes: ['CWE-506'],
    cvss: { baseScore: 9.8, baseSeverity: 'CRITICAL', vectorString: 'NVD' },
  }),
};

describe('mergeAdvisory', () => {
  it('returns the empty-but-valid shape when no evidence exists', () => {
    const out = mergeAdvisory('CVE-2024-3094', []);
    expect(out.canonicalId).toBe('CVE-2024-3094');
    expect(out.cwes).toEqual([]);
    expect(out.severity).toBe('none');
    expect(out.knownExploited).toBe(false);
  });

  it('CNA title and description win over NVD', () => {
    const out = mergeAdvisory('CVE-2024-3094', [NVD_ROW, CVEPROJECT_ROW]);
    expect(out.title).toBe('XZ Utils Backdoor');
    expect(out.description).toBe('A malicious backdoor was inserted into liblzma.');
    expect(out.conflicts.some((c) => c.field === 'description')).toBe(true);
  });

  it('CVSS precedence: CNA > ADP > NVD', () => {
    const out = mergeAdvisory('CVE-2024-3094', [NVD_ROW, VULNRICHMENT_ROW, CVEPROJECT_ROW]);
    expect(out.cvss?.baseScore).toBe(10.0);
    expect(out.cvss?.source).toBe('cveproject');
  });

  it('falls back to ADP CVSS when CNA evidence is absent', () => {
    const out = mergeAdvisory('CVE-2024-3094', [NVD_ROW, VULNRICHMENT_ROW]);
    expect(out.cvss?.source).toBe('cisa-vulnrichment');
    expect(out.cvss?.baseScore).toBe(9.8);
  });

  it('takes the latest modifiedAt across sources', () => {
    const out = mergeAdvisory('CVE-2024-3094', [CVEPROJECT_ROW, NVD_ROW]);
    expect(out.modifiedAt).toBe('2024-05-01T00:00:00.000Z');
  });

  it('marks knownExploited true when KEV evidence exists', () => {
    const out = mergeAdvisory('CVE-2024-3094', [KEV_ROW]);
    expect(out.knownExploited).toBe(true);
    expect(out.exploitationSources).toContain('cisa-kev');
  });

  it('surfaces SSVC as a secondary exploitation source', () => {
    const out = mergeAdvisory('CVE-2024-3094', [VULNRICHMENT_ROW]);
    expect(out.exploitationSources).toContain('cisa-vulnrichment-ssvc');
  });

  it('unions CWEs from all sources, keeping the first source as provenance', () => {
    const out = mergeAdvisory('CVE-2024-3094', [NVD_ROW, CVEPROJECT_ROW, VULNRICHMENT_ROW]);
    const ids = out.cwes.map((c) => c.cweId).sort();
    expect(ids).toEqual(['CWE-506', 'CWE-94']);
    const cwe506 = out.cwes.find((c) => c.cweId === 'CWE-506');
    // cveproject has higher priority than nvd-feed; it should own the entry.
    expect(cwe506?.source).toBe('cveproject');
  });

  it('attaches EPSS scores from first-epss', () => {
    const out = mergeAdvisory('CVE-2024-3094', [EPSS_ROW]);
    expect(out.epss).toMatchObject({ probability: 0.91, percentile: 0.998 });
  });

  it('end-to-end golden case (CVE-2024-3094) — all 5 sources', () => {
    const out = mergeAdvisory('CVE-2024-3094', [
      KEV_ROW,
      EPSS_ROW,
      VULNRICHMENT_ROW,
      CVEPROJECT_ROW,
      NVD_ROW,
    ]);
    expect(out.title).toBe('XZ Utils Backdoor'); // CNA wins
    expect(out.cvss?.source).toBe('cveproject');
    expect(out.severity).toBe('critical');
    expect(out.knownExploited).toBe(true);
    expect(out.epss?.probability).toBeCloseTo(0.91);
    expect(out.modifiedAt).toBe('2024-05-01T00:00:00.000Z');
    expect(out.cwes.map((c) => c.cweId).sort()).toEqual(['CWE-506', 'CWE-94']);
    expect(out.conflicts.length).toBeGreaterThanOrEqual(1); // title or description disagreement
  });

  it('does not invent a conflict when only one source contributes a field', () => {
    const out = mergeAdvisory('CVE-2024-3094', [CVEPROJECT_ROW]);
    expect(out.conflicts).toEqual([]);
  });
});
