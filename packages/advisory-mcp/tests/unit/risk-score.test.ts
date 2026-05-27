import { describe, expect, it } from 'vitest';

import type { Advisory } from '../../src/schemas/advisory.js';
import { computeRiskScore } from '../../src/risk/score.js';

const baseAdvisory: Advisory = {
  id: 'CVE-2021-44228',
  canonicalId: 'CVE-2021-44228',
  type: 'cve',
  aliases: [],
  affected: [],
  cwes: [],
  cvss: [{ version: '3.1', score: 10, severity: 'CRITICAL' }],
  kev: { cve: 'CVE-2021-44228' },
  epss: { cve: 'CVE-2021-44228', epss: 0.97, percentile: 0.99, date: '2024-01-01' },
  references: [],
  sourceDisagreements: [],
};

describe('risk score', () => {
  it('scores KEV + critical CVSS highly', () => {
    const risk = computeRiskScore(baseAdvisory, [], 'internet_exposed');
    expect(risk.score).toBeGreaterThan(70);
    expect(risk.severity).toMatch(/high|critical/);
  });
});
