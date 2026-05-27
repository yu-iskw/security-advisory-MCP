import { describe, expect, it } from 'vitest';

import { scoreRisk } from './score.js';

describe('scoreRisk', () => {
  it('returns 0/none when there is no positive evidence', () => {
    const r = scoreRisk('default', { knownExploited: false, evidenceConfidences: [] });
    expect(r.score).toBe(0);
    expect(r.severity).toBe('none');
  });

  it('credits the KEV driver fully when knownExploited=true', () => {
    const r = scoreRisk('default', { knownExploited: true, evidenceConfidences: [0.9] });
    const kev = r.drivers.find((d) => d.kind === 'known_exploited');
    expect(kev?.contribution).toBe(25);
  });

  it('scales EPSS contribution linearly with probability', () => {
    const low = scoreRisk('default', {
      knownExploited: false,
      epss: { probability: 0.01, percentile: 0.1 },
      evidenceConfidences: [],
    });
    const high = scoreRisk('default', {
      knownExploited: false,
      epss: { probability: 0.95, percentile: 0.99 },
      evidenceConfidences: [],
    });
    expect(high.score).toBeGreaterThan(low.score);
  });

  it('reaches critical for KEV + high EPSS + recent + confident', () => {
    const r = scoreRisk('internet_exposed', {
      knownExploited: true,
      epss: { probability: 0.97, percentile: 0.999 },
      publishedAt: new Date().toISOString(),
      evidenceConfidences: [0.95, 0.9],
    });
    expect(r.severity === 'critical' || r.severity === 'high').toBe(true);
  });

  it('different profiles produce different scores for the same input', () => {
    const inputs = {
      knownExploited: true,
      epss: { probability: 0.5, percentile: 0.9 },
      evidenceConfidences: [0.9],
    };
    const defaultScore = scoreRisk('default', inputs).score;
    const exposedScore = scoreRisk('internet_exposed', inputs).score;
    expect(exposedScore).toBeGreaterThan(defaultScore);
  });

  it('always lists CVSS uncertainty until CVE feeds land', () => {
    const r = scoreRisk('default', { knownExploited: false, evidenceConfidences: [] });
    expect(r.uncertainty.join(' ')).toMatch(/CVSS/);
  });
});
