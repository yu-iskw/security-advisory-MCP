import { ageMs } from '../util/time.js';

import { getRiskWeights, type RiskProfileName, type RiskWeights } from './profiles.js';

interface ScoreInputs {
  knownExploited: boolean;
  epss?: { probability: number; percentile: number };
  publishedAt?: string | null;
  evidenceConfidences: number[];
}

export type Severity = 'none' | 'low' | 'medium' | 'high' | 'critical';

export interface RiskDriver {
  kind: string;
  weight: number;
  contribution: number;
  detail: string;
}

export interface RiskResult {
  score: number;
  severity: Severity;
  profile: RiskProfileName;
  weights: RiskWeights;
  drivers: RiskDriver[];
  uncertainty: string[];
}

const RECENCY_HALF_LIFE_DAYS = 30;

export function scoreRisk(profile: RiskProfileName, inputs: ScoreInputs): RiskResult {
  const weights = getRiskWeights(profile);
  const drivers: RiskDriver[] = [];
  const uncertainty: string[] = [];

  // known_exploited: full weight if listed in KEV
  if (inputs.knownExploited) {
    drivers.push({
      kind: 'known_exploited',
      weight: weights.knownExploited,
      contribution: weights.knownExploited,
      detail: 'Listed in CISA KEV',
    });
  }

  // EPSS: linear in probability (0..1)
  if (inputs.epss) {
    const contribution = weights.epss * inputs.epss.probability;
    drivers.push({
      kind: 'epss',
      weight: weights.epss,
      contribution,
      detail: `EPSS probability ${inputs.epss.probability.toFixed(5)} (percentile ${inputs.epss.percentile.toFixed(5)})`,
    });
  } else {
    uncertainty.push('No EPSS evidence yet — sync the first-epss source.');
  }

  // CVSS: placeholder until M14/M15 add CVE feeds
  uncertainty.push('CVSS not yet available locally; CVE feeds land in a later milestone.');

  // recency
  if (inputs.publishedAt) {
    const days = ageMs(inputs.publishedAt) / 86_400_000;
    if (days >= 0) {
      const factor = Math.exp(-days / RECENCY_HALF_LIFE_DAYS);
      const contribution = weights.recency * factor;
      drivers.push({
        kind: 'recency',
        weight: weights.recency,
        contribution,
        detail: `Published ${Math.round(days)} day(s) ago`,
      });
    }
  }

  // evidence confidence
  if (inputs.evidenceConfidences.length > 0) {
    const avg =
      inputs.evidenceConfidences.reduce((a, b) => a + b, 0) /
      inputs.evidenceConfidences.length;
    const contribution = weights.evidenceConfidence * avg;
    drivers.push({
      kind: 'evidence_confidence',
      weight: weights.evidenceConfidence,
      contribution,
      detail: `Mean source confidence ${avg.toFixed(2)}`,
    });
  }

  const total = drivers.reduce((acc, d) => acc + d.contribution, 0);
  const score = Math.round(Math.min(100, Math.max(0, total)));

  return {
    score,
    severity: severityForScore(score),
    profile,
    weights,
    drivers,
    uncertainty,
  };
}

function severityForScore(score: number): Severity {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 30) return 'medium';
  if (score > 0) return 'low';
  return 'none';
}
