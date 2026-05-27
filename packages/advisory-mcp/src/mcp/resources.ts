import { buildSourceStatusSummary } from '../store/repositories/source-state-repository.js';

import type { AdvisoryStore } from '../store/db.js';

export const RESOURCE_URIS = {
  sourceStatus: 'advisory://source/status',
  riskProfile: (name: string) => `advisory://risk-profile/${name}`,
  advisoryById: (id: string) => `advisory://id/${encodeURIComponent(id)}`,
} as const;

export function readSourceStatusResource(store: AdvisoryStore): {
  uri: string;
  mimeType: string;
  text: string;
} {
  const summary = buildSourceStatusSummary(store, { includeDisabled: true });
  return {
    uri: RESOURCE_URIS.sourceStatus,
    mimeType: 'application/json',
    text: JSON.stringify(
      {
        sources: summary.sources,
        advisoryCount: summary.advisoryCount,
        evidenceCount: summary.evidenceCount,
      },
      null,
      2,
    ),
  };
}

export const BUILTIN_RISK_PROFILES: Record<
  string,
  { name: string; description: string; weights: Record<string, number> }
> = {
  default: {
    name: 'default',
    description: 'Balanced general prioritization',
    weights: {
      knownExploitation: 0.25,
      epss: 0.2,
      cvss: 0.2,
      packageCertainty: 0.15,
      ecosystemExposure: 0.1,
      recency: 0.05,
      evidenceConfidence: 0.05,
    },
  },
  internet_exposed: {
    name: 'internet_exposed',
    description: 'Bias toward KEV, EPSS, and network attack surface',
    weights: {
      knownExploitation: 0.35,
      epss: 0.25,
      cvss: 0.2,
      packageCertainty: 0.1,
      ecosystemExposure: 0.05,
      recency: 0.03,
      evidenceConfidence: 0.02,
    },
  },
};

export function readRiskProfileResource(name: string): {
  uri: string;
  mimeType: string;
  text: string;
} | null {
  switch (name) {
    case 'default':
    case 'internet_exposed': {
      const profile = BUILTIN_RISK_PROFILES[name];
      return {
        uri: RESOURCE_URIS.riskProfile(name),
        mimeType: 'application/json',
        text: JSON.stringify(profile, null, 2),
      };
    }
    default:
      return null;
  }
}
