import {
  buildSourceStatusSummary,
  sourceStatusPayload,
} from '../store/repositories/source-state-repository.js';

import type { AdvisoryStore } from '../store/db.js';

export const RESOURCE_URIS = {
  sourceStatus: 'advisory://source/status',
  riskProfile: (name: RiskProfileName) => `advisory://risk-profile/${name}`,
} as const;

export const BUILTIN_RISK_PROFILES = {
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
} as const;

export type RiskProfileName = keyof typeof BUILTIN_RISK_PROFILES;

export const RISK_PROFILE_NAMES = Object.keys(BUILTIN_RISK_PROFILES) as RiskProfileName[];

export function readSourceStatusResource(store: AdvisoryStore): {
  uri: string;
  mimeType: string;
  text: string;
} {
  const summary = buildSourceStatusSummary(store, { includeDisabled: true });
  return {
    uri: RESOURCE_URIS.sourceStatus,
    mimeType: 'application/json',
    text: JSON.stringify(sourceStatusPayload(summary), null, 2),
  };
}

export function readRiskProfileResource(name: RiskProfileName): {
  uri: string;
  mimeType: string;
  text: string;
} {
  const profile =
    name === 'default' ? BUILTIN_RISK_PROFILES.default : BUILTIN_RISK_PROFILES.internet_exposed;
  return {
    uri: RESOURCE_URIS.riskProfile(name),
    mimeType: 'application/json',
    text: JSON.stringify(profile, null, 2),
  };
}

export function resourceContents(resource: { uri: string; mimeType: string; text: string }) {
  return {
    contents: [
      {
        uri: resource.uri,
        mimeType: resource.mimeType,
        text: resource.text,
      },
    ],
  };
}
