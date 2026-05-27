import type { RiskProfileName } from '../schemas/risk.js';

export interface ProfileWeights {
  knownExploitation: number;
  epss: number;
  cvss: number;
  packageCertainty: number;
  ecosystemExposure: number;
  recency: number;
  evidenceConfidence: number;
}

export const RISK_PROFILE_NAMES = [
  'default',
  'internet_exposed',
  'application_dependency',
  'container_image',
  'executive',
  'research',
] as const satisfies readonly RiskProfileName[];

export const PROFILE_WEIGHTS: Record<RiskProfileName, ProfileWeights> = {
  default: {
    knownExploitation: 0.25,
    epss: 0.2,
    cvss: 0.2,
    packageCertainty: 0.15,
    ecosystemExposure: 0.1,
    recency: 0.05,
    evidenceConfidence: 0.05,
  },
  internet_exposed: {
    knownExploitation: 0.35,
    epss: 0.25,
    cvss: 0.2,
    packageCertainty: 0.1,
    ecosystemExposure: 0.05,
    recency: 0.03,
    evidenceConfidence: 0.02,
  },
  application_dependency: {
    knownExploitation: 0.15,
    epss: 0.15,
    cvss: 0.15,
    packageCertainty: 0.35,
    ecosystemExposure: 0.15,
    recency: 0.03,
    evidenceConfidence: 0.02,
  },
  container_image: {
    knownExploitation: 0.2,
    epss: 0.15,
    cvss: 0.15,
    packageCertainty: 0.3,
    ecosystemExposure: 0.15,
    recency: 0.03,
    evidenceConfidence: 0.02,
  },
  executive: {
    knownExploitation: 0.4,
    epss: 0.2,
    cvss: 0.15,
    packageCertainty: 0.1,
    ecosystemExposure: 0.1,
    recency: 0.03,
    evidenceConfidence: 0.02,
  },
  research: {
    knownExploitation: 0.1,
    epss: 0.1,
    cvss: 0.1,
    packageCertainty: 0.1,
    ecosystemExposure: 0.1,
    recency: 0.1,
    evidenceConfidence: 0.4,
  },
};

export function getProfileWeights(name: RiskProfileName): ProfileWeights {
  switch (name) {
    case 'default':
      return PROFILE_WEIGHTS.default;
    case 'internet_exposed':
      return PROFILE_WEIGHTS.internet_exposed;
    case 'application_dependency':
      return PROFILE_WEIGHTS.application_dependency;
    case 'container_image':
      return PROFILE_WEIGHTS.container_image;
    case 'executive':
      return PROFILE_WEIGHTS.executive;
    case 'research':
      return PROFILE_WEIGHTS.research;
    default: {
      const _exhaustive: never = name;
      return _exhaustive;
    }
  }
}
