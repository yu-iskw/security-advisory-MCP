/**
 * Risk profiles bias the default scoring weights for different audiences
 * (RFC 13.2). All weights are unitless; the score function normalizes them.
 *
 * v1 only fills in the drivers we have evidence for (KEV, EPSS, recency,
 * evidence confidence). CVSS / fix availability / ecosystem exposure
 * arrive with later milestones; weights remain so adding those drivers
 * does not require a profile change.
 */

export const RISK_PROFILE_NAMES = [
  'default',
  'internet_exposed',
  'application_dependency',
  'container_image',
  'executive',
  'research',
] as const;

export type RiskProfileName = (typeof RISK_PROFILE_NAMES)[number];

export interface RiskWeights {
  knownExploited: number;
  epss: number;
  cvss: number;
  fixAvailable: number;
  ecosystemExposure: number;
  recency: number;
  evidenceConfidence: number;
}

const DEFAULT_WEIGHTS: RiskWeights = {
  knownExploited: 25,
  epss: 20,
  cvss: 20,
  fixAvailable: 15,
  ecosystemExposure: 10,
  recency: 5,
  evidenceConfidence: 5,
};

const PROFILE_WEIGHTS: Record<RiskProfileName, RiskWeights> = {
  default: DEFAULT_WEIGHTS,
  internet_exposed: {
    knownExploited: 35,
    epss: 30,
    cvss: 15,
    fixAvailable: 5,
    ecosystemExposure: 5,
    recency: 5,
    evidenceConfidence: 5,
  },
  application_dependency: {
    knownExploited: 15,
    epss: 15,
    cvss: 15,
    fixAvailable: 30,
    ecosystemExposure: 15,
    recency: 5,
    evidenceConfidence: 5,
  },
  container_image: {
    knownExploited: 20,
    epss: 15,
    cvss: 20,
    fixAvailable: 25,
    ecosystemExposure: 10,
    recency: 5,
    evidenceConfidence: 5,
  },
  executive: {
    knownExploited: 40,
    epss: 20,
    cvss: 15,
    fixAvailable: 10,
    ecosystemExposure: 5,
    recency: 5,
    evidenceConfidence: 5,
  },
  research: {
    knownExploited: 10,
    epss: 10,
    cvss: 15,
    fixAvailable: 10,
    ecosystemExposure: 5,
    recency: 5,
    evidenceConfidence: 45,
  },
};

export function getRiskWeights(name: RiskProfileName): RiskWeights {
  // `name` is constrained to RISK_PROFILE_NAMES; lookup is safe.
  // eslint-disable-next-line security/detect-object-injection
  return PROFILE_WEIGHTS[name];
}

export function isRiskProfileName(value: string): value is RiskProfileName {
  return (RISK_PROFILE_NAMES as readonly string[]).includes(value);
}
