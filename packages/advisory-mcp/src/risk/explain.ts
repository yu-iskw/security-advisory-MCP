import { getProfileWeights, type ProfileWeights } from './profiles.js';
import { computeRiskScore } from './score.js';

import type { Advisory } from '../schemas/advisory.js';
import type { Evidence } from '../schemas/evidence.js';
import type { RiskProfileName, RiskResult } from '../schemas/risk.js';

export function explainRisk(
  advisory: Advisory,
  evidence: Evidence[],
  profile: RiskProfileName,
): { risk: RiskResult; weights: ProfileWeights; markdown: string } {
  const risk = computeRiskScore(advisory, evidence, profile);
  const weights = getProfileWeights(profile);
  const lines = [
    `# Risk explanation: ${advisory.canonicalId}`,
    '',
    `Profile: **${profile}**`,
    `Score: **${risk.score}** (${risk.severity})`,
    '',
    '## Weight breakdown',
    '',
    '| Factor | Weight |',
    '| --- | --- |',
    ...Object.entries(weights).map(([k, v]) => `| ${k} | ${(v * 100).toFixed(0)}% |`),
    '',
    '## Drivers',
    '',
    ...risk.drivers.map((d) => `- **${d.kind}** (contribution ${d.weight.toFixed(1)})`),
    '',
    risk.uncertainty.length > 0 ? '## Uncertainty\n' : '',
    ...risk.uncertainty.map((u) => `- ${u}`),
  ];
  return { risk, weights, markdown: lines.filter(Boolean).join('\n') };
}
