import { z } from 'zod';

import { findAdvisoryById } from '../../store/repositories/advisory-repository.js';
import { listEvidenceForAdvisory } from '../../store/repositories/evidence-repository.js';
import type { AdvisoryStore } from '../../store/db.js';
import { explainRisk } from '../../risk/explain.js';
import { riskProfileNameSchema } from '../../schemas/risk.js';

export const explainRiskInputSchema = z.object({
  id: z.string(),
  profile: riskProfileNameSchema.default('default'),
});

export function runExplainRisk(
  store: AdvisoryStore,
  input: z.infer<typeof explainRiskInputSchema>,
) {
  const advisory = findAdvisoryById(store, input.id);
  if (!advisory) {
    throw new Error(`Advisory not found: ${input.id}`);
  }
  const evidence = listEvidenceForAdvisory(store, advisory.id);
  const result = explainRisk(advisory, evidence, input.profile);
  return {
    structured: { risk: result.risk, weights: result.weights },
    markdown: result.markdown,
  };
}
