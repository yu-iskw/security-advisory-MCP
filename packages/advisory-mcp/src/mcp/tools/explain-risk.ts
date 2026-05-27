import { z } from 'zod';

import { explainRiskMarkdown } from '../../risk/explain.js';
import { isRiskProfileName, RISK_PROFILE_NAMES, type RiskProfileName } from '../../risk/profiles.js';
import { scoreRisk } from '../../risk/score.js';

import type { AdvisoryStore } from '../../store/store.js';

export const ExplainRiskInputSchema = z.object({
  id: z.string().min(1).max(128),
  profile: z.enum(RISK_PROFILE_NAMES).default('default'),
});

type ExplainRiskInput = z.infer<typeof ExplainRiskInputSchema>;

interface ExplainRiskResult {
  found: boolean;
  query: string;
  markdown: string;
  risk?: ReturnType<typeof scoreRisk>;
}

export function explainRisk(store: AdvisoryStore, input: ExplainRiskInput): ExplainRiskResult {
  const advisory =
    store.advisories.findById(input.id) ?? store.advisories.findByAlias(input.id);
  if (!advisory) {
    return {
      found: false,
      query: input.id,
      markdown: `No advisory found locally for **${input.id}**.`,
    };
  }
  const evidence = store.evidence.findByAdvisoryId(advisory.id);
  const knownExploited = evidence.some(
    (e) => e.source === 'cisa-kev' && e.type === 'known_exploited',
  );
  const epssRow = evidence.find((e) => e.source === 'first-epss' && e.type === 'epss_score');
  const epss = epssRow ? parseEpssEvidence(epssRow.normalizedJson) : undefined;

  const profile: RiskProfileName = isRiskProfileName(input.profile) ? input.profile : 'default';

  const result = scoreRisk(profile, {
    knownExploited,
    epss,
    publishedAt: advisory.publishedAt,
    evidenceConfidences: evidence.map((e) => e.confidence),
  });

  return {
    found: true,
    query: input.id,
    risk: result,
    markdown: explainRiskMarkdown(advisory.id, result),
  };
}

function parseEpssEvidence(json: string): { probability: number; percentile: number } | undefined {
  try {
    const obj = JSON.parse(json) as { epss?: unknown; percentile?: unknown };
    if (typeof obj.epss !== 'number' || typeof obj.percentile !== 'number') return undefined;
    return { probability: obj.epss, percentile: obj.percentile };
  } catch {
    return undefined;
  }
}
