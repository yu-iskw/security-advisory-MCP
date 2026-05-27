import { z } from 'zod';

import { computeRiskScore } from '../../risk/score.js';
import { recommendationSchema, riskProfileNameSchema } from '../../schemas/risk.js';
import { labelUntrustedQuote } from '../../security/content-sanitizer.js';
import { findAdvisoryById } from '../../store/repositories/advisory-repository.js';
import { listEvidenceForAdvisory } from '../../store/repositories/evidence-repository.js';
import { buildFreshnessSummary } from '../../store/repositories/freshness.js';

import type { Advisory } from '../../schemas/advisory.js';
import type { Recommendation } from '../../schemas/risk.js';
import type { AdvisoryStore } from '../../store/db.js';

export const analyzeAdvisoryInputSchema = z.object({
  id: z.string().min(1).max(128),
  profile: riskProfileNameSchema.default('default'),
  includeEvidence: z.boolean().default(true),
  includeRaw: z.boolean().default(false),
});

export type AnalyzeAdvisoryInput = z.infer<typeof analyzeAdvisoryInputSchema>;

export function runAnalyzeAdvisory(store: AdvisoryStore, input: AnalyzeAdvisoryInput) {
  const advisory = findAdvisoryById(store, input.id);
  if (!advisory) {
    throw new Error(
      `Advisory not found locally: ${input.id}. Run advisory-mcp sync --preset core.`,
    );
  }
  const evidence = listEvidenceForAdvisory(store, advisory.id);
  const risk = computeRiskScore(advisory, evidence, input.profile);
  const freshness = buildFreshnessSummary(store);
  const recommendations = buildRecommendations(advisory, risk.severity);

  const structured = {
    advisory: summarizeAdvisory(advisory),
    risk,
    affected: advisory.affected,
    evidence: input.includeEvidence
      ? evidence.map((e) => ({
          id: e.id,
          source: e.source,
          confidence: e.confidence,
          fetchedAt: e.fetchedAt,
          summary: e.summary,
        }))
      : [],
    conflicts: advisory.sourceDisagreements,
    recommendations,
    freshness,
  };

  const markdown = [
    `# ${advisory.canonicalId}`,
    advisory.title ?? '',
    '',
    `**Risk:** ${risk.score}/100 (${risk.severity}) — profile \`${input.profile}\``,
    '',
    advisory.description ? labelUntrustedQuote(advisory.description) : '',
    '',
    `Known exploited: ${advisory.kev ? 'yes' : 'no'}`,
    `Fix available: ${advisory.affected.some((p) => p.fixedVersions.length > 0) ? 'yes' : 'no'}`,
  ].join('\n');

  return { structured, markdown };
}

function summarizeAdvisory(advisory: Advisory) {
  return {
    id: advisory.id,
    canonicalId: advisory.canonicalId,
    type: advisory.type,
    aliases: advisory.aliases,
    title: advisory.title,
    publishedAt: advisory.publishedAt,
    modifiedAt: advisory.modifiedAt,
  };
}

function buildRecommendations(advisory: Advisory, severity: string): Recommendation[] {
  const recs: Recommendation[] = [];
  if (advisory.kev) {
    recs.push(
      recommendationSchema.parse({
        action: 'Prioritize remediation — listed in CISA KEV',
        rationale: 'Known exploited in the wild',
        priority: 'critical',
      }),
    );
  }
  if (advisory.affected.some((p) => p.fixedVersions.length > 0)) {
    recs.push(
      recommendationSchema.parse({
        action: 'Upgrade to a fixed version',
        rationale: 'Vendor fix available',
        priority: severity === 'critical' ? 'critical' : 'high',
      }),
    );
  }
  return recs;
}
