import { z } from 'zod';

import { sourceIdSchema } from './source.js';

export const riskProfileNameSchema = z.enum([
  'default',
  'internet_exposed',
  'application_dependency',
  'container_image',
  'executive',
  'research',
]);

export type RiskProfileName = z.infer<typeof riskProfileNameSchema>;

export const riskDriverSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('known_exploited'), source: sourceIdSchema, weight: z.number() }),
  z.object({
    kind: z.literal('epss_high'),
    probability: z.number(),
    percentile: z.number(),
    weight: z.number(),
  }),
  z.object({
    kind: z.literal('cvss_critical'),
    score: z.number(),
    vector: z.string().optional(),
    weight: z.number(),
  }),
  z.object({ kind: z.literal('fix_available'), versions: z.array(z.string()), weight: z.number() }),
  z.object({ kind: z.literal('malicious_package'), source: sourceIdSchema, weight: z.number() }),
  z.object({ kind: z.literal('recently_published'), days: z.number(), weight: z.number() }),
  z.object({ kind: z.literal('source_conflict'), description: z.string(), weight: z.number() }),
]);

export const riskResultSchema = z.object({
  score: z.number().min(0).max(100),
  severity: z.enum(['none', 'low', 'medium', 'high', 'critical']),
  profile: riskProfileNameSchema,
  drivers: z.array(riskDriverSchema),
  explanation: z.string(),
  uncertainty: z.array(z.string()),
});

export type RiskResult = z.infer<typeof riskResultSchema>;
export type RiskDriver = z.infer<typeof riskDriverSchema>;

export const freshnessSummarySchema = z.object({
  oldestSourceSuccess: z.string().nullable(),
  staleSources: z.array(z.string()),
  warnings: z.array(z.string()),
});

export type FreshnessSummary = z.infer<typeof freshnessSummarySchema>;

export const recommendationSchema = z.object({
  action: z.string(),
  rationale: z.string(),
  priority: z.enum(['low', 'medium', 'high', 'critical']),
});

export type Recommendation = z.infer<typeof recommendationSchema>;
