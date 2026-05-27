import { z } from 'zod';

import { sourceIdSchema } from './source.js';

export const trustTierSchema = z.enum(['A', 'B', 'C', 'D']);

export const evidenceTypeSchema = z.enum([
  'cve_record',
  'nvd_enrichment',
  'kev',
  'epss',
  'vulnrichment',
  'osv',
  'ghsa',
  'malicious_package',
  'distro',
  'taxonomy',
  'research',
]);

export const evidenceSchema = z.object({
  id: z.string(),
  advisoryId: z.string(),
  source: sourceIdSchema,
  sourceRecordId: z.string().optional(),
  sourceUrl: z.string().optional(),
  type: evidenceTypeSchema,
  fetchedAt: z.string(),
  observedAt: z.string().optional(),
  sourceModifiedAt: z.string().optional(),
  confidence: z.number(),
  trustTier: trustTierSchema,
  summary: z.string(),
  normalizedJson: z.unknown(),
  rawRef: z.string().optional(),
});

export type Evidence = z.infer<typeof evidenceSchema>;
export type TrustTier = z.infer<typeof trustTierSchema>;

export const evidenceSummarySchema = evidenceSchema.pick({
  id: true,
  source: true,
  type: true,
  fetchedAt: true,
  confidence: true,
  trustTier: true,
  summary: true,
});

export type EvidenceSummary = z.infer<typeof evidenceSummarySchema>;
