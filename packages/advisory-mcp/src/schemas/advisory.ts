import { z } from 'zod';

import { sourceIdSchema } from './source.js';

export const advisoryTypeSchema = z.enum([
  'cve',
  'ghsa',
  'osv',
  'malicious-package',
  'distro',
  'other',
]);

export const cvssMetricSchema = z.object({
  version: z.string(),
  score: z.number(),
  severity: z.string().optional(),
  vector: z.string().optional(),
  source: sourceIdSchema.optional(),
});

export const epssMetricSchema = z.object({
  cve: z.string(),
  epss: z.number(),
  percentile: z.number(),
  date: z.string(),
});

export const kevEntrySchema = z.object({
  cve: z.string(),
  dateAdded: z.string().optional(),
  dueDate: z.string().optional(),
  knownRansomware: z.boolean().optional(),
});

export const ssvcDecisionSchema = z.object({
  decision: z.string().optional(),
  exploitation: z.string().optional(),
  automatable: z.string().optional(),
});

export const advisoryReferenceSchema = z.object({
  url: z.string(),
  tags: z.array(z.string()).optional(),
});

export const affectedPackageSchema = z.object({
  ecosystem: z.string(),
  name: z.string(),
  purl: z.string().optional(),
  vulnerableRanges: z.array(z.string()),
  fixedVersions: z.array(z.string()),
  source: sourceIdSchema,
  confidence: z.number(),
});

export const evidenceConflictSchema = z.object({
  field: z.string(),
  sources: z.array(sourceIdSchema),
  description: z.string(),
  resolution: z.string().optional(),
  severity: z.enum(['low', 'medium', 'high']).default('low'),
});

export const advisorySchema = z.object({
  id: z.string(),
  canonicalId: z.string(),
  type: advisoryTypeSchema,
  aliases: z.array(z.string()),
  title: z.string().optional(),
  description: z.string().optional(),
  publishedAt: z.string().optional(),
  modifiedAt: z.string().optional(),
  withdrawnAt: z.string().optional(),
  affected: z.array(affectedPackageSchema),
  cwes: z.array(z.string()),
  cvss: z.array(cvssMetricSchema),
  epss: epssMetricSchema.optional(),
  kev: kevEntrySchema.optional(),
  ssvc: ssvcDecisionSchema.optional(),
  references: z.array(advisoryReferenceSchema),
  sourceDisagreements: z.array(evidenceConflictSchema),
});

export type Advisory = z.infer<typeof advisorySchema>;
export type AffectedPackage = z.infer<typeof affectedPackageSchema>;
export type EvidenceConflict = z.infer<typeof evidenceConflictSchema>;

export const advisorySummarySchema = advisorySchema.pick({
  id: true,
  canonicalId: true,
  type: true,
  aliases: true,
  title: true,
  publishedAt: true,
  modifiedAt: true,
});

export type AdvisorySummary = z.infer<typeof advisorySummarySchema>;
