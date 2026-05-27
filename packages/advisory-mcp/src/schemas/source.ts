import { z } from 'zod';

export const sourceIdSchema = z.enum([
  'cveproject',
  'nvd-feed',
  'cisa-kev',
  'cisa-vulnrichment',
  'first-epss',
  'osv',
  'github-advisory',
  'ossf-malicious-packages',
  'mitre-cwe',
  'mitre-capec',
]);

export type SourceId = z.infer<typeof sourceIdSchema>;

export const syncPresetSchema = z.enum([
  'core',
  'packages',
  'ecosystems',
  'context',
  'all',
  'research',
]);

export type SyncPreset = z.infer<typeof syncPresetSchema>;

export const sourceStatusSchema = z.enum([
  'never_synced',
  'syncing',
  'ok',
  'stale',
  'error',
  'disabled',
]);

export type SourceStatus = z.infer<typeof sourceStatusSchema>;

export const sourceStateRowSchema = z.object({
  source: sourceIdSchema,
  enabled: z.boolean(),
  preset: syncPresetSchema,
  lastSyncStartedAt: z.string().nullable(),
  lastSyncCompletedAt: z.string().nullable(),
  lastSuccessAt: z.string().nullable(),
  lastError: z.string().nullable(),
  version: z.string().nullable(),
  etag: z.string().nullable(),
  lastModified: z.string().nullable(),
  sha256: z.string().nullable(),
  status: sourceStatusSchema,
});

export type SourceStateRow = z.infer<typeof sourceStateRowSchema>;

export const sourceStatusInputSchema = z.object({
  source: z.string().optional(),
  includeDisabled: z.boolean().default(false),
});

export type SourceStatusInput = z.infer<typeof sourceStatusInputSchema>;

export const CORE_SOURCE_IDS: SourceId[] = [
  'cveproject',
  'nvd-feed',
  'cisa-kev',
  'cisa-vulnrichment',
  'first-epss',
];
