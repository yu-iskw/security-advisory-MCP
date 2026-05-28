import { readFile } from 'node:fs/promises';

import { z } from 'zod';

import { LIMITS } from '../../security/limits.js';

import { scanSbom } from './scan-sbom.js';

import type { PathPolicy } from '../../security/path-policy.js';
import type { AdvisoryStore } from '../../store/store.js';

export const ScanSbomFileInputSchema = z.object({
  path: z.string().min(1).max(4096),
  format: z.enum(['auto', 'cyclonedx', 'spdx']).default('auto'),
  profile: z
    .enum(['default', 'internet_exposed', 'application_dependency', 'container_image'])
    .default('application_dependency'),
  includeDevDependencies: z.boolean().default(false),
  limit: z.number().int().min(1).max(500).default(100),
});

type ScanSbomFileInput = z.infer<typeof ScanSbomFileInputSchema>;

export async function scanSbomFile(
  store: AdvisoryStore,
  policy: PathPolicy,
  input: ScanSbomFileInput,
): Promise<ReturnType<typeof scanSbom>> {
  const resolved = policy.assertReadable(input.path);
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- path is policy-checked
  const buf = await readFile(resolved);
  if (buf.length > LIMITS.maxSbomJsonBytes) {
    throw new Error(`SBOM file exceeds ${LIMITS.maxSbomJsonBytes.toString()}-byte limit`);
  }
  return scanSbom(store, {
    sbomJson: buf.toString('utf8'),
    format: input.format,
    profile: input.profile,
    includeDevDependencies: input.includeDevDependencies,
    limit: input.limit,
  });
}
