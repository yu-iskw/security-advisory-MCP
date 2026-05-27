import { z } from 'zod';

import { parsePurl } from './purl.js';

export const sbomComponentSchema = z.object({
  name: z.string(),
  version: z.string().optional(),
  purl: z.string().optional(),
  ecosystem: z.string().optional(),
  type: z.string().optional(),
});

export type SbomComponent = z.infer<typeof sbomComponentSchema>;

export const cycloneDxSbomSchema = z.object({
  bomFormat: z.literal('CycloneDX').optional(),
  specVersion: z.string().optional(),
  components: z
    .array(
      z.object({
        type: z.string().optional(),
        name: z.string(),
        version: z.string().optional(),
        purl: z.string().optional(),
      }),
    )
    .optional(),
});

export const spdxSbomSchema = z.object({
  spdxVersion: z.string().optional(),
  packages: z
    .array(
      z.object({
        name: z.string(),
        versionInfo: z.string().optional(),
        externalRefs: z
          .array(
            z.object({
              referenceType: z.string().optional(),
              referenceLocator: z.string().optional(),
            }),
          )
          .optional(),
      }),
    )
    .optional(),
});

export function parseSbomComponents(
  json: unknown,
  format: 'cyclonedx' | 'spdx' | 'auto',
): SbomComponent[] {
  const detected = format === 'auto' ? detectSbomFormat(json) : format;
  if (detected === 'cyclonedx') {
    return parseCycloneDx(json);
  }
  return parseSpdx(json);
}

function detectSbomFormat(json: unknown): 'cyclonedx' | 'spdx' {
  if (typeof json === 'object' && json !== null) {
    const obj = json as Record<string, unknown>;
    if (obj.bomFormat === 'CycloneDX' || Array.isArray(obj.components)) {
      return 'cyclonedx';
    }
    if (typeof obj.spdxVersion === 'string' || Array.isArray(obj.packages)) {
      return 'spdx';
    }
  }
  return 'cyclonedx';
}

function ecosystemFromPurl(purl: string | undefined): string | undefined {
  if (!purl) {
    return undefined;
  }
  return parsePurl(purl)?.type;
}

function ecosystemFromComponentType(type: string | undefined): string {
  if (type === undefined) {
    return 'generic';
  }
  switch (type.toLowerCase()) {
    case 'library':
    case 'application':
      return 'generic';
    case 'container':
      return 'oci';
    default:
      return 'generic';
  }
}

function resolveEcosystem(purl: string | undefined, type: string | undefined): string {
  return ecosystemFromPurl(purl) ?? ecosystemFromComponentType(type);
}

function parseCycloneDx(json: unknown): SbomComponent[] {
  const parsed = cycloneDxSbomSchema.safeParse(json);
  if (!parsed.success || !parsed.data.components) {
    return [];
  }
  return parsed.data.components.map((c) => ({
    name: c.name,
    version: c.version,
    purl: c.purl,
    ecosystem: resolveEcosystem(c.purl, c.type),
    type: c.type,
  }));
}

function parseSpdx(json: unknown): SbomComponent[] {
  const parsed = spdxSbomSchema.safeParse(json);
  if (!parsed.success || !parsed.data.packages) {
    return [];
  }
  return parsed.data.packages.map((pkg) => {
    const purlRef = pkg.externalRefs?.find((r) => r.referenceType === 'purl');
    const purl = purlRef?.referenceLocator;
    return {
      name: pkg.name.replace(/^pkg:/, ''),
      version: pkg.versionInfo?.replace(/^v/, ''),
      purl,
      ecosystem: resolveEcosystem(purl, undefined),
    };
  });
}
