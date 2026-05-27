/**
 * SBOM normalization for CycloneDX and SPDX JSON. The parser accepts the
 * minimum useful field set: every component becomes
 *   { purl?, ecosystem?, name?, version?, isDev? }
 * which is what analyze_package consumes.
 *
 * Unknown / unsupported formats raise SbomFormatError. The 20 MB cap on the
 * raw JSON is enforced by the caller (RFC 11.1 / LIMITS.maxSbomJsonBytes).
 */

type SbomFormat = 'cyclonedx' | 'spdx';

export interface SbomComponent {
  purl?: string;
  ecosystem?: string;
  name?: string;
  version?: string;
  isDev: boolean;
}

interface NormalizedSbom {
  format: SbomFormat;
  components: SbomComponent[];
}

class SbomFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SbomFormatError';
  }
}

interface CycloneDxComponent {
  type?: string;
  name?: string;
  version?: string;
  purl?: string;
  scope?: string;
}

interface CycloneDxSbom {
  bomFormat?: string;
  specVersion?: string;
  components?: ReadonlyArray<CycloneDxComponent>;
}

interface SpdxExternalRef {
  referenceCategory?: string;
  referenceType?: string;
  referenceLocator?: string;
}

interface SpdxPackage {
  name?: string;
  versionInfo?: string;
  externalRefs?: ReadonlyArray<SpdxExternalRef>;
}

interface SpdxSbom {
  spdxVersion?: string;
  packages?: ReadonlyArray<SpdxPackage>;
}

export function parseSbom(json: string, hint: SbomFormat | 'auto' = 'auto'): NormalizedSbom {
  let data: unknown;
  try {
    data = JSON.parse(json);
  } catch (err) {
    throw new SbomFormatError(`SBOM is not valid JSON: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (typeof data !== 'object' || data === null) {
    throw new SbomFormatError('SBOM root is not an object');
  }
  const obj = data as Record<string, unknown>;

  if (hint === 'cyclonedx' || obj.bomFormat === 'CycloneDX') {
    return { format: 'cyclonedx', components: parseCyclonedx(obj) };
  }
  if (hint === 'spdx' || typeof obj.spdxVersion === 'string') {
    return { format: 'spdx', components: parseSpdx(obj) };
  }
  throw new SbomFormatError('SBOM format could not be detected; pass format=cyclonedx|spdx');
}

function parseCyclonedx(sbom: CycloneDxSbom): SbomComponent[] {
  const out: SbomComponent[] = [];
  for (const c of sbom.components ?? []) {
    const isDev = (c.scope ?? '').toLowerCase() === 'optional';
    out.push({
      purl: c.purl,
      name: c.name,
      version: c.version,
      ecosystem: ecosystemFromPurl(c.purl),
      isDev,
    });
  }
  return out;
}

function parseSpdx(sbom: SpdxSbom): SbomComponent[] {
  const out: SbomComponent[] = [];
  for (const p of sbom.packages ?? []) {
    const purl = (p.externalRefs ?? []).find(
      (ref) =>
        (ref.referenceCategory ?? '').toUpperCase() === 'PACKAGE-MANAGER' &&
        (ref.referenceType ?? '').toLowerCase() === 'purl',
    )?.referenceLocator;
    out.push({
      purl,
      name: p.name,
      version: p.versionInfo,
      ecosystem: ecosystemFromPurl(purl),
      isDev: false,
    });
  }
  return out;
}

function ecosystemFromPurl(purl: string | undefined): string | undefined {
  if (purl === undefined || !purl.startsWith('pkg:')) return undefined;
  const rest = purl.slice(4);
  const slash = rest.indexOf('/');
  return slash > 0 ? rest.slice(0, slash).toLowerCase() : undefined;
}
