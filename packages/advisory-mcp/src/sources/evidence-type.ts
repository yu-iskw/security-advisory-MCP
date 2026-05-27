import type { Evidence } from '../schemas/evidence.js';
import type { SourceId } from '../schemas/source.js';

export function evidenceTypeForSource(sourceId: SourceId): Evidence['type'] {
  switch (sourceId) {
    case 'cveproject':
      return 'cve_record';
    case 'nvd-feed':
      return 'nvd_enrichment';
    case 'cisa-kev':
      return 'kev';
    case 'first-epss':
      return 'epss';
    case 'cisa-vulnrichment':
      return 'vulnrichment';
    case 'osv':
      return 'osv';
    case 'github-advisory':
      return 'ghsa';
    case 'ossf-malicious-packages':
      return 'malicious_package';
    case 'debian':
    case 'ubuntu':
    case 'alpine':
      return 'distro';
    case 'rustsec':
    case 'go-vulndb':
    case 'pypa':
      return 'osv';
    case 'mitre-cwe':
    case 'mitre-capec':
      return 'taxonomy';
    default: {
      const _exhaustive: never = sourceId;
      return _exhaustive;
    }
  }
}
