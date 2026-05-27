import type { SyncPreset, SourceId } from '../schemas/source.js';
import type { SourceDefinition } from './source.js';

export const SOURCE_DEFINITIONS: SourceDefinition[] = [
  {
    id: 'cveproject',
    displayName: 'CVEProject cvelistV5',
    trustTier: 'A',
    defaultPreset: 'core',
    fixtureSubdir: 'core/cveproject',
  },
  {
    id: 'nvd-feed',
    displayName: 'NVD JSON Feeds',
    trustTier: 'A',
    defaultPreset: 'core',
    fixtureSubdir: 'core/nvd-feed',
  },
  {
    id: 'cisa-kev',
    displayName: 'CISA KEV',
    trustTier: 'A',
    defaultPreset: 'core',
    fixtureSubdir: 'core/cisa-kev',
  },
  {
    id: 'cisa-vulnrichment',
    displayName: 'CISA Vulnrichment',
    trustTier: 'A',
    defaultPreset: 'core',
    fixtureSubdir: 'core/cisa-vulnrichment',
  },
  {
    id: 'first-epss',
    displayName: 'FIRST EPSS',
    trustTier: 'A',
    defaultPreset: 'core',
    fixtureSubdir: 'core/first-epss',
  },
  {
    id: 'osv',
    displayName: 'OSV.dev',
    trustTier: 'A',
    defaultPreset: 'packages',
    fixtureSubdir: 'packages/osv',
  },
  {
    id: 'github-advisory',
    displayName: 'GitHub Advisory Database',
    trustTier: 'B',
    defaultPreset: 'packages',
    fixtureSubdir: 'packages/github-advisory',
  },
  {
    id: 'ossf-malicious-packages',
    displayName: 'OpenSSF Malicious Packages',
    trustTier: 'B',
    defaultPreset: 'packages',
    fixtureSubdir: 'packages/ossf-malicious-packages',
  },
  {
    id: 'debian',
    displayName: 'Debian Security Tracker',
    trustTier: 'B',
    defaultPreset: 'ecosystems',
    fixtureSubdir: 'ecosystems/debian',
  },
  {
    id: 'ubuntu',
    displayName: 'Ubuntu Security',
    trustTier: 'B',
    defaultPreset: 'ecosystems',
    fixtureSubdir: 'ecosystems/ubuntu',
  },
  {
    id: 'alpine',
    displayName: 'Alpine SecDB',
    trustTier: 'B',
    defaultPreset: 'ecosystems',
    fixtureSubdir: 'ecosystems/alpine',
  },
  {
    id: 'rustsec',
    displayName: 'RustSec',
    trustTier: 'B',
    defaultPreset: 'ecosystems',
    fixtureSubdir: 'ecosystems/rustsec',
  },
  {
    id: 'go-vulndb',
    displayName: 'Go Vulnerability DB',
    trustTier: 'B',
    defaultPreset: 'ecosystems',
    fixtureSubdir: 'ecosystems/go-vulndb',
  },
  {
    id: 'pypa',
    displayName: 'PyPA Advisory Data',
    trustTier: 'B',
    defaultPreset: 'ecosystems',
    fixtureSubdir: 'ecosystems/pypa',
  },
  {
    id: 'mitre-cwe',
    displayName: 'MITRE CWE',
    trustTier: 'A',
    defaultPreset: 'context',
    fixtureSubdir: 'context/mitre-cwe',
  },
  {
    id: 'mitre-capec',
    displayName: 'MITRE CAPEC',
    trustTier: 'A',
    defaultPreset: 'context',
    fixtureSubdir: 'context/mitre-capec',
  },
];

const PRESET_SOURCES: Record<SyncPreset, SourceId[]> = {
  core: ['cveproject', 'nvd-feed', 'cisa-kev', 'cisa-vulnrichment', 'first-epss'],
  packages: ['osv', 'github-advisory', 'ossf-malicious-packages'],
  ecosystems: ['debian', 'ubuntu', 'alpine', 'rustsec', 'go-vulndb', 'pypa'],
  context: ['mitre-cwe', 'mitre-capec'],
  all: [],
  research: [],
};

PRESET_SOURCES.all = [
  ...PRESET_SOURCES.core,
  ...PRESET_SOURCES.packages,
  ...PRESET_SOURCES.ecosystems,
  ...PRESET_SOURCES.context,
];

PRESET_SOURCES.research = [...PRESET_SOURCES.all];

export function sourcesForPreset(preset: SyncPreset): SourceDefinition[] {
  const ids = new Set(PRESET_SOURCES[preset]);
  return SOURCE_DEFINITIONS.filter((s) => ids.has(s.id));
}

export function getSourceDefinition(id: SourceId): SourceDefinition | undefined {
  return SOURCE_DEFINITIONS.find((s) => s.id === id);
}
