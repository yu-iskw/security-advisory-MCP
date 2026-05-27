import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { openAdvisoryStore, type AdvisoryStore } from '../../store/store.js';

import { scanSbom } from './scan-sbom.js';

function seedStore(store: AdvisoryStore): void {
  store.advisories.upsert({
    id: 'CVE-2021-44228',
    canonicalId: 'CVE-2021-44228',
    type: 'cve',
    title: 'Log4Shell',
    mergedJson: '{}',
  });
  store.affectedPackages.replaceForAdvisory('CVE-2021-44228', [
    {
      advisoryId: 'CVE-2021-44228',
      ecosystem: 'maven',
      name: 'org.apache.logging.log4j:log4j-core',
      vulnerableRange: '>=2.0',
      fixedVersion: '2.17.0',
      source: 'osv',
      confidence: 0.85,
    },
  ]);
}

const CYCLONEDX = JSON.stringify({
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  components: [
    {
      type: 'library',
      name: 'org.apache.logging.log4j:log4j-core',
      version: '2.14.0',
      purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0',
    },
    { type: 'library', name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21' },
  ],
});

const SPDX = JSON.stringify({
  spdxVersion: 'SPDX-2.3',
  packages: [
    {
      name: 'org.apache.logging.log4j:log4j-core',
      versionInfo: '2.14.0',
      externalRefs: [
        {
          referenceCategory: 'PACKAGE-MANAGER',
          referenceType: 'purl',
          referenceLocator: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0',
        },
      ],
    },
  ],
});

describe('scanSbom', () => {
  let store: AdvisoryStore;

  beforeEach(() => {
    store = openAdvisoryStore({ path: ':memory:', noWal: true });
    seedStore(store);
  });

  afterEach(() => {
    store.close();
  });

  it('flags vulnerable components in a CycloneDX SBOM', () => {
    const r = scanSbom(store, {
      sbomJson: CYCLONEDX,
      format: 'auto',
      profile: 'application_dependency',
      includeDevDependencies: false,
      limit: 100,
    });
    expect(r.format).toBe('cyclonedx');
    expect(r.scanned).toBe(2);
    expect(r.hits).toHaveLength(1);
    expect(r.hits[0]?.advisoryId).toBe('CVE-2021-44228');
    expect(r.markdown).toMatch(/Log4Shell|CVE-2021-44228/);
  });

  it('flags vulnerable components in an SPDX SBOM', () => {
    const r = scanSbom(store, {
      sbomJson: SPDX,
      format: 'auto',
      profile: 'application_dependency',
      includeDevDependencies: false,
      limit: 100,
    });
    expect(r.format).toBe('spdx');
    expect(r.hits).toHaveLength(1);
  });

  it('returns zero hits when versions are patched', () => {
    const sbom = JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      components: [
        {
          type: 'library',
          name: 'org.apache.logging.log4j:log4j-core',
          version: '2.17.0',
          purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0',
        },
      ],
    });
    const r = scanSbom(store, {
      sbomJson: sbom,
      format: 'auto',
      profile: 'application_dependency',
      includeDevDependencies: false,
      limit: 100,
    });
    expect(r.hits).toEqual([]);
  });

  it('rejects unparseable input', () => {
    expect(() =>
      scanSbom(store, {
        sbomJson: 'not json',
        format: 'auto',
        profile: 'application_dependency',
        includeDevDependencies: false,
        limit: 100,
      }),
    ).toThrow(/not valid JSON/);
  });
});
