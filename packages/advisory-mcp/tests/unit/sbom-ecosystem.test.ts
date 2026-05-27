import { describe, expect, it } from 'vitest';

import { parseSbomComponents } from '../../src/schemas/sbom.js';

describe('parseSbomComponents ecosystem', () => {
  it('derives ecosystem from purl type', () => {
    const components = parseSbomComponents(
      {
        bomFormat: 'CycloneDX',
        components: [
          {
            type: 'library',
            name: 'log4j-core',
            version: '2.16.0',
            purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.16.0',
          },
        ],
      },
      'cyclonedx',
    );
    expect(components[0]?.ecosystem).toBe('maven');
  });
});
