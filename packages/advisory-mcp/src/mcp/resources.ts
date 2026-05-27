import { ResourceTemplate, type McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import { getRiskWeights, isRiskProfileName, RISK_PROFILE_NAMES } from '../risk/profiles.js';

import { analyzeAdvisory } from './tools/analyze-advisory.js';
import { sourceStatus } from './tools/source-status.js';

import type { AdvisoryStore } from '../store/store.js';

export function registerAdvisoryResources(server: McpServer, store: AdvisoryStore): void {
  server.registerResource(
    'advisory-by-id',
    new ResourceTemplate('advisory://id/{id}', { list: undefined }),
    {
      title: 'Advisory by ID or alias',
      description:
        'Returns a JSON snapshot of the locally-cached advisory matching the given CVE/GHSA/OSV ID or any known alias. Does not access the network.',
    },
    (uri, vars) => {
      const id = String(vars.id ?? '');
      const result = analyzeAdvisory(store, { id, includeEvidence: true });
      return {
        contents: [
          {
            uri: uri.href,
            mimeType: 'application/json',
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    },
  );

  server.registerResource(
    'source-status',
    'advisory://source/status',
    {
      title: 'Source status',
      description: 'Sync freshness and last error per configured source.',
      mimeType: 'application/json',
    },
    (uri) => {
      const result = sourceStatus(store, {});
      return {
        contents: [
          {
            uri: uri.href,
            mimeType: 'application/json',
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    },
  );

  server.registerResource(
    'risk-profile',
    new ResourceTemplate('advisory://risk-profile/{name}', { list: undefined }),
    {
      title: 'Risk profile weights',
      description:
        'Returns the weight matrix for the named risk profile (default, internet_exposed, application_dependency, container_image, executive, research).',
    },
    (uri, vars) => {
      const name = String(vars.name ?? '');
      const body = isRiskProfileName(name)
        ? { name, weights: getRiskWeights(name) }
        : { error: `unknown risk profile: ${name}`, known: RISK_PROFILE_NAMES };
      return {
        contents: [
          {
            uri: uri.href,
            mimeType: 'application/json',
            text: JSON.stringify(body, null, 2),
          },
        ],
      };
    },
  );

  server.registerResource(
    'advisory-by-cve',
    new ResourceTemplate('advisory://cve/{cveId}', { list: undefined }),
    {
      title: 'Advisory by CVE ID',
      description:
        'Same as advisory://id/{id} but scoped to CVE identifiers. Does not access the network.',
    },
    (uri, vars) => {
      const cveId = String(vars.cveId ?? '');
      const result = analyzeAdvisory(store, { id: cveId, includeEvidence: true });
      return {
        contents: [
          {
            uri: uri.href,
            mimeType: 'application/json',
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    },
  );
}
