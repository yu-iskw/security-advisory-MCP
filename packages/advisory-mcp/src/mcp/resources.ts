import { ResourceTemplate, type McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import { getRiskWeights, isRiskProfileName, RISK_PROFILE_NAMES } from '../risk/profiles.js';

import { analyzeAdvisory } from './tools/analyze-advisory.js';
import { analyzePackage } from './tools/analyze-package.js';
import { sourceStatus } from './tools/source-status.js';

import type { AdvisoryStore } from '../store/store.js';

const SCHEMA_MIME = 'application/schema+json';

const ADVISORY_SCHEMA_JSON = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  title: 'Advisory',
  type: 'object',
  properties: {
    id: { type: 'string' },
    canonicalId: { type: 'string' },
    type: { type: 'string', enum: ['cve', 'ghsa', 'osv', 'malicious_package', 'ecosystem'] },
    aliases: { type: 'array', items: { type: 'string' } },
    title: { type: 'string' },
    description: { type: 'string' },
    publishedAt: { type: 'string', format: 'date-time' },
    modifiedAt: { type: 'string', format: 'date-time' },
    severity: { type: 'string', enum: ['none', 'low', 'medium', 'high', 'critical'] },
    knownExploited: { type: 'boolean' },
  },
  required: ['id', 'canonicalId', 'type'],
} as const;

const EVIDENCE_SCHEMA_JSON = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  title: 'Evidence',
  type: 'object',
  properties: {
    id: { type: 'string' },
    advisoryId: { type: 'string' },
    source: { type: 'string' },
    type: { type: 'string' },
    fetchedAt: { type: 'string', format: 'date-time' },
    observedAt: { type: 'string', format: 'date-time' },
    sourceModifiedAt: { type: 'string', format: 'date-time' },
    confidence: { type: 'number', minimum: 0, maximum: 1 },
    trustTier: { type: 'string', enum: ['A', 'B', 'C', 'D'] },
    summary: { type: 'string' },
    normalized: { type: 'object' },
  },
  required: ['id', 'advisoryId', 'source', 'type', 'fetchedAt', 'confidence', 'trustTier'],
} as const;

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

  registerAliasResource(
    server,
    store,
    'advisory-by-cve',
    'advisory://cve/{cveId}',
    'cveId',
    'Same as advisory://id/{id} but scoped to CVE identifiers.',
  );
  registerAliasResource(
    server,
    store,
    'advisory-by-ghsa',
    'advisory://ghsa/{ghsaId}',
    'ghsaId',
    'Same as advisory://id/{id} but scoped to GHSA identifiers.',
  );
  registerAliasResource(
    server,
    store,
    'advisory-by-osv',
    'advisory://osv/{osvId}',
    'osvId',
    'Same as advisory://id/{id} but scoped to OSV / ecosystem identifiers (PYSEC, RUSTSEC, GO).',
  );

  server.registerResource(
    'package-summary',
    new ResourceTemplate('advisory://package/{purl}', { list: undefined }),
    {
      title: 'Package advisory summary',
      description: 'Returns advisories that match the given PURL from the local store.',
    },
    (uri, vars) => {
      const purl = decodeURIComponent(String(vars.purl ?? ''));
      const result = analyzePackage(store, { purl, profile: 'application_dependency' });
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
    'schema-advisory',
    'advisory://schema/advisory',
    {
      title: 'Advisory schema',
      description: 'JSON Schema for the canonical merged advisory shape.',
      mimeType: SCHEMA_MIME,
    },
    (uri) => ({
      contents: [
        {
          uri: uri.href,
          mimeType: SCHEMA_MIME,
          text: JSON.stringify(ADVISORY_SCHEMA_JSON, null, 2),
        },
      ],
    }),
  );

  server.registerResource(
    'schema-evidence',
    'advisory://schema/evidence',
    {
      title: 'Evidence schema',
      description: 'JSON Schema for an advisory evidence row.',
      mimeType: SCHEMA_MIME,
    },
    (uri) => ({
      contents: [
        {
          uri: uri.href,
          mimeType: SCHEMA_MIME,
          text: JSON.stringify(EVIDENCE_SCHEMA_JSON, null, 2),
        },
      ],
    }),
  );
}

function registerAliasResource(
  server: McpServer,
  store: AdvisoryStore,
  resourceName: string,
  template: string,
  varName: string,
  description: string,
): void {
  server.registerResource(
    resourceName,
    new ResourceTemplate(template, { list: undefined }),
    { title: 'Advisory alias', description },
    (uri, vars) => {
      // eslint-disable-next-line security/detect-object-injection -- varName is a literal passed by registerAdvisoryResources
      const id = String(vars[varName] ?? '');
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
}
