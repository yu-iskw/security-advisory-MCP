import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import { RISK_PROFILE_NAMES } from '../risk/profiles.js';

import { registerAdvisoryResources } from './resources.js';
import { analyzeAdvisory, AnalyzeAdvisoryInputSchema } from './tools/analyze-advisory.js';
import { analyzePackage, AnalyzePackageInputSchema } from './tools/analyze-package.js';
import { explainRisk, ExplainRiskInputSchema } from './tools/explain-risk.js';
import { ping } from './tools/ping.js';
import { searchAdvisories, SearchAdvisoriesInputSchema } from './tools/search-advisories.js';
import { sourceStatus, SourceStatusInputSchema } from './tools/source-status.js';

import type { AdvisoryStore } from '../store/store.js';

export const SERVER_NAME = 'advisory-mcp';
export const SERVER_VERSION = '0.1.0';

interface CreateMcpServerOptions {
  store?: AdvisoryStore;
}

export function createMcpServer(options: CreateMcpServerOptions = {}): McpServer {
  const server = new McpServer({
    name: SERVER_NAME,
    version: SERVER_VERSION,
  });

  server.registerTool(
    'ping',
    {
      title: 'Ping',
      description:
        'Health check. Returns the server name and version. Does not access the network.',
      inputSchema: {},
    },
    () => {
      const result = ping(SERVER_NAME, SERVER_VERSION);
      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(result),
          },
        ],
      };
    },
  );

  if (options.store) {
    const store = options.store;
    server.registerTool(
      'analyze_advisory',
      {
        title: 'Analyze advisory',
        description:
          'Analyze a locally-cached advisory by CVE, GHSA, OSV, or any known alias. ' +
          'Returns risk-relevant evidence (incl. CISA KEV exploitation status) and a ' +
          'human-readable markdown summary. Advisory text is treated as untrusted and ' +
          'returned inside an explicit untrusted-content fence. Does not access the network.',
        inputSchema: {
          id: z.string().min(1).max(128),
          includeEvidence: z.boolean().default(true).optional(),
        },
      },
      (input) => {
        const parsed = AnalyzeAdvisoryInputSchema.parse(input);
        const result = analyzeAdvisory(store, parsed);
        return {
          content: [
            { type: 'text' as const, text: result.markdown },
            { type: 'text' as const, text: JSON.stringify(result, null, 2) },
          ],
        };
      },
    );

    server.registerTool(
      'search_advisories',
      {
        title: 'Search advisories',
        description:
          'Full-text search the locally-cached advisory index. Supports optional ' +
          'filters for severity, knownExploited, and hasFix. Returns up to 50 hits ' +
          'sorted by relevance. Does not access the network.',
        inputSchema: {
          query: z.string().min(1).max(200),
          severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
          knownExploited: z.boolean().optional(),
          hasFix: z.boolean().optional(),
          limit: z.number().int().min(1).max(50).default(10).optional(),
        },
      },
      (input) => {
        const parsed = SearchAdvisoriesInputSchema.parse(input);
        const result = searchAdvisories(store, parsed);
        return {
          content: [
            { type: 'text' as const, text: result.markdown },
            { type: 'text' as const, text: JSON.stringify(result, null, 2) },
          ],
        };
      },
    );

    server.registerTool(
      'source_status',
      {
        title: 'Source status',
        description:
          'Report sync status and freshness for each configured advisory source. ' +
          'Sources past the configured staleness threshold are flagged. Does not ' +
          'access the network.',
        inputSchema: {
          source: z.string().min(1).max(64).optional(),
          staleAfterHours: z.number().int().min(1).max(24 * 30).default(168).optional(),
        },
      },
      (input) => {
        const parsed = SourceStatusInputSchema.parse(input);
        const result = sourceStatus(store, parsed);
        return {
          content: [
            { type: 'text' as const, text: result.markdown },
            { type: 'text' as const, text: JSON.stringify(result, null, 2) },
          ],
        };
      },
    );

    server.registerTool(
      'explain_risk',
      {
        title: 'Explain risk score',
        description:
          'Compute a profile-aware risk score for an advisory from local evidence ' +
          '(CISA KEV, EPSS, advisory recency, source confidence). Returns each ' +
          'positive driver and known uncertainty. Does not access the network.',
        inputSchema: {
          id: z.string().min(1).max(128),
          profile: z.enum(RISK_PROFILE_NAMES).default('default').optional(),
        },
      },
      (input) => {
        const parsed = ExplainRiskInputSchema.parse(input);
        const result = explainRisk(store, parsed);
        return {
          content: [
            { type: 'text' as const, text: result.markdown },
            { type: 'text' as const, text: JSON.stringify(result, null, 2) },
          ],
        };
      },
    );

    server.registerTool(
      'analyze_package',
      {
        title: 'Analyze package',
        description:
          'Check a package (by PURL or ecosystem+name+version) against the ' +
          'local advisory store. Flags vulnerable version ranges and malicious-' +
          'package matches. Does not access the network.',
        inputSchema: {
          purl: z.string().optional(),
          ecosystem: z.string().optional(),
          name: z.string().optional(),
          version: z.string().optional(),
          profile: z
            .enum(RISK_PROFILE_NAMES)
            .default('application_dependency')
            .optional(),
        },
      },
      (input) => {
        const parsed = AnalyzePackageInputSchema.parse(input);
        const result = analyzePackage(store, parsed);
        return {
          content: [
            { type: 'text' as const, text: result.markdown },
            { type: 'text' as const, text: JSON.stringify(result, null, 2) },
          ],
        };
      },
    );

    registerAdvisoryResources(server, store);
  }

  return server;
}
