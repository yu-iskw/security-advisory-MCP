import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import { registerAdvisoryResources } from './resources.js';
import { analyzeAdvisory, AnalyzeAdvisoryInputSchema } from './tools/analyze-advisory.js';
import { ping } from './tools/ping.js';
import { searchAdvisories, SearchAdvisoriesInputSchema } from './tools/search-advisories.js';

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

    registerAdvisoryResources(server, store);
  }

  return server;
}
