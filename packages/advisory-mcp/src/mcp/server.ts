import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import { sourceStatusInputSchema } from '../schemas/source.js';
import { assertStoreReady } from '../store/db.js';
import {
  buildSourceStatusSummary,
  sourceStatusPayload,
} from '../store/repositories/source-state-repository.js';

import { PROMPT_NAMES, buildTriageAdvisoryPrompt } from './prompts.js';
import {
  RISK_PROFILE_NAMES,
  readRiskProfileResource,
  readSourceStatusResource,
  RESOURCE_URIS,
  resourceContents,
} from './resources.js';

import type { AdvisoryStore } from '../store/db.js';

export const SERVER_NAME = 'advisory-mcp';
export const SERVER_VERSION = '0.1.0';

export interface CreateMcpServerOptions {
  store: AdvisoryStore;
  requireInitialized?: boolean;
}

export function createMcpServer(options: CreateMcpServerOptions): McpServer {
  const { store, requireInitialized = true } = options;
  const server = new McpServer({
    name: SERVER_NAME,
    version: SERVER_VERSION,
  });

  const ensureReady = (): void => {
    if (requireInitialized) {
      assertStoreReady(store);
    }
  };

  server.registerTool(
    'source_status',
    {
      description:
        'Return sync and freshness state for configured advisory sources. Read-only; does not access the network.',
      inputSchema: sourceStatusInputSchema,
    },
    (input) => {
      ensureReady();
      const summary = buildSourceStatusSummary(store, input);
      const structured = sourceStatusPayload(summary);
      return {
        content: [
          { type: 'text', text: summary.markdownSummary },
          { type: 'text', text: JSON.stringify(structured, null, 2) },
        ],
      };
    },
  );

  server.registerResource(
    'source-status',
    RESOURCE_URIS.sourceStatus,
    {
      description: 'Sync and freshness state for all configured sources',
      mimeType: 'application/json',
    },
    () => {
      ensureReady();
      return resourceContents(readSourceStatusResource(store));
    },
  );

  for (const profileName of RISK_PROFILE_NAMES) {
    server.registerResource(
      `risk-profile-${profileName}`,
      RESOURCE_URIS.riskProfile(profileName),
      {
        description: `Risk prioritization profile: ${profileName}`,
        mimeType: 'application/json',
      },
      () => resourceContents(readRiskProfileResource(profileName)),
    );
  }

  server.registerPrompt(
    PROMPT_NAMES.triageAdvisory,
    {
      description: 'Analyst-grade triage workflow for a single advisory ID',
      argsSchema: {
        id: z.string().describe('CVE, GHSA, OSV, or alias ID'),
        environment: z.string().optional().describe('Deployment context'),
      },
    },
    (args) => buildTriageAdvisoryPrompt(args),
  );

  return server;
}
