import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import { assertStoreReady, DatabaseNotInitializedError } from '../store/db.js';

import { PROMPT_NAMES, buildTriageAdvisoryPrompt } from './prompts.js';
import {
  BUILTIN_RISK_PROFILES,
  readRiskProfileResource,
  readSourceStatusResource,
  RESOURCE_URIS,
} from './resources.js';
import { runSourceStatus } from './tools/source-status.js';

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
      inputSchema: z.object({
        source: z.string().optional(),
        includeDisabled: z.boolean().default(false),
      }),
    },
    (input) => {
      ensureReady();
      const result = runSourceStatus(store, input);
      return {
        content: [
          { type: 'text', text: result.markdownSummary },
          { type: 'text', text: JSON.stringify(result.structured, null, 2) },
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
      const resource = readSourceStatusResource(store);
      return {
        contents: [
          {
            uri: resource.uri,
            mimeType: resource.mimeType,
            text: resource.text,
          },
        ],
      };
    },
  );

  for (const profileName of Object.keys(BUILTIN_RISK_PROFILES)) {
    const uri = `advisory://risk-profile/${profileName}`;
    server.registerResource(
      `risk-profile-${profileName}`,
      uri,
      {
        description: `Risk prioritization profile: ${profileName}`,
        mimeType: 'application/json',
      },
      () => {
        const resource = readRiskProfileResource(profileName);
        if (!resource) {
          throw new Error(`Unknown risk profile: ${profileName}`);
        }
        return {
          contents: [
            {
              uri: resource.uri,
              mimeType: resource.mimeType,
              text: resource.text,
            },
          ],
        };
      },
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

export { DatabaseNotInitializedError };
