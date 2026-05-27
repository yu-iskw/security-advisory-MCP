import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import { sourceStatusInputSchema } from '../schemas/source.js';
import { assertStoreReady } from '../store/db.js';
import {
  buildSourceStatusSummary,
  sourceStatusPayload,
} from '../store/repositories/source-state-repository.js';

import {
  PROMPT_NAMES,
  buildPatchBriefPrompt,
  buildRiskAcceptanceDraftPrompt,
  buildSbomRiskReviewPrompt,
  buildTriageAdvisoryPrompt,
} from './prompts.js';
import {
  RISK_PROFILE_NAMES,
  readAdvisoryResource,
  readAdvisorySchemaResource,
  readEvidenceSchemaResource,
  readRiskProfileResource,
  readSourceStatusResource,
  RESOURCE_URIS,
  resourceContents,
} from './resources.js';
import { analyzeAdvisoryInputSchema, runAnalyzeAdvisory } from './tools/analyze-advisory.js';
import { analyzePackageInputSchema, runAnalyzePackage } from './tools/analyze-package.js';
import { explainRiskInputSchema, runExplainRisk } from './tools/explain-risk.js';
import { prioritizeInputSchema, runPrioritize } from './tools/prioritize.js';
import { scanSbomInputSchema, runScanSbom } from './tools/scan-sbom.js';
import { searchAdvisoriesInputSchema, runSearchAdvisories } from './tools/search-advisories.js';

import type { AdvisoryStore } from '../store/db.js';

export const SERVER_NAME = 'advisory-mcp';
export const SERVER_VERSION = '0.1.0';

export interface CreateMcpServerOptions {
  store: AdvisoryStore;
  requireInitialized?: boolean;
}

function toolResult(markdown: string, structured: unknown) {
  return {
    content: [
      { type: 'text' as const, text: markdown },
      { type: 'text' as const, text: JSON.stringify(structured, null, 2) },
    ],
  };
}

export function createMcpServer(options: CreateMcpServerOptions): McpServer {
  const { store, requireInitialized = true } = options;
  const server = new McpServer({ name: SERVER_NAME, version: SERVER_VERSION });

  const ensureReady = (): void => {
    if (requireInitialized) {
      assertStoreReady(store);
    }
  };

  server.registerTool(
    'source_status',
    {
      description: 'Return sync and freshness state. Read-only; no network.',
      inputSchema: sourceStatusInputSchema,
    },
    (input) => {
      ensureReady();
      const summary = buildSourceStatusSummary(store, input);
      return toolResult(summary.markdownSummary, sourceStatusPayload(summary));
    },
  );

  server.registerTool(
    'analyze_advisory',
    {
      description:
        'Analyze a local advisory by CVE, GHSA, OSV, or alias. Returns risk, evidence, conflicts. No network.',
      inputSchema: analyzeAdvisoryInputSchema,
    },
    (input) => {
      ensureReady();
      const result = runAnalyzeAdvisory(store, input);
      return toolResult(result.markdown, result.structured);
    },
  );

  server.registerTool(
    'search_advisories',
    {
      description: 'Search the local advisory FTS index. No network.',
      inputSchema: searchAdvisoriesInputSchema,
    },
    (input) => {
      ensureReady();
      const result = runSearchAdvisories(store, input);
      return toolResult(result.markdown, result.structured);
    },
  );

  server.registerTool(
    'explain_risk',
    {
      description: 'Explain how the risk score was derived for an advisory. No network.',
      inputSchema: explainRiskInputSchema,
    },
    (input) => {
      ensureReady();
      const result = runExplainRisk(store, input);
      return toolResult(result.markdown, result.structured);
    },
  );

  server.registerTool(
    'analyze_package',
    {
      description:
        'Check package vulnerabilities from the local store by PURL or ecosystem/name. No network.',
      inputSchema: analyzePackageInputSchema,
    },
    (input) => {
      ensureReady();
      const result = runAnalyzePackage(store, input);
      return toolResult(result.markdown, result.structured);
    },
  );

  server.registerTool(
    'scan_sbom',
    {
      description: 'Scan CycloneDX or SPDX SBOM JSON against the local advisory store. No network.',
      inputSchema: scanSbomInputSchema,
    },
    (input) => {
      ensureReady();
      const result = runScanSbom(store, input);
      return toolResult(result.markdown, result.structured);
    },
  );

  server.registerTool(
    'prioritize',
    {
      description: 'Rank advisory IDs or package findings by policy-weighted risk. No network.',
      inputSchema: prioritizeInputSchema,
    },
    (input) => {
      ensureReady();
      const result = runPrioritize(store, input);
      return toolResult(result.markdown, result.structured);
    },
  );

  server.registerResource(
    'source-status',
    RESOURCE_URIS.sourceStatus,
    { description: 'Source sync state', mimeType: 'application/json' },
    () => {
      ensureReady();
      return resourceContents(readSourceStatusResource(store));
    },
  );

  for (const name of RISK_PROFILE_NAMES) {
    server.registerResource(
      `risk-profile-${name}`,
      RESOURCE_URIS.riskProfile(name),
      { description: `Risk profile ${name}`, mimeType: 'application/json' },
      () => resourceContents(readRiskProfileResource(name)),
    );
  }

  server.registerResource(
    'schema-advisory',
    RESOURCE_URIS.advisorySchema,
    { description: 'Advisory schema', mimeType: 'application/json' },
    () => resourceContents(readAdvisorySchemaResource()),
  );

  server.registerResource(
    'schema-evidence',
    RESOURCE_URIS.evidenceSchema,
    { description: 'Evidence schema', mimeType: 'application/json' },
    () => resourceContents(readEvidenceSchemaResource()),
  );

  server.registerResource(
    'advisory-by-id',
    'advisory://id/{id}',
    { description: 'Advisory record by ID', mimeType: 'application/json' },
    (uri) => {
      ensureReady();
      const id = decodeURIComponent(uri.pathname.replace(/^\//, ''));
      return resourceContents(readAdvisoryResource(store, id));
    },
  );

  for (const goldenId of ['CVE-2021-44228', 'CVE-2024-3094', 'CVE-2023-34362']) {
    server.registerResource(
      `advisory-${goldenId}`,
      RESOURCE_URIS.advisoryById(goldenId),
      { description: `Advisory ${goldenId}`, mimeType: 'application/json' },
      () => {
        ensureReady();
        return resourceContents(readAdvisoryResource(store, goldenId));
      },
    );
  }

  server.registerPrompt(
    PROMPT_NAMES.triageAdvisory,
    {
      description: 'Analyst triage workflow',
      argsSchema: {
        id: z.string(),
        environment: z.string().optional(),
      },
    },
    (args) => buildTriageAdvisoryPrompt(args),
  );

  server.registerPrompt(
    PROMPT_NAMES.patchBrief,
    {
      description: 'Remediation brief',
      argsSchema: {
        id: z.string(),
        audience: z.enum(['engineering', 'executive', 'security']).optional(),
      },
    },
    (args) => buildPatchBriefPrompt(args),
  );

  server.registerPrompt(
    PROMPT_NAMES.sbomRiskReview,
    {
      description: 'SBOM risk review workflow',
      argsSchema: {
        projectName: z.string().optional(),
        deploymentContext: z.string().optional(),
      },
    },
    (args) => buildSbomRiskReviewPrompt(args),
  );

  server.registerPrompt(
    PROMPT_NAMES.riskAcceptanceDraft,
    {
      description: 'Risk acceptance draft',
      argsSchema: {
        id: z.string(),
        compensatingControls: z.string().optional(),
        expirationDays: z.number().optional(),
      },
    },
    (args) => buildRiskAcceptanceDraftPrompt(args),
  );

  return server;
}
