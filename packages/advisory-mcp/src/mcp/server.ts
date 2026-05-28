import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import { RISK_PROFILE_NAMES } from '../risk/profiles.js';
import { PathPolicy } from '../security/path-policy.js';

import { registerPrompts } from './prompts.js';
import { registerAdvisoryResources } from './resources.js';
import { analyzeAdvisory, AnalyzeAdvisoryInputSchema } from './tools/analyze-advisory.js';
import { analyzePackage, AnalyzePackageInputSchema } from './tools/analyze-package.js';
import { explainRisk, ExplainRiskInputSchema } from './tools/explain-risk.js';
import { ping } from './tools/ping.js';
import { prioritize, PrioritizeInputSchema } from './tools/prioritize.js';
import { scanSbomFile, ScanSbomFileInputSchema } from './tools/scan-sbom-file.js';
import { scanSbom, ScanSbomInputSchema } from './tools/scan-sbom.js';
import { searchAdvisories, SearchAdvisoriesInputSchema } from './tools/search-advisories.js';
import { sourceStatus, SourceStatusInputSchema } from './tools/source-status.js';

import type { AdvisoryStore } from '../store/store.js';

export const SERVER_NAME = 'advisory-mcp';
export const SERVER_VERSION = '0.1.0';

interface CreateMcpServerOptions {
  store?: AdvisoryStore;
  /** Approved directories for scan_sbom_file. Empty disables the tool. */
  sbomRoots?: ReadonlyArray<string>;
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
          staleAfterHours: z
            .number()
            .int()
            .min(1)
            .max(24 * 30)
            .default(168)
            .optional(),
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
          profile: z.enum(RISK_PROFILE_NAMES).default('application_dependency').optional(),
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

    server.registerTool(
      'scan_sbom',
      {
        title: 'Scan SBOM',
        description:
          'Scan a CycloneDX or SPDX JSON SBOM against the local advisory store. ' +
          'Returns per-component matches with risk scores. Does not access the network.',
        inputSchema: {
          sbomJson: z.string(),
          format: z.enum(['auto', 'cyclonedx', 'spdx']).default('auto').optional(),
          profile: z
            .enum(['default', 'internet_exposed', 'application_dependency', 'container_image'])
            .default('application_dependency')
            .optional(),
          includeDevDependencies: z.boolean().default(false).optional(),
          limit: z.number().int().min(1).max(500).default(100).optional(),
        },
      },
      (input) => {
        const parsed = ScanSbomInputSchema.parse(input);
        const result = scanSbom(store, parsed);
        return {
          content: [
            { type: 'text' as const, text: result.markdown },
            { type: 'text' as const, text: JSON.stringify(result, null, 2) },
          ],
        };
      },
    );

    server.registerTool(
      'prioritize',
      {
        title: 'Prioritize findings',
        description:
          'Rank a mixed list of advisory IDs and/or packages by profile-aware ' +
          'risk score. Returns a deduplicated, sorted list. Does not access the ' +
          'network.',
        inputSchema: {
          advisoryIds: z.array(z.string().min(1).max(128)).max(500).optional(),
          packages: z
            .array(
              z.object({
                purl: z.string().optional(),
                ecosystem: z.string().optional(),
                name: z.string().optional(),
                version: z.string().optional(),
              }),
            )
            .max(500)
            .optional(),
          profile: z.enum(RISK_PROFILE_NAMES).default('default').optional(),
        },
      },
      (input) => {
        const parsed = PrioritizeInputSchema.parse(input);
        const result = prioritize(store, parsed);
        return {
          content: [
            { type: 'text' as const, text: result.markdown },
            { type: 'text' as const, text: JSON.stringify(result, null, 2) },
          ],
        };
      },
    );

    if (options.sbomRoots && options.sbomRoots.length > 0) {
      const pathPolicy = new PathPolicy(options.sbomRoots);
      server.registerTool(
        'scan_sbom_file',
        {
          title: 'Scan SBOM file',
          description:
            'Read an SBOM (CycloneDX or SPDX JSON) from an operator-approved ' +
            'path on disk and scan it against the local advisory store. The path ' +
            'must be inside one of the configured `sbomRoots`. Does not access ' +
            'the network.',
          inputSchema: {
            path: z.string().min(1).max(4096),
            format: z.enum(['auto', 'cyclonedx', 'spdx']).default('auto').optional(),
            profile: z
              .enum(['default', 'internet_exposed', 'application_dependency', 'container_image'])
              .default('application_dependency')
              .optional(),
            includeDevDependencies: z.boolean().default(false).optional(),
            limit: z.number().int().min(1).max(500).default(100).optional(),
          },
        },
        async (input) => {
          const parsed = ScanSbomFileInputSchema.parse(input);
          const result = await scanSbomFile(store, pathPolicy, parsed);
          return {
            content: [
              { type: 'text' as const, text: result.markdown },
              { type: 'text' as const, text: JSON.stringify(result, null, 2) },
            ],
          };
        },
      );
    }

    registerAdvisoryResources(server, store);
    registerPrompts(server);
  }

  return server;
}
