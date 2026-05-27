import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, describe, expect, it } from 'vitest';

import { runInit } from '../../src/cli/commands/init.js';
import { runSync } from '../../src/cli/commands/sync.js';
import { createMcpServer } from '../../src/mcp/server.js';
import { getBundledFixturesPath } from '../../src/util/fixtures-path.js';
import { openStore } from '../../src/store/db.js';

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe('MCP tools after sync', () => {
  it('exposes all RFC tools and calls analyze_advisory', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'advisory-mcp-mcp-'));
    tempDirs.push(dir);
    const databasePath = path.join(dir, 'advisory.db');
    runInit({ databasePath, cachePath: path.join(dir, 'cache') });
    runSync({ preset: 'all', databasePath, fixturesPath: getBundledFixturesPath() });

    const store = openStore({ databasePath });
    const server = createMcpServer({ store, requireInitialized: true });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'test', version: '0.0.0' });
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const tools = await client.listTools();
    const names = tools.tools.map((t) => t.name);
    expect(names).toEqual(
      expect.arrayContaining([
        'source_status',
        'analyze_advisory',
        'search_advisories',
        'explain_risk',
        'analyze_package',
        'scan_sbom',
        'prioritize',
      ]),
    );

    const analysis = await client.callTool({
      name: 'analyze_advisory',
      arguments: { id: 'CVE-2021-44228', profile: 'default' },
    });
    const text = JSON.stringify(analysis.content);
    expect(text).toContain('CVE-2021-44228');

    await client.close();
    await server.close();
    store.close();
  });
});
