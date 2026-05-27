import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, describe, expect, it } from 'vitest';

import { runInit } from '../../src/cli/commands/init.js';
import { createMcpServer } from '../../src/mcp/server.js';
import {
  DatabaseNotInitializedError,
  isStoreInitialized,
  openStore,
} from '../../src/store/db.js';

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe('empty / initialized database', () => {
  it('reports uninitialized when database file is missing', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'advisory-mcp-empty-'));
    tempDirs.push(dir);
    const databasePath = path.join(dir, 'missing.db');
    expect(isStoreInitialized(databasePath)).toBe(false);
    expect(() => {
      throw new DatabaseNotInitializedError(databasePath);
    }).toThrow(/sync --preset core/);
  });

  it('lists source_status via in-memory MCP transport after init', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'advisory-mcp-mcp-'));
    tempDirs.push(dir);
    const databasePath = path.join(dir, 'advisory.db');
    runInit({ databasePath, cachePath: path.join(dir, 'cache') });

    const store = openStore({ databasePath });
    const server = createMcpServer({ store, requireInitialized: true });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'test-client', version: '0.0.0' });

    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const tools = await client.listTools();
    expect(tools.tools.map((t) => t.name)).toContain('source_status');

    const call = await client.callTool({
      name: 'source_status',
      arguments: { includeDisabled: false },
    });
    expect(call.content).toBeDefined();
    const textBlocks = (call.content as Array<{ type: string; text?: string }>).filter(
      (c) => c.type === 'text',
    );
    expect(textBlocks.some((b) => b.text?.includes('cveproject'))).toBe(true);

    const resources = await client.listResources();
    expect(resources.resources.some((r) => r.uri === 'advisory://source/status')).toBe(true);

    const prompts = await client.listPrompts();
    expect(prompts.prompts.map((p) => p.name)).toContain('triage-advisory');

    await client.close();
    await server.close();
    store.close();
  });
});
