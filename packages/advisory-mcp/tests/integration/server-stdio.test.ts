import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { createMcpServer, SERVER_NAME, SERVER_VERSION } from '../../src/index.js';

interface TextContent {
  type: string;
  text: string;
}

describe('advisory-mcp server (in-memory transport)', () => {
  let client: Client;
  let server: ReturnType<typeof createMcpServer>;

  beforeEach(async () => {
    server = createMcpServer();
    client = new Client({ name: 'test-client', version: '0.0.0' });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  });

  afterEach(async () => {
    await client.close();
    await server.close();
  });

  it('lists the ping tool', async () => {
    const tools = await client.listTools();
    expect(tools.tools.map((t) => t.name)).toContain('ping');
  });

  it('responds to a ping tool call with ok=true and server metadata', async () => {
    const result = await client.callTool({ name: 'ping', arguments: {} });
    const content = result.content as TextContent[];
    expect(content[0]?.type).toBe('text');
    const parsed = JSON.parse(content[0]?.text ?? '{}') as {
      ok: boolean;
      name: string;
      version: string;
    };
    expect(parsed).toEqual({
      ok: true,
      name: SERVER_NAME,
      version: SERVER_VERSION,
    });
  });
});
