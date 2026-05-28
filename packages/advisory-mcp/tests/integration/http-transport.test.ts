import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { serveStreamableHttp, type HttpServerHandle } from '../../src/mcp/transports/http.js';
import { openAdvisoryStore, type AdvisoryStore } from '../../src/store/store.js';

describe('mcp integration: streamable http transport', () => {
  let store: AdvisoryStore;
  let handle: HttpServerHandle;
  let client: Client;

  beforeEach(async () => {
    store = openAdvisoryStore({ path: ':memory:', noWal: true });
    // Port 0: let the OS pick a free port.
    handle = await serveStreamableHttp({ port: 0, host: '127.0.0.1', store });
    const address = handle.server.address();
    if (typeof address !== 'object' || address === null) throw new Error('no address');
    const transport = new StreamableHTTPClientTransport(
      new URL(`http://127.0.0.1:${address.port.toString()}/mcp`),
    );
    client = new Client({ name: 'test-http', version: '0.0.0' });
    await client.connect(transport);
  });

  afterEach(async () => {
    await client.close();
    await handle.close();
    store.close();
  });

  it('responds to a ping tool call over HTTP', async () => {
    const result = await client.callTool({ name: 'ping', arguments: {} });
    const content = result.content as { type: string; text: string }[];
    const parsed = JSON.parse(content[0]?.text ?? '{}') as { ok: boolean; name: string };
    expect(parsed.ok).toBe(true);
    expect(parsed.name).toBe('advisory-mcp');
  });

  it('lists tools over HTTP', async () => {
    const tools = await client.listTools();
    const names = tools.tools.map((t) => t.name);
    expect(names).toContain('ping');
    expect(names).toContain('analyze_advisory');
  });
});
