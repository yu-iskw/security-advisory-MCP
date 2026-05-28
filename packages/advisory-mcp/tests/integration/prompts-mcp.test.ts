import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { createMcpServer } from '../../src/mcp/server.js';
import { openAdvisoryStore, type AdvisoryStore } from '../../src/store/store.js';

interface TextContent {
  type: string;
  text: string;
}

describe('mcp integration: prompts', () => {
  let store: AdvisoryStore;
  let client: Client;
  let server: ReturnType<typeof createMcpServer>;

  beforeEach(async () => {
    store = openAdvisoryStore({ path: ':memory:', noWal: true });
    server = createMcpServer({ store });
    client = new Client({ name: 'test', version: '0.0.0' });
    const [c, s] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(s), client.connect(c)]);
  });

  afterEach(async () => {
    await client.close();
    await server.close();
    store.close();
  });

  it('lists all four prompts', async () => {
    const res = await client.listPrompts();
    const names = res.prompts.map((p) => p.name).sort();
    expect(names).toEqual(['patch-brief', 'risk-acceptance-draft', 'sbom-risk-review', 'triage-advisory']);
  });

  it('triage-advisory returns instructions referencing the advisory id', async () => {
    const res = await client.getPrompt({
      name: 'triage-advisory',
      arguments: { id: 'CVE-2024-3094' },
    });
    expect(res.messages).toHaveLength(1);
    const text = (res.messages[0]?.content as TextContent).text;
    expect(text).toContain('CVE-2024-3094');
    expect(text).toContain('analyze_advisory');
    expect(text).toContain('UNTRUSTED CONTENT');
  });

  it('patch-brief accepts an audience argument', async () => {
    const res = await client.getPrompt({
      name: 'patch-brief',
      arguments: { id: 'CVE-2024-3094', audience: 'executive' },
    });
    const text = (res.messages[0]?.content as TextContent).text;
    expect(text).toContain('executive');
  });

  it('sbom-risk-review surfaces malicious packages separately', async () => {
    const res = await client.getPrompt({ name: 'sbom-risk-review', arguments: {} });
    const text = (res.messages[0]?.content as TextContent).text;
    expect(text).toMatch(/malicious-package/i);
  });
});
