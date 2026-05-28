import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { createMcpServer } from '../../src/mcp/server.js';
import { openAdvisoryStore, type AdvisoryStore } from '../../src/store/store.js';

interface TextContent {
  type: string;
  text: string;
}

interface ResourceContent {
  uri: string;
  mimeType?: string;
  text?: string;
}

function seedAdvisory(store: AdvisoryStore): void {
  store.advisories.upsert({
    id: 'CVE-2021-44228',
    canonicalId: 'CVE-2021-44228',
    type: 'cve',
    title: 'Apache Log4j2 Remote Code Execution Vulnerability',
    description: 'Log4j2 JNDI lookup allows remote code execution.',
    mergedJson: '{}',
  });
  store.evidence.upsert({
    id: 'kev:CVE-2021-44228',
    advisoryId: 'CVE-2021-44228',
    source: 'cisa-kev',
    type: 'known_exploited',
    fetchedAt: '2026-05-27T00:00:00.000Z',
    confidence: 0.95,
    trustTier: 'A',
    summary: 'Log4Shell listed in CISA KEV.',
    normalizedJson: JSON.stringify({ cveID: 'CVE-2021-44228', dateAdded: '2021-12-10' }),
  });
}

describe('mcp integration: analyze_advisory + advisory resource', () => {
  let store: AdvisoryStore;
  let client: Client;
  let server: ReturnType<typeof createMcpServer>;

  beforeEach(async () => {
    store = openAdvisoryStore({ path: ':memory:', noWal: true });
    seedAdvisory(store);

    server = createMcpServer({ store });
    client = new Client({ name: 'test-client', version: '0.0.0' });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  });

  afterEach(async () => {
    await client.close();
    await server.close();
    store.close();
  });

  it('lists analyze_advisory alongside ping in tools/list', async () => {
    const tools = await client.listTools();
    const names = tools.tools.map((t) => t.name);
    expect(names).toContain('ping');
    expect(names).toContain('analyze_advisory');
  });

  it('returns markdown + JSON content for a known CVE', async () => {
    const res = await client.callTool({
      name: 'analyze_advisory',
      arguments: { id: 'CVE-2021-44228' },
    });
    const content = res.content as TextContent[];
    expect(content).toHaveLength(2);
    expect(content[0]?.text).toMatch(/CVE-2021-44228/);
    expect(content[0]?.text).toMatch(/Log4j/);
    const parsed = JSON.parse(content[1]?.text ?? '{}') as {
      found: boolean;
      knownExploited?: { listed: boolean };
    };
    expect(parsed.found).toBe(true);
    expect(parsed.knownExploited?.listed).toBe(true);
  });

  it('returns found=false for an unknown id', async () => {
    const res = await client.callTool({
      name: 'analyze_advisory',
      arguments: { id: 'CVE-9999-9999' },
    });
    const content = res.content as TextContent[];
    const parsed = JSON.parse(content[1]?.text ?? '{}') as { found: boolean };
    expect(parsed.found).toBe(false);
  });

  it('exposes advisory://id/{id} as an MCP resource', async () => {
    const res = await client.readResource({ uri: 'advisory://id/CVE-2021-44228' });
    expect(res.contents).toHaveLength(1);
    const c = res.contents[0] as ResourceContent;
    expect(c.mimeType).toBe('application/json');
    const parsed = JSON.parse(c.text ?? '{}') as { advisory?: { id: string } };
    expect(parsed.advisory?.id).toBe('CVE-2021-44228');
  });

  it('exposes advisory://cve/{cveId} as an MCP resource', async () => {
    const res = await client.readResource({ uri: 'advisory://cve/CVE-2021-44228' });
    const c = res.contents[0] as ResourceContent;
    const parsed = JSON.parse(c.text ?? '{}') as { found: boolean };
    expect(parsed.found).toBe(true);
  });
});
