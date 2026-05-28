import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';

import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';

import { createMcpServer } from '../server.js';

import type { AdvisoryStore } from '../../store/store.js';

interface ServeHttpOptions {
  port: number;
  host?: string;
  store?: AdvisoryStore;
  sbomRoots?: ReadonlyArray<string>;
}

export interface HttpServerHandle {
  server: Server;
  port: number;
  close(): Promise<void>;
}

/**
 * Stateless Streamable HTTP transport. Each POST creates a fresh MCP server
 * + transport pair, handles the single JSON-RPC request, and tears down.
 * That's the most defensive deployment shape (no cross-request state, no
 * long-lived sessions) and matches the SDK's documented stateless mode.
 *
 * GET (for SSE streaming) and non-JSON-RPC paths return 405.
 */
export async function serveStreamableHttp(opts: ServeHttpOptions): Promise<HttpServerHandle> {
  const httpServer = createServer((req, res) => {
    void handle(req, res, opts);
  });
  await new Promise<void>((resolve) => {
    httpServer.listen(opts.port, opts.host ?? '127.0.0.1', () => {
      resolve();
    });
  });
  return {
    server: httpServer,
    port: opts.port,
    close: () =>
      new Promise<void>((resolve, reject) => {
        httpServer.close((err) => {
          if (err) reject(err);
          else resolve();
        });
      }),
  };
}

async function handle(
  req: IncomingMessage,
  res: ServerResponse,
  opts: ServeHttpOptions,
): Promise<void> {
  if (req.method !== 'POST') {
    res.statusCode = 405;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ error: 'POST required' }));
    return;
  }
  const server = createMcpServer({ store: opts.store, sbomRoots: opts.sbomRoots });
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });

  const cleanup = (): void => {
    void transport.close();
    void server.close();
  };
  res.on('close', cleanup);

  try {
    await server.connect(transport);
    const body = await readJsonBody(req);
    await transport.handleRequest(req, res, body);
  } catch (err) {
    if (!res.headersSent) {
      res.statusCode = 500;
      res.setHeader('content-type', 'application/json');
      res.end(
        JSON.stringify({ error: err instanceof Error ? err.message : String(err) }),
      );
    }
    cleanup();
  }
}

async function readJsonBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array));
  }
  const text = Buffer.concat(chunks).toString('utf8');
  if (text === '') return undefined;
  return JSON.parse(text);
}
