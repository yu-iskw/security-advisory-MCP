import { createServer } from 'node:http';

/**
 * HTTP transport stub for Phase 4. Returns 503 with guidance to use stdio.
 */
export async function serveHttp(port: number): Promise<void> {
  const httpServer = createServer((_req, res) => {
    res.writeHead(503, { 'Content-Type': 'application/json' });
    res.end(
      JSON.stringify({
        error: 'Streamable HTTP transport is not fully implemented',
        hint: 'Use: advisory-mcp serve --transport stdio',
      }),
    );
  });

  await new Promise<void>((resolve) => {
    httpServer.listen(port, () => resolve());
  });
  process.stderr.write(`advisory-mcp HTTP stub listening on :${port} (use stdio for MCP)\n`);

  await new Promise<void>((resolve) => {
    const shutdown = () => {
      httpServer.close(() => resolve());
    };
    process.once('SIGINT', shutdown);
    process.once('SIGTERM', shutdown);
  });
}
