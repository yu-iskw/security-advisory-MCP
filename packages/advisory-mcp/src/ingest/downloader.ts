import { request } from 'undici';

import { LIMITS } from '../security/limits.js';
import { UrlPolicyError } from '../security/url-policy.js';

import { sha256Hex } from './verifier.js';

import type { UrlPolicy } from '../security/url-policy.js';

export class DownloadError extends Error {
  constructor(
    message: string,
    public readonly reason: 'policy' | 'http' | 'oversized' | 'timeout' | 'redirect' | 'aborted',
  ) {
    super(message);
    this.name = 'DownloadError';
  }
}

export interface DownloadRequest {
  url: string;
  /** Conditional-request validators. If the server replies 304, returns undefined. */
  etag?: string;
  lastModified?: string;
  /** Cap on response body bytes (defaults to LIMITS). */
  maxBytes?: number;
  /** Per-request timeout in ms (defaults to LIMITS). */
  timeoutMs?: number;
  /** Aborts the in-flight request when triggered. */
  signal?: AbortSignal;
}

export interface DownloadedBody {
  url: string;
  status: number;
  contentType: string | undefined;
  etag: string | undefined;
  lastModified: string | undefined;
  body: Uint8Array;
  sha256: string;
}

export interface Downloader {
  download(req: DownloadRequest): Promise<DownloadedBody | 'not_modified'>;
}

/**
 * HTTPS downloader with:
 *  - URL allowlist + private-address rejection via UrlPolicy;
 *  - response-size cap (streaming check, fail-fast);
 *  - per-request timeout;
 *  - manual redirect handling: each Location must pass UrlPolicy
 *    before the next request is issued (defends against open-redirect
 *    SSRF and DNS rebinding chains);
 *  - conditional requests via If-None-Match / If-Modified-Since with
 *    `not_modified` returned on 304.
 */
export class HttpsDownloader implements Downloader {
  private static readonly MAX_REDIRECTS = 5;

  constructor(private readonly policy: UrlPolicy) {}

  async download(req: DownloadRequest): Promise<DownloadedBody | 'not_modified'> {
    const maxBytes = req.maxBytes ?? LIMITS.defaultMaxDownloadBytes;
    const timeoutMs = req.timeoutMs ?? LIMITS.httpTimeoutMs;

    let currentUrl = req.url;
    for (let hop = 0; hop <= HttpsDownloader.MAX_REDIRECTS; hop++) {
      const verified = await this.verifyOrThrow(currentUrl);
      const result = await this.requestOnce({
        url: verified.href,
        etag: hop === 0 ? req.etag : undefined,
        lastModified: hop === 0 ? req.lastModified : undefined,
        maxBytes,
        timeoutMs,
        signal: req.signal,
      });

      if (result.status === 304) return 'not_modified';

      if (result.status >= 300 && result.status < 400 && result.location) {
        currentUrl = new URL(result.location, verified).href;
        continue;
      }

      if (result.status < 200 || result.status >= 300) {
        throw new DownloadError(`HTTP ${result.status} for ${verified.href}`, 'http');
      }

      return {
        url: verified.href,
        status: result.status,
        contentType: result.contentType,
        etag: result.etag,
        lastModified: result.lastModified,
        body: result.body,
        sha256: sha256Hex(result.body),
      };
    }

    throw new DownloadError(`too many redirects starting at ${req.url}`, 'redirect');
  }

  private async verifyOrThrow(url: string): Promise<URL> {
    try {
      return await this.policy.assertSafe(url);
    } catch (err) {
      if (err instanceof UrlPolicyError) {
        throw new DownloadError(err.message, 'policy');
      }
      throw err;
    }
  }

  private async requestOnce(opts: {
    url: string;
    etag: string | undefined;
    lastModified: string | undefined;
    maxBytes: number;
    timeoutMs: number;
    signal: AbortSignal | undefined;
  }): Promise<{
    status: number;
    contentType: string | undefined;
    etag: string | undefined;
    lastModified: string | undefined;
    location: string | undefined;
    body: Uint8Array;
  }> {
    const headers: Record<string, string> = {
      'user-agent': 'advisory-mcp/0.1.0 (+https://github.com/yu-iskw/security-advisory-mcp)',
      'accept-encoding': 'identity',
    };
    if (opts.etag) headers['if-none-match'] = opts.etag;
    if (opts.lastModified) headers['if-modified-since'] = opts.lastModified;

    const controller = new AbortController();
    const timer = setTimeout(() => {
      controller.abort();
    }, opts.timeoutMs);
    const onParentAbort = (): void => {
      controller.abort();
    };
    opts.signal?.addEventListener('abort', onParentAbort, { once: true });

    try {
      // undici's request() does not follow redirects by default; we handle
      // each Location manually so it can be re-checked against UrlPolicy.
      const res = await request(opts.url, {
        method: 'GET',
        headers,
        signal: controller.signal,
      });
      const status = res.statusCode;
      const contentType = singleHeader(res.headers['content-type']);
      const etag = singleHeader(res.headers.etag);
      const lastModified = singleHeader(res.headers['last-modified']);
      const location = singleHeader(res.headers.location);

      if (status === 304 || (status >= 300 && status < 400)) {
        // drain and discard
        await res.body.dump();
        return {
          status,
          contentType,
          etag,
          lastModified,
          location,
          body: new Uint8Array(0),
        };
      }

      const body = await readBodyWithLimit(res.body, opts.maxBytes);
      return { status, contentType, etag, lastModified, location, body };
    } catch (err) {
      if (controller.signal.aborted && !opts.signal?.aborted) {
        throw new DownloadError(
          `request timeout after ${opts.timeoutMs}ms: ${opts.url}`,
          'timeout',
        );
      }
      if (opts.signal?.aborted) {
        throw new DownloadError('download aborted', 'aborted');
      }
      throw err;
    } finally {
      clearTimeout(timer);
      opts.signal?.removeEventListener('abort', onParentAbort);
    }
  }
}

interface BodyStream {
  on(event: 'data', listener: (chunk: Buffer) => void): unknown;
  on(event: 'end' | 'error', listener: (err?: Error) => void): unknown;
  destroy(): void;
}

async function readBodyWithLimit(body: BodyStream, maxBytes: number): Promise<Uint8Array> {
  const chunks: Buffer[] = [];
  let total = 0;
  return new Promise<Uint8Array>((resolve, reject) => {
    body.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) {
        body.destroy();
        reject(new DownloadError(`response exceeded ${maxBytes} bytes`, 'oversized'));
        return;
      }
      chunks.push(chunk);
    });
    body.on('end', () => {
      resolve(new Uint8Array(Buffer.concat(chunks, total)));
    });
    body.on('error', (err) => {
      reject(err ?? new Error('stream error'));
    });
  });
}

function singleHeader(h: string | string[] | undefined): string | undefined {
  if (Array.isArray(h)) return h[0];
  return h;
}
