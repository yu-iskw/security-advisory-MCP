import { describe, expect, it } from 'vitest';

import { DownloadError, HttpsDownloader } from '../../src/ingest/downloader.js';
import { UrlPolicy } from '../../src/security/url-policy.js';

const ALLOWED = ['evil.example.test'];

describe('security: URL policy survives integration with HttpsDownloader', () => {
  it('blocks an https URL whose host is not on the allowlist', async () => {
    const policy = new UrlPolicy({
      allowedHosts: ['only-this-host.test'],
      resolver: () => Promise.resolve(['1.1.1.1']),
    });
    const dl = new HttpsDownloader(policy);
    await expect(dl.download({ url: 'https://evil.example.test/' }))
      .rejects.toMatchObject({ name: 'DownloadError', reason: 'policy' });
  });

  it('blocks an allowlisted host that resolves to AWS metadata endpoint (DNS rebinding)', async () => {
    const policy = new UrlPolicy({
      allowedHosts: ALLOWED,
      resolver: () => Promise.resolve(['169.254.169.254']),
    });
    const dl = new HttpsDownloader(policy);
    try {
      await dl.download({ url: 'https://evil.example.test/' });
      expect.fail('should have rejected');
    } catch (err) {
      expect(err).toBeInstanceOf(DownloadError);
      expect((err as DownloadError).reason).toBe('policy');
      expect((err as Error).message).toMatch(/169\.254\.169\.254/);
    }
  });

  it('blocks plain http even if the host is allowlisted', async () => {
    const policy = new UrlPolicy({
      allowedHosts: ALLOWED,
      resolver: () => Promise.resolve(['1.1.1.1']),
    });
    const dl = new HttpsDownloader(policy);
    await expect(dl.download({ url: 'http://evil.example.test/' }))
      .rejects.toMatchObject({ name: 'DownloadError', reason: 'policy' });
  });

  it('blocks loopback resolutions (127.0.0.1)', async () => {
    const policy = new UrlPolicy({
      allowedHosts: ALLOWED,
      resolver: () => Promise.resolve(['127.0.0.1']),
    });
    const dl = new HttpsDownloader(policy);
    await expect(dl.download({ url: 'https://evil.example.test/' }))
      .rejects.toMatchObject({ name: 'DownloadError', reason: 'policy' });
  });
});
