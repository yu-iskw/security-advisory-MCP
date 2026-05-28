import { describe, expect, it } from 'vitest';

import { UrlPolicy } from '../security/url-policy.js';

import { DownloadError, HttpsDownloader } from './downloader.js';

describe('HttpsDownloader', () => {
  it('rejects URLs that violate the policy with DownloadError(policy)', async () => {
    const policy = new UrlPolicy({
      allowedHosts: ['example.com'],
      resolver: () => Promise.resolve(['1.1.1.1']),
    });
    const dl = new HttpsDownloader(policy);
    await expect(dl.download({ url: 'https://evil.example.org/' })).rejects.toMatchObject({
      reason: 'policy',
    });
  });

  it('rejects non-https URLs with DownloadError(policy)', async () => {
    const policy = new UrlPolicy({
      allowedHosts: ['example.com'],
      resolver: () => Promise.resolve(['1.1.1.1']),
    });
    const dl = new HttpsDownloader(policy);
    await expect(dl.download({ url: 'http://example.com/' })).rejects.toBeInstanceOf(DownloadError);
  });

  it('rejects hosts that resolve to private/loopback addresses', async () => {
    const policy = new UrlPolicy({
      allowedHosts: ['example.com'],
      resolver: () => Promise.resolve(['127.0.0.1']),
    });
    const dl = new HttpsDownloader(policy);
    await expect(dl.download({ url: 'https://example.com/' })).rejects.toMatchObject({
      reason: 'policy',
    });
  });
});
