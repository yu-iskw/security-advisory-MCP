import { isIP } from 'node:net';

const ALLOWED_HOSTS = new Set([
  'github.com',
  'raw.githubusercontent.com',
  'nvd.nist.gov',
  'services.nvd.nist.gov',
  'www.cisa.gov',
  'cisagov.github.io',
  'epss.cyentia.com',
  'osv-vulnerabilities.storage.googleapis.com',
  'api.osv.dev',
  'mitre.org',
  'cveawg.mitre.org',
]);

function isBlockedIp(ip: string): boolean {
  if (ip === '127.0.0.1' || ip === '::1' || ip === '0.0.0.0') {
    return true;
  }
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('169.254.')) {
    return true;
  }
  if (ip.startsWith('172.')) {
    const second = Number.parseInt(ip.split('.')[1] ?? '0', 10);
    if (second >= 16 && second <= 31) {
      return true;
    }
  }
  if (ip.startsWith('fc') || ip.startsWith('fd') || ip === '::') {
    return true;
  }
  return false;
}

export function assertAllowlistedUrl(urlString: string): URL {
  let url: URL;
  try {
    url = new URL(urlString);
  } catch {
    throw new Error(`Invalid URL: ${urlString}`);
  }
  if (url.protocol !== 'https:') {
    throw new Error(`Only HTTPS URLs are allowed: ${urlString}`);
  }
  const host = url.hostname.toLowerCase();
  if (!ALLOWED_HOSTS.has(host)) {
    throw new Error(`Host not on allowlist: ${host}`);
  }
  const ipVersion = isIP(host);
  if (ipVersion && isBlockedIp(host)) {
    throw new Error(`Blocked IP: ${host}`);
  }
  return url;
}
