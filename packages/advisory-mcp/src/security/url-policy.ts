import { promises as dnsPromises } from 'node:dns';
import { isIP } from 'node:net';

/**
 * URL safety policy. Enforced by the downloader before every HTTP request
 * (including each redirect hop). Threats it defends against (RFC 17.1):
 *
 *  - SSRF to private / loopback / link-local / metadata IP ranges;
 *  - SSRF via DNS rebinding (the resolved IPs are re-checked, not just the
 *    hostname);
 *  - silently redirecting to non-allowlisted hosts;
 *  - non-HTTPS exfiltration channels.
 *
 * The policy is intentionally allowlist-based: every supported source
 * registers its expected host(s), and unknown hosts are rejected.
 */

const DEFAULT_ALLOWED_HOSTS: ReadonlySet<string> = new Set([
  // populated as source adapters land. KEV will add 'www.cisa.gov' in M7.
]);

interface UrlPolicyOptions {
  allowedHosts?: Iterable<string>;
  /** Used by tests to inject deterministic DNS results. */
  resolver?: (host: string) => Promise<string[]>;
  /** Used by tests to allow private IPs (still requires explicit opt-in). */
  permitPrivateAddresses?: boolean;
}

export class UrlPolicyError extends Error {
  constructor(
    message: string,
    public readonly reason:
      | 'protocol'
      | 'host_not_allowed'
      | 'unresolvable'
      | 'private_address'
      | 'invalid_url',
  ) {
    super(message);
    this.name = 'UrlPolicyError';
  }
}

export class UrlPolicy {
  private readonly allowedHosts: Set<string>;
  private readonly resolver: (host: string) => Promise<string[]>;
  private readonly permitPrivate: boolean;

  constructor(options: UrlPolicyOptions = {}) {
    this.allowedHosts = new Set([
      ...DEFAULT_ALLOWED_HOSTS,
      ...(options.allowedHosts ?? []),
    ]);
    this.resolver =
      options.resolver ??
      (async (host) => {
        const recs = await dnsPromises.lookup(host, { all: true });
        return recs.map((r) => r.address);
      });
    this.permitPrivate = options.permitPrivateAddresses ?? false;
  }

  async assertSafe(rawUrl: string): Promise<URL> {
    let url: URL;
    try {
      url = new URL(rawUrl);
    } catch {
      throw new UrlPolicyError(`invalid url: ${rawUrl}`, 'invalid_url');
    }

    if (url.protocol !== 'https:') {
      throw new UrlPolicyError(
        `only https is permitted (got ${url.protocol}) for ${url.href}`,
        'protocol',
      );
    }

    const host = url.hostname.toLowerCase();
    if (!this.allowedHosts.has(host)) {
      throw new UrlPolicyError(
        `host not on allowlist: ${host}`,
        'host_not_allowed',
      );
    }

    const ipsToCheck = isIP(host) ? [host] : await this.resolver(host);
    if (ipsToCheck.length === 0) {
      throw new UrlPolicyError(`could not resolve host: ${host}`, 'unresolvable');
    }
    if (!this.permitPrivate) {
      for (const ip of ipsToCheck) {
        if (isDisallowedIp(ip)) {
          throw new UrlPolicyError(
            `host ${host} resolves to a disallowed address (${ip})`,
            'private_address',
          );
        }
      }
    }

    return url;
  }
}

/**
 * Returns true for IPv4/IPv6 addresses that must never be the target of a
 * downloader request: loopback, private (RFC 1918), link-local, multicast,
 * unspecified, and the AWS/GCP/Azure cloud-metadata endpoints.
 */
export function isDisallowedIp(address: string): boolean {
  const version = isIP(address);
  if (version === 4) return isDisallowedIpv4(address);
  if (version === 6) return isDisallowedIpv6(address);
  return true; // not a valid IP at all → treat as disallowed
}

function isDisallowedIpv4(address: string): boolean {
  const parts = address.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return true;
  const [a = 0, b = 0] = parts;
  // 0.0.0.0/8 unspecified, 10/8 private, 127/8 loopback,
  // 169.254/16 link-local (incl. 169.254.169.254 metadata),
  // 172.16/12 private, 192.0.0/24 IETF, 192.168/16 private,
  // 100.64/10 CGN, 224/4 multicast, 240/4 reserved, 255.255.255.255 broadcast.
  if (a === 0) return true;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 0) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a >= 224) return true;
  return false;
}

function isDisallowedIpv6(address: string): boolean {
  const lower = address.toLowerCase();
  if (lower === '::' || lower === '::1') return true;
  if (lower.startsWith('fe80:')) return true; // link-local
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // ULA
  if (lower.startsWith('ff')) return true; // multicast
  // IPv4-mapped: ::ffff:a.b.c.d
  const v4Mapped = lower.match(/^::ffff:([\d.]+)$/);
  if (v4Mapped?.[1]) return isDisallowedIpv4(v4Mapped[1]);
  return false;
}
