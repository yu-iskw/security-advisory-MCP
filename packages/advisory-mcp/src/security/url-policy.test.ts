import { describe, expect, it } from 'vitest';

import { isDisallowedIp, UrlPolicy, UrlPolicyError } from './url-policy.js';

describe('isDisallowedIp', () => {
  it('flags loopback and unspecified', () => {
    expect(isDisallowedIp('127.0.0.1')).toBe(true);
    expect(isDisallowedIp('0.0.0.0')).toBe(true);
    expect(isDisallowedIp('::')).toBe(true);
    expect(isDisallowedIp('::1')).toBe(true);
  });

  it('flags private ranges', () => {
    expect(isDisallowedIp('10.0.0.1')).toBe(true);
    expect(isDisallowedIp('192.168.1.1')).toBe(true);
    expect(isDisallowedIp('172.16.0.1')).toBe(true);
    expect(isDisallowedIp('172.31.255.255')).toBe(true);
    expect(isDisallowedIp('100.64.0.1')).toBe(true);
  });

  it('flags link-local incl. AWS metadata endpoint', () => {
    expect(isDisallowedIp('169.254.169.254')).toBe(true);
    expect(isDisallowedIp('fe80::1')).toBe(true);
  });

  it('flags multicast and reserved', () => {
    expect(isDisallowedIp('224.0.0.1')).toBe(true);
    expect(isDisallowedIp('240.0.0.1')).toBe(true);
    expect(isDisallowedIp('ff02::1')).toBe(true);
  });

  it('flags link-local across the full fe80::/10 range, not just fe80:', () => {
    expect(isDisallowedIp('fe80::1')).toBe(true);
    expect(isDisallowedIp('fe85::1')).toBe(true);
    expect(isDisallowedIp('fe9a:0:0:0:0:0:0:1')).toBe(true);
    expect(isDisallowedIp('feab::ffff')).toBe(true);
    // fec0:: is reserved (deprecated site-local), not link-local; should
    // not match the link-local regex.
    expect(isDisallowedIp('fec0::1')).toBe(false);
  });

  it('flags IPv4-mapped IPv6 in hex form (SSRF bypass guard)', () => {
    // ::ffff:7f00:0001 == 127.0.0.1
    expect(isDisallowedIp('::ffff:7f00:0001')).toBe(true);
    // ::ffff:a9fe:a9fe == 169.254.169.254 (AWS metadata)
    expect(isDisallowedIp('::ffff:a9fe:a9fe')).toBe(true);
    // ::ffff:0a00:0001 == 10.0.0.1
    expect(isDisallowedIp('::ffff:a00:1')).toBe(true);
  });

  it('flags 6to4-wrapped private IPv4 addresses', () => {
    // 2002:7f00:0001:: == 6to4 wrapping 127.0.0.1
    expect(isDisallowedIp('2002:7f00:1::')).toBe(true);
    // 2002:a9fe:a9fe:: == 6to4 wrapping 169.254.169.254
    expect(isDisallowedIp('2002:a9fe:a9fe::')).toBe(true);
  });

  it('flags fully-expanded loopback / unspecified', () => {
    expect(isDisallowedIp('0:0:0:0:0:0:0:0')).toBe(true);
    expect(isDisallowedIp('0:0:0:0:0:0:0:1')).toBe(true);
  });

  it('flags IPv6 ULA and v4-mapped private', () => {
    expect(isDisallowedIp('fc00::1')).toBe(true);
    expect(isDisallowedIp('fd12::abcd')).toBe(true);
    expect(isDisallowedIp('::ffff:192.168.1.1')).toBe(true);
  });

  it('allows public addresses', () => {
    expect(isDisallowedIp('1.1.1.1')).toBe(false);
    expect(isDisallowedIp('8.8.8.8')).toBe(false);
    expect(isDisallowedIp('2606:4700:4700::1111')).toBe(false);
  });

  it('treats invalid strings as disallowed', () => {
    expect(isDisallowedIp('not-an-ip')).toBe(true);
  });
});

describe('UrlPolicy.assertSafe', () => {
  const allowedHosts = ['www.cisa.gov'];

  it('accepts an allowed https host with a public IP', async () => {
    const policy = new UrlPolicy({
      allowedHosts,
      resolver: () => Promise.resolve(['1.1.1.1']),
    });
    const url = await policy.assertSafe('https://www.cisa.gov/path');
    expect(url.hostname).toBe('www.cisa.gov');
  });

  it('rejects non-https', async () => {
    const policy = new UrlPolicy({
      allowedHosts,
      resolver: () => Promise.resolve(['1.1.1.1']),
    });
    await expect(policy.assertSafe('http://www.cisa.gov/x')).rejects.toMatchObject({
      reason: 'protocol',
    });
  });

  it('rejects hosts not on the allowlist', async () => {
    const policy = new UrlPolicy({
      allowedHosts,
      resolver: () => Promise.resolve(['1.1.1.1']),
    });
    await expect(policy.assertSafe('https://evil.example.com/x')).rejects.toMatchObject({
      reason: 'host_not_allowed',
    });
  });

  it('rejects hosts that resolve to disallowed addresses (DNS rebinding)', async () => {
    const policy = new UrlPolicy({
      allowedHosts,
      resolver: () => Promise.resolve(['169.254.169.254']),
    });
    await expect(policy.assertSafe('https://www.cisa.gov/x')).rejects.toMatchObject({
      reason: 'private_address',
    });
  });

  it('rejects malformed URLs', async () => {
    const policy = new UrlPolicy({ allowedHosts, resolver: () => Promise.resolve([]) });
    await expect(policy.assertSafe('not-a-url')).rejects.toBeInstanceOf(UrlPolicyError);
  });

  it('rejects hosts that fail DNS resolution', async () => {
    const policy = new UrlPolicy({
      allowedHosts,
      resolver: () => Promise.resolve([]),
    });
    await expect(policy.assertSafe('https://www.cisa.gov/x')).rejects.toMatchObject({
      reason: 'unresolvable',
    });
  });
});
