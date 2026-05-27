import { describe, expect, it } from 'vitest';

import { assertSha256, HashMismatchError, sha256Hex } from './verifier.js';

describe('sha256Hex', () => {
  it('hashes a known string to the expected digest', () => {
    expect(sha256Hex('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  it('hashes bytes equivalently to the string', () => {
    expect(sha256Hex(new TextEncoder().encode('abc'))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });
});

describe('assertSha256', () => {
  it('passes when hashes match (case-insensitive)', () => {
    const data = new TextEncoder().encode('abc');
    expect(() =>
      assertSha256(data, 'BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD'),
    ).not.toThrow();
  });

  it('throws HashMismatchError with both digests on failure', () => {
    const data = new TextEncoder().encode('abc');
    try {
      assertSha256(data, '0'.repeat(64));
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(HashMismatchError);
      const hashErr = err as HashMismatchError;
      expect(hashErr.expected).toBe('0'.repeat(64));
      expect(hashErr.actual).toMatch(/^ba7816bf/);
    }
  });
});
