import { createHash } from 'node:crypto';

export function sha256Hex(data: Uint8Array | string): string {
  return createHash('sha256').update(data).digest('hex');
}

export class HashMismatchError extends Error {
  constructor(
    public readonly expected: string,
    public readonly actual: string,
  ) {
    super(`sha256 mismatch: expected ${expected}, got ${actual}`);
    this.name = 'HashMismatchError';
  }
}

export function assertSha256(data: Uint8Array, expected: string): void {
  const actual = sha256Hex(data);
  if (actual.toLowerCase() !== expected.toLowerCase()) {
    throw new HashMismatchError(expected, actual);
  }
}
