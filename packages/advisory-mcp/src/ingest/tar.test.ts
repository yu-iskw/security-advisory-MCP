import { describe, expect, it } from 'vitest';

import { buildTar } from '../../tests/fixtures/tar-builder.js';

import { readTar } from './tar.js';

const ENC = new TextEncoder();

describe('readTar', () => {
  it('reads a single-entry tar', () => {
    const tar = buildTar([{ path: 'hello.txt', content: ENC.encode('hi') }]);
    const entries = readTar(tar);
    expect(entries).toHaveLength(1);
    expect(entries[0]?.path).toBe('hello.txt');
    expect(new TextDecoder().decode(entries[0]?.content)).toBe('hi');
  });

  it('reads multiple entries with arbitrary sizes', () => {
    const tar = buildTar([
      { path: 'a.json', content: ENC.encode('{"a":1}') },
      { path: 'subdir/b.json', content: ENC.encode('x'.repeat(700)) },
    ]);
    const entries = readTar(tar);
    expect(entries.map((e) => e.path)).toEqual(['a.json', 'subdir/b.json']);
    expect(entries[1]?.content.length).toBe(700);
  });

  it('skips non-existent entries when the archive ends', () => {
    const tar = buildTar([{ path: 'one.txt', content: ENC.encode('only') }]);
    const entries = readTar(tar);
    expect(entries).toHaveLength(1);
  });

  it('rejects path traversal entries', () => {
    const tar = buildTar([
      { path: '../etc/passwd', content: ENC.encode('boom') },
    ]);
    expect(() => readTar(tar)).toThrow(/path traversal/);
  });

  it('enforces the decompressed-size cap', () => {
    const tar = buildTar([{ path: 'big.bin', content: ENC.encode('x'.repeat(2000)) }]);
    expect(() => readTar(tar, { maxBytes: 100 })).toThrow(/exceed limit/);
  });

  it('stops cleanly at the trailing zero blocks', () => {
    const tar = buildTar([{ path: 'one.txt', content: ENC.encode('only') }]);
    // Append junk after the trailing two zero blocks; readTar should stop.
    const junk = new Uint8Array([1, 2, 3, 4, 5]);
    const combined = new Uint8Array(tar.length + junk.length);
    combined.set(tar);
    combined.set(junk, tar.length);
    expect(() => readTar(combined)).not.toThrow();
    expect(readTar(combined)).toHaveLength(1);
  });
});
