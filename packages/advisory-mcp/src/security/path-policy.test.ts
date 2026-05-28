import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { PathPolicy, PathPolicyError } from './path-policy.js';

describe('PathPolicy', () => {
  let root: string;
  let inside: string;

  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), 'advisory-mcp-path-'));
    inside = join(root, 'a.json');
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- test temp file
    writeFileSync(inside, '{}');
  });

  afterAll(() => {
    // Leave the tmpdir; tmp cleanup is OS-managed.
  });

  it('allows a path inside the root', () => {
    const policy = new PathPolicy([root]);
    expect(policy.assertReadable(inside)).toBe(inside);
  });

  it('rejects a path outside every root', () => {
    const policy = new PathPolicy([root]);
    expect(() => policy.assertReadable('/etc/passwd')).toThrow(PathPolicyError);
  });

  it('rejects when no roots are configured', () => {
    const policy = new PathPolicy([]);
    try {
      policy.assertReadable(inside);
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(PathPolicyError);
      expect((err as PathPolicyError).reason).toBe('no_roots');
    }
  });

  it('rejects parent-traversal even via relative paths', () => {
    const policy = new PathPolicy([root]);
    expect(() => policy.assertReadable(join(root, '..', 'somewhere-else'))).toThrow(PathPolicyError);
  });
});
