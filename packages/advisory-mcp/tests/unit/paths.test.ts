import { describe, expect, it } from 'vitest';

import { expandHome, resolvePaths } from '../../src/util/paths.js';

describe('paths', () => {
  it('resolvePaths returns defaults', () => {
    const paths = resolvePaths();
    expect(paths.databasePath).toContain('.advisory-mcp');
    expect(paths.cachePath).toContain('.advisory-mcp');
  });

  it('expandHome expands tilde paths', () => {
    const expanded = expandHome('~/advisory-mcp-test');
    expect(expanded).not.toBe('~/advisory-mcp-test');
    expect(expanded.endsWith('advisory-mcp-test')).toBe(true);
  });
});
