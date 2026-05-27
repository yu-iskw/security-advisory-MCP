import { describe, expect, it } from 'vitest';

import { buildFtsMatchQuery } from '../../src/util/fts-query.js';

describe('buildFtsMatchQuery', () => {
  it('phrase-quotes tokens and strips unsafe characters', () => {
    expect(buildFtsMatchQuery('log4j OR drop')).toBe('"log4j" "OR" "drop"');
    expect(buildFtsMatchQuery('  ')).toBe('""');
  });

  it('escapes embedded double quotes', () => {
    expect(buildFtsMatchQuery('foo"bar')).toBe('"foobar"');
  });
});
