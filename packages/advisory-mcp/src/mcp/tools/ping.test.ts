import { describe, expect, it } from 'vitest';

import { ping } from './ping.js';

describe('ping', () => {
  it('returns ok with the given name and version', () => {
    expect(ping('advisory-mcp', '1.2.3')).toEqual({
      ok: true,
      name: 'advisory-mcp',
      version: '1.2.3',
    });
  });
});
