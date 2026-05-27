import { describe, expect, it } from 'vitest';

import { err, isErr, isOk, ok, unwrap } from './result.js';

describe('result', () => {
  it('ok wraps a value', () => {
    const r = ok(42);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.value).toBe(42);
  });

  it('err wraps an error', () => {
    const r = err(new Error('boom'));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.message).toBe('boom');
  });

  it('isOk and isErr narrow correctly', () => {
    const r1 = ok('x');
    expect(isOk(r1)).toBe(true);
    expect(isErr(r1)).toBe(false);
    const r2 = err('nope');
    expect(isOk(r2)).toBe(false);
    expect(isErr(r2)).toBe(true);
  });

  it('unwrap returns the value on Ok', () => {
    expect(unwrap(ok(7))).toBe(7);
  });

  it('unwrap throws the wrapped Error on Err', () => {
    expect(() => unwrap(err(new Error('bad')))).toThrow('bad');
  });

  it('unwrap throws a wrapping Error when Err is not an Error', () => {
    expect(() => unwrap(err('plain'))).toThrow(/plain/);
  });
});
