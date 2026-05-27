import { describe, expect, it } from 'vitest';

import { ageMs, isIsoString, nowIso, toIso } from './time.js';

describe('time', () => {
  it('nowIso returns a valid ISO string', () => {
    expect(isIsoString(nowIso())).toBe(true);
  });

  it('toIso formats a Date', () => {
    expect(toIso(new Date('2026-05-27T00:00:00Z'))).toBe('2026-05-27T00:00:00.000Z');
  });

  it('isIsoString accepts Z and offset', () => {
    expect(isIsoString('2026-05-27T00:00:00Z')).toBe(true);
    expect(isIsoString('2026-05-27T00:00:00.123Z')).toBe(true);
    expect(isIsoString('2026-05-27T00:00:00+00:00')).toBe(true);
  });

  it('isIsoString rejects invalid strings', () => {
    expect(isIsoString('not a date')).toBe(false);
    expect(isIsoString('2026-13-45T99:99:99Z')).toBe(false);
    expect(isIsoString(42)).toBe(false);
  });

  it('ageMs returns the positive elapsed milliseconds', () => {
    const ref = new Date('2026-01-02T00:00:00Z');
    expect(ageMs('2026-01-01T00:00:00Z', ref)).toBe(86_400_000);
  });

  it('ageMs throws on invalid input', () => {
    expect(() => ageMs('garbage')).toThrow(/invalid ISO timestamp/);
  });
});
