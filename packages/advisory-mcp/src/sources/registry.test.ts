import { describe, expect, it } from 'vitest';

import { SourceRegistry } from './registry.js';

import type { SourceAdapter, SyncPreset } from './source.js';

function makeStub(id: string, defaultPreset: SyncPreset): SourceAdapter {
  return {
    id,
    displayName: id,
    trustTier: 'A',
    defaultPreset,
    requiresApiKey: false,
    checkForUpdates: () => Promise.resolve({ changed: false }),
    fetch: () => Promise.resolve({ artifacts: [] }),
    parse: function* () {
      yield* [];
    } as unknown as SourceAdapter['parse'],
    normalize: () => Promise.resolve([]),
  };
}

describe('SourceRegistry', () => {
  it('registers adapters and looks them up by id', () => {
    const r = new SourceRegistry();
    const a = makeStub('cisa-kev', 'core');
    r.register(a);
    expect(r.get('cisa-kev')).toBe(a);
    expect(r.get('missing')).toBeUndefined();
  });

  it('rejects duplicate registration', () => {
    const r = new SourceRegistry();
    r.register(makeStub('cisa-kev', 'core'));
    expect(() => r.register(makeStub('cisa-kev', 'core'))).toThrow(/already registered/);
  });

  it('resolvePreset filters by defaultPreset', () => {
    const r = new SourceRegistry();
    r.register(makeStub('cisa-kev', 'core'));
    r.register(makeStub('first-epss', 'core'));
    r.register(makeStub('osv', 'packages'));
    r.register(makeStub('exploit-db', 'research'));

    expect(r.resolvePreset('core').map((a) => a.id)).toEqual(['cisa-kev', 'first-epss']);
    expect(r.resolvePreset('packages').map((a) => a.id)).toEqual(['osv']);
    expect(r.resolvePreset('research').map((a) => a.id)).toEqual(['exploit-db']);
  });

  it('all expands to every non-research preset', () => {
    const r = new SourceRegistry();
    r.register(makeStub('cisa-kev', 'core'));
    r.register(makeStub('osv', 'packages'));
    r.register(makeStub('mitre-cwe', 'context'));
    r.register(makeStub('exploit-db', 'research'));

    const ids = r.resolvePreset('all').map((a) => a.id);
    expect(ids).toEqual(['cisa-kev', 'mitre-cwe', 'osv']);
    expect(ids).not.toContain('exploit-db');
  });
});
