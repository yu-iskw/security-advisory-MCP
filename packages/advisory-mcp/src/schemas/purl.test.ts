import { describe, expect, it } from 'vitest';

import { parsePurl, PurlError } from './purl.js';

describe('parsePurl', () => {
  it('parses a minimal pkg:npm/foo@1.2.3', () => {
    const p = parsePurl('pkg:npm/lodash@4.17.21');
    expect(p.type).toBe('npm');
    expect(p.name).toBe('lodash');
    expect(p.version).toBe('4.17.21');
    expect(p.namespace).toBeUndefined();
  });

  it('parses an npm scope as namespace and lowercases', () => {
    const p = parsePurl('pkg:npm/%40Angular/Core@15.0.0');
    expect(p.type).toBe('npm');
    expect(p.namespace).toBe('@angular');
    expect(p.name).toBe('core');
  });

  it('normalizes pypi names per PEP 503', () => {
    const p = parsePurl('pkg:pypi/Django_REST.framework@3.14');
    expect(p.name).toBe('django-rest-framework');
  });

  it('parses qualifiers and subpath', () => {
    const p = parsePurl('pkg:maven/org.apache.commons/commons-text@1.10.0?type=jar#path/to/Class.java');
    expect(p.type).toBe('maven');
    expect(p.namespace).toBe('org.apache.commons');
    expect(p.name).toBe('commons-text');
    expect(p.version).toBe('1.10.0');
    expect(p.qualifiers).toMatchObject({ type: 'jar' });
    expect(p.subpath).toBe('path/to/Class.java');
  });

  it('parses a go path-style package', () => {
    const p = parsePurl('pkg:golang/github.com/owner/repo@v1.0.0');
    expect(p.type).toBe('golang');
    expect(p.namespace).toBe('github.com/owner');
    expect(p.name).toBe('repo');
  });

  it('rejects strings missing the pkg: prefix', () => {
    expect(() => parsePurl('npm/lodash@1.0.0')).toThrow(PurlError);
  });

  it('rejects strings missing the type or name', () => {
    expect(() => parsePurl('pkg:/lodash')).toThrow(PurlError);
    expect(() => parsePurl('pkg:npm/')).toThrow(PurlError);
  });

  it('treats @ inside a namespace as part of the name path', () => {
    const p = parsePurl('pkg:npm/lodash');
    expect(p.version).toBeUndefined();
    expect(p.name).toBe('lodash');
  });
});
