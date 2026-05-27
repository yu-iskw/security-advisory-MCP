/**
 * Package URL (PURL) parser per the spec at
 * https://github.com/package-url/purl-spec.
 *
 * Form: pkg:type/namespace/name@version?qualifiers#subpath
 *
 * The result is normalized for the most common ecosystems we support
 * (npm lowercases name; pypi normalizes name; go uses path-style; etc.).
 * Unsupported fields (qualifiers, subpath) are parsed but kept as-is.
 */

interface ParsedPurl {
  type: string;
  namespace?: string;
  name: string;
  version?: string;
  qualifiers: Record<string, string>;
  subpath?: string;
}

export class PurlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PurlError';
  }
}

export function parsePurl(input: string): ParsedPurl {
  if (!input.startsWith('pkg:')) {
    throw new PurlError(`PURL must start with "pkg:" — got: ${truncate(input)}`);
  }
  let s = input.slice(4);
  // strip optional leading slashes per spec
  while (s.startsWith('/')) s = s.slice(1);

  let subpath: string | undefined;
  const hashIdx = s.indexOf('#');
  if (hashIdx >= 0) {
    subpath = decodeOrEmpty(s.slice(hashIdx + 1));
    s = s.slice(0, hashIdx);
  }

  const qualifiers: Record<string, string> = {};
  const qIdx = s.indexOf('?');
  if (qIdx >= 0) {
    const qs = s.slice(qIdx + 1);
    s = s.slice(0, qIdx);
    for (const pair of qs.split('&')) {
      const eq = pair.indexOf('=');
      if (eq <= 0) continue;
      const key = decodeOrEmpty(pair.slice(0, eq)).toLowerCase();
      const value = decodeOrEmpty(pair.slice(eq + 1));
      // key came from decodeURIComponent on a user-supplied PURL; we only
      // store the value, never use it as a code path or fs key.
      // eslint-disable-next-line security/detect-object-injection
      if (key !== '' && value !== '') qualifiers[key] = value;
    }
  }

  let version: string | undefined;
  const atIdx = s.lastIndexOf('@');
  // Only treat '@' as a version separator if it appears after the path part
  const slashIdx = s.indexOf('/');
  if (atIdx > slashIdx) {
    version = decodeOrEmpty(s.slice(atIdx + 1));
    s = s.slice(0, atIdx);
  }

  const slash = s.indexOf('/');
  if (slash < 0) {
    throw new PurlError(`PURL missing type or name: ${truncate(input)}`);
  }
  const type = s.slice(0, slash).toLowerCase();
  if (type === '') throw new PurlError(`PURL missing type: ${truncate(input)}`);

  const rest = s.slice(slash + 1);
  const lastSlash = rest.lastIndexOf('/');
  let namespace: string | undefined;
  let name: string;
  if (lastSlash >= 0) {
    namespace = decodeOrEmpty(rest.slice(0, lastSlash));
    name = decodeOrEmpty(rest.slice(lastSlash + 1));
  } else {
    name = decodeOrEmpty(rest);
  }

  if (name === '') throw new PurlError(`PURL missing name: ${truncate(input)}`);

  return normalizePurl({ type, namespace, name, version, qualifiers, subpath });
}

function normalizePurl(p: ParsedPurl): ParsedPurl {
  switch (p.type) {
    case 'npm':
      // npm names are lowercase, namespace is the @scope (kept without leading @)
      return { ...p, name: p.name.toLowerCase(), namespace: p.namespace?.toLowerCase() };
    case 'pypi':
      // PEP 503 normalization: lowercase, runs of [-_.] → '-'
      return { ...p, name: p.name.toLowerCase().replace(/[-_.]+/g, '-') };
    case 'maven':
    case 'gem':
    case 'cargo':
    case 'golang':
    case 'composer':
    case 'nuget':
    case 'rpm':
    case 'deb':
    case 'apk':
      return p;
    default:
      return p;
  }
}

function decodeOrEmpty(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

function truncate(s: string): string {
  return s.length > 64 ? `${s.slice(0, 60)}…` : s;
}
