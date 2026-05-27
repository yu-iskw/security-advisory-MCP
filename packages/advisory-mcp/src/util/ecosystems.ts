/**
 * Canonical ecosystem names + aliases. PURL types, OSV ecosystem strings, and
 * GHSA `ecosystem` values all map onto these so the merger and risk engine see
 * one identifier per package universe.
 *
 * Add new entries here when a new source adapter lands.
 */

const CANONICAL: ReadonlyArray<string> = [
  'npm',
  'pypi',
  'maven',
  'gem',
  'cargo',
  'go',
  'composer',
  'nuget',
  'rpm',
  'deb',
  'alpine',
];

const ALIASES: ReadonlyMap<string, string> = new Map<string, string>([
  ['npm', 'npm'],
  ['npmjs', 'npm'],
  ['pypi', 'pypi'],
  ['python', 'pypi'],
  ['maven', 'maven'],
  ['rubygems', 'gem'],
  ['gem', 'gem'],
  ['ruby', 'gem'],
  ['cargo', 'cargo'],
  ['crates.io', 'cargo'],
  ['rust', 'cargo'],
  ['go', 'go'],
  ['golang', 'go'],
  ['packagist', 'composer'],
  ['composer', 'composer'],
  ['php', 'composer'],
  ['nuget', 'nuget'],
  ['.net', 'nuget'],
  ['rpm', 'rpm'],
  ['deb', 'deb'],
  ['debian', 'deb'],
  ['ubuntu', 'deb'],
  ['alpine', 'alpine'],
]);

export function canonicalEcosystem(input: string): string | undefined {
  const lower = input.trim().toLowerCase();
  return ALIASES.get(lower);
}

export function isKnownEcosystem(input: string): boolean {
  return CANONICAL.includes(input);
}
