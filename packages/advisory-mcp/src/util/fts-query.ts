/**
 * Build a safe FTS5 MATCH expression from user text (phrase-quoted tokens).
 */
export function buildFtsMatchQuery(query: string): string {
  const tokens = query
    .trim()
    .split(/\s+/)
    .map((token) => token.replace(/[^\w\-@.]+/g, ''))
    .filter((token) => token.length > 0);

  if (tokens.length === 0) {
    return '""';
  }

  return tokens.map((token) => `"${token.replaceAll('"', '""')}"`).join(' ');
}
