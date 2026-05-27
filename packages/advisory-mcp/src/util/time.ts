export function nowIso(): string {
  return new Date().toISOString();
}

export function toIso(date: Date): string {
  return date.toISOString();
}

// All sub-patterns are bounded fixed-length groups; no catastrophic backtracking.
// eslint-disable-next-line security/detect-unsafe-regex
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/;

export function isIsoString(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  if (!ISO_RE.test(value)) return false;
  const parsed = Date.parse(value);
  return !Number.isNaN(parsed);
}

export function ageMs(timestamp: string, reference: Date = new Date()): number {
  const t = Date.parse(timestamp);
  if (Number.isNaN(t)) throw new Error(`invalid ISO timestamp: ${timestamp}`);
  return reference.getTime() - t;
}
