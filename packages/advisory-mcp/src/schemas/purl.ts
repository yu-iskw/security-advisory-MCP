import { z } from 'zod';

export const parsedPurlSchema = z.object({
  type: z.string(),
  namespace: z.string().optional(),
  name: z.string(),
  version: z.string().optional(),
  qualifiers: z.record(z.string()).optional(),
  subpath: z.string().optional(),
  canonical: z.string(),
});

export type ParsedPurl = z.infer<typeof parsedPurlSchema>;

const PURL_PATTERN =
  /^pkg:([a-z0-9.-]+)(?:\/([^@/]+))?(?:\/([^@/]+))?(?:@([^#?]+))?(?:\?([^#]+))?(?:#(.+))?$/i;

export function parsePurl(purl: string): ParsedPurl | null {
  const trimmed = purl.trim();
  if (!trimmed.startsWith('pkg:')) {
    return null;
  }
  const match = PURL_PATTERN.exec(trimmed);
  if (!match) {
    return null;
  }
  const [, type, nsOrName, maybeName, version, qualifiersRaw, subpath] = match;
  let namespace: string | undefined;
  let name: string;
  if (maybeName) {
    namespace = nsOrName;
    name = maybeName;
  } else {
    name = nsOrName;
  }
  const qualifiers: Record<string, string> = {};
  if (qualifiersRaw) {
    for (const part of qualifiersRaw.split('&')) {
      const [k, v] = part.split('=');
      if (k && v) {
        qualifiers[decodeURIComponent(k)] = decodeURIComponent(v);
      }
    }
  }
  return parsedPurlSchema.parse({
    type: type.toLowerCase(),
    namespace,
    name,
    version: version || undefined,
    qualifiers: Object.keys(qualifiers).length > 0 ? qualifiers : undefined,
    subpath: subpath || undefined,
    canonical: trimmed,
  });
}
