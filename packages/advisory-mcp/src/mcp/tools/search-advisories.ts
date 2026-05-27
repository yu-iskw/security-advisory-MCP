import { z } from 'zod';

import { sanitizeText } from '../../security/content-sanitizer.js';

import type { AdvisoryStore } from '../../store/store.js';

export const SearchAdvisoriesInputSchema = z.object({
  query: z.string().min(1).max(200),
  severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  knownExploited: z.boolean().optional(),
  hasFix: z.boolean().optional(),
  limit: z.number().int().min(1).max(50).default(10),
});

type SearchAdvisoriesInput = z.infer<typeof SearchAdvisoriesInputSchema>;

interface SearchAdvisoriesHit {
  id: string;
  title: string;
  knownExploited: boolean;
  aliases: string[];
}

interface SearchAdvisoriesResult {
  query: string;
  hits: SearchAdvisoriesHit[];
  markdown: string;
}

export function searchAdvisories(
  store: AdvisoryStore,
  input: SearchAdvisoriesInput,
): SearchAdvisoriesResult {
  const rawHits = store.search.search({
    query: input.query,
    severity: input.severity,
    hasFix: input.hasFix,
    knownExploited: input.knownExploited,
    limit: input.limit,
  });

  const hits: SearchAdvisoriesHit[] = rawHits
    .map((hit) => {
      const advisory = store.advisories.findById(hit.id);
      if (!advisory) return undefined;
      const aliases = store.advisories.aliasesFor(advisory.id);
      const evidence = store.evidence.findByAdvisoryId(advisory.id);
      const knownExploited = evidence.some(
        (e) => e.source === 'cisa-kev' && e.type === 'known_exploited',
      );
      return {
        id: advisory.id,
        title: sanitizeText(advisory.title ?? advisory.id, { maxChars: 200 }),
        knownExploited,
        aliases,
      };
    })
    .filter((h): h is SearchAdvisoriesHit => h !== undefined);

  return {
    query: input.query,
    hits,
    markdown: renderMarkdown(input.query, hits),
  };
}

function renderMarkdown(query: string, hits: SearchAdvisoriesHit[]): string {
  if (hits.length === 0) {
    return `No advisories matched **${sanitizeText(query, { maxChars: 200 })}** in the local index.`;
  }
  const lines: string[] = [];
  lines.push(`# Search results — ${hits.length} hit(s)`);
  for (const h of hits) {
    const flag = h.knownExploited ? ' :rotating_light: KEV' : '';
    lines.push(`- **${h.id}** — ${h.title}${flag}`);
  }
  return lines.join('\n');
}
