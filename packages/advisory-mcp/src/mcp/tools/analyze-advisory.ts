import { z } from 'zod';

import { quoteUntrusted, sanitizeText } from '../../security/content-sanitizer.js';
import { LIMITS } from '../../security/limits.js';

import type { AdvisoryStore } from '../../store/store.js';

export const AnalyzeAdvisoryInputSchema = z.object({
  id: z.string().min(1).max(128),
  includeEvidence: z.boolean().default(true),
});

type AnalyzeAdvisoryInput = z.infer<typeof AnalyzeAdvisoryInputSchema>;

interface EvidenceSummary {
  id: string;
  source: string;
  type: string;
  confidence: number;
  trustTier: string;
  summary: string;
  fetchedAt: string;
  observedAt: string | null;
}

interface KnownExploitedSummary {
  listed: boolean;
  source?: string;
  dateAdded?: string;
}

interface AnalyzeAdvisoryResult {
  found: boolean;
  query: string;
  advisory?: {
    id: string;
    canonicalId: string;
    type: string;
    aliases: string[];
    title: string;
    description: string;
    publishedAt: string | null;
    modifiedAt: string | null;
  };
  knownExploited?: KnownExploitedSummary;
  evidence?: EvidenceSummary[];
  freshness?: {
    sources: { source: string; status: string; lastSuccessAt: string | null }[];
  };
  markdown: string;
}

export function analyzeAdvisory(
  store: AdvisoryStore,
  input: AnalyzeAdvisoryInput,
): AnalyzeAdvisoryResult {
  const advisory =
    store.advisories.findById(input.id) ?? store.advisories.findByAlias(input.id);

  if (!advisory) {
    return {
      found: false,
      query: input.id,
      markdown: `No advisory found locally for **${sanitizeText(input.id, { maxChars: 128 })}**.`,
    };
  }

  const aliases = store.advisories.aliasesFor(advisory.id);
  const evidence = store.evidence.findByAdvisoryId(advisory.id);

  const kevRecord = evidence.find((e) => e.source === 'cisa-kev');
  const knownExploited: KnownExploitedSummary | undefined = kevRecord
    ? {
        listed: true,
        source: 'cisa-kev',
        dateAdded: parseKevDateAdded(kevRecord.normalizedJson) ?? undefined,
      }
    : { listed: false };

  const includeEvidence = input.includeEvidence;
  const evidenceSummaries: EvidenceSummary[] | undefined = includeEvidence
    ? evidence.map((e) => ({
        id: e.id,
        source: e.source,
        type: e.type,
        confidence: e.confidence,
        trustTier: e.trustTier,
        summary: sanitizeText(e.summary, { maxChars: LIMITS.maxClientTextChars }),
        fetchedAt: e.fetchedAt,
        observedAt: e.observedAt,
      }))
    : undefined;

  const sourceRows = store.sourceState
    .listAll()
    .map((s) => ({
      source: s.source,
      status: s.status,
      lastSuccessAt: s.lastSuccessAt,
    }));

  const sanitizedTitle = sanitizeText(advisory.title ?? advisory.id, { maxChars: 256 });
  const sanitizedDescription = sanitizeText(advisory.description ?? '');

  const markdown = renderMarkdown({
    id: advisory.id,
    title: sanitizedTitle,
    description: sanitizedDescription,
    aliases,
    knownExploited,
    evidence: evidenceSummaries,
  });

  return {
    found: true,
    query: input.id,
    advisory: {
      id: advisory.id,
      canonicalId: advisory.canonicalId,
      type: advisory.type,
      aliases,
      title: sanitizedTitle,
      description: sanitizedDescription,
      publishedAt: advisory.publishedAt,
      modifiedAt: advisory.modifiedAt,
    },
    knownExploited,
    evidence: evidenceSummaries,
    freshness: { sources: sourceRows },
    markdown,
  };
}

function parseKevDateAdded(normalizedJson: string): string | null {
  try {
    const obj = JSON.parse(normalizedJson) as { dateAdded?: unknown };
    return typeof obj.dateAdded === 'string' ? obj.dateAdded : null;
  } catch {
    return null;
  }
}

function renderMarkdown(args: {
  id: string;
  title: string;
  description: string;
  aliases: string[];
  knownExploited?: KnownExploitedSummary;
  evidence?: EvidenceSummary[];
}): string {
  const lines: string[] = [];
  lines.push(`# ${args.id} — ${args.title}`);
  if (args.aliases.length > 0) {
    lines.push('', `**Aliases:** ${args.aliases.join(', ')}`);
  }
  if (args.knownExploited) {
    if (args.knownExploited.listed) {
      const when = args.knownExploited.dateAdded
        ? ` (added ${args.knownExploited.dateAdded})`
        : '';
      lines.push('', `**Known exploited:** Yes — listed in CISA KEV${when}.`);
    } else {
      lines.push('', `**Known exploited:** Not listed in CISA KEV.`);
    }
  }
  if (args.evidence && args.evidence.length > 0) {
    lines.push('', '**Evidence:**');
    for (const e of args.evidence) {
      lines.push(
        `- ${e.source} (${e.type}, Tier ${e.trustTier}, conf=${e.confidence.toFixed(2)})`,
      );
    }
  }
  if (args.description.length > 0) {
    lines.push('', quoteUntrusted('advisory description', args.description));
  }
  return lines.join('\n');
}
