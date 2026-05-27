import { sourceStatusInputSchema, type SourceStatusInput } from '../../schemas/source.js';
import { buildSourceStatusSummary } from '../../store/repositories/source-state-repository.js';

import type { AdvisoryStore } from '../../store/db.js';

export function parseSourceStatusInput(raw: unknown): SourceStatusInput {
  return sourceStatusInputSchema.parse(raw);
}

export function runSourceStatus(store: AdvisoryStore, input: SourceStatusInput) {
  const summary = buildSourceStatusSummary(store, input);
  return {
    structured: {
      sources: summary.sources,
      advisoryCount: summary.advisoryCount,
      evidenceCount: summary.evidenceCount,
    },
    markdownSummary: summary.markdownSummary,
  };
}
