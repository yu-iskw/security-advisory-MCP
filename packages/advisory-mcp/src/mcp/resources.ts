import { getProfileWeights, RISK_PROFILE_NAMES } from '../risk/profiles.js';
import { computeRiskScore } from '../risk/score.js';
import { advisorySchema } from '../schemas/advisory.js';
import { evidenceSchema } from '../schemas/evidence.js';
import { findAdvisoryById } from '../store/repositories/advisory-repository.js';
import { listEvidenceForAdvisory } from '../store/repositories/evidence-repository.js';
import {
  buildSourceStatusSummary,
  sourceStatusPayload,
} from '../store/repositories/source-state-repository.js';

import type { RiskProfileName } from '../schemas/risk.js';
import type { AdvisoryStore } from '../store/db.js';

export const RESOURCE_URIS = {
  sourceStatus: 'advisory://source/status',
  riskProfile: (name: RiskProfileName) => `advisory://risk-profile/${name}`,
  advisoryById: (id: string) => `advisory://id/${encodeURIComponent(id)}`,
  advisorySchema: 'advisory://schema/advisory',
  evidenceSchema: 'advisory://schema/evidence',
} as const;

export { RISK_PROFILE_NAMES };

export function readSourceStatusResource(store: AdvisoryStore) {
  const summary = buildSourceStatusSummary(store, { includeDisabled: true });
  return jsonResource(RESOURCE_URIS.sourceStatus, sourceStatusPayload(summary));
}

export function readRiskProfileResource(name: RiskProfileName) {
  const profile = getProfileWeights(name);
  return jsonResource(RESOURCE_URIS.riskProfile(name), { name, weights: profile });
}

export function readAdvisoryResource(store: AdvisoryStore, id: string) {
  const advisory = findAdvisoryById(store, id);
  if (!advisory) {
    throw new Error(`Advisory not found: ${id}`);
  }
  const evidence = listEvidenceForAdvisory(store, advisory.id);
  const risk = computeRiskScore(advisory, evidence, 'default');
  return jsonResource(RESOURCE_URIS.advisoryById(advisory.canonicalId), {
    id: advisory.canonicalId,
    aliases: advisory.aliases,
    title: advisory.title,
    risk: { score: risk.score, severity: risk.severity, profile: 'default' },
    evidence: evidence.map((e) => ({
      source: e.source,
      confidence: e.confidence,
      fetchedAt: e.fetchedAt,
    })),
  });
}

export function readAdvisorySchemaResource() {
  return jsonResource(RESOURCE_URIS.advisorySchema, { schema: advisorySchema.shape });
}

export function readEvidenceSchemaResource() {
  return jsonResource(RESOURCE_URIS.evidenceSchema, { schema: evidenceSchema.shape });
}

function jsonResource(uri: string, payload: unknown) {
  return {
    uri,
    mimeType: 'application/json',
    text: JSON.stringify(payload, null, 2),
  };
}

export function resourceContents(resource: { uri: string; mimeType: string; text: string }) {
  return {
    contents: [
      {
        uri: resource.uri,
        mimeType: resource.mimeType,
        text: resource.text,
      },
    ],
  };
}
