import type { Advisory } from '../schemas/advisory.js';
import type { Evidence } from '../schemas/evidence.js';
import type { RiskDriver, RiskProfileName, RiskResult } from '../schemas/risk.js';
import { PROFILE_WEIGHTS } from './profiles.js';

export function computeRiskScore(
  advisory: Advisory,
  evidence: Evidence[],
  profile: RiskProfileName,
): RiskResult {
  const weights = PROFILE_WEIGHTS[profile];
  const drivers: RiskDriver[] = [];
  const uncertainty: string[] = [];

  let score = 0;

  if (advisory.kev) {
    const w = 100 * weights.knownExploitation;
    score += w;
    drivers.push({ kind: 'known_exploited', source: 'cisa-kev', weight: w });
  }

  if (advisory.epss && advisory.epss.epss >= 0.5) {
    const w = advisory.epss.epss * 100 * weights.epss;
    score += w;
    drivers.push({
      kind: 'epss_high',
      probability: advisory.epss.epss,
      percentile: advisory.epss.percentile,
      weight: w,
    });
  }

  const topCvss = advisory.cvss.reduce((max, c) => (c.score > max ? c.score : max), 0);
  if (topCvss >= 7) {
    const w = (topCvss / 10) * 100 * weights.cvss;
    score += w;
    drivers.push({ kind: 'cvss_critical', score: topCvss, weight: w });
  }

  const hasFix = advisory.affected.some((p) => p.fixedVersions.length > 0);
  if (hasFix) {
    const w = 40 * weights.packageCertainty;
    score += w;
    drivers.push({
      kind: 'fix_available',
      versions: advisory.affected.flatMap((p) => p.fixedVersions),
      weight: w,
    });
  }

  if (advisory.type === 'malicious-package') {
    const w = 100 * weights.ecosystemExposure;
    score += w;
    drivers.push({ kind: 'malicious_package', source: 'ossf-malicious-packages', weight: w });
  }

  if (advisory.publishedAt) {
    const days = daysSince(advisory.publishedAt);
    if (days < 30) {
      const w = 30 * weights.recency;
      score += w;
      drivers.push({ kind: 'recently_published', days, weight: w });
    }
  }

  const avgConfidence =
    evidence.length > 0 ? evidence.reduce((s, e) => s + e.confidence, 0) / evidence.length : 0.5;
  score += avgConfidence * 100 * weights.evidenceConfidence;

  for (const conflict of advisory.sourceDisagreements) {
    const w = 10 * weights.evidenceConfidence;
    drivers.push({ kind: 'source_conflict', description: conflict.description, weight: w });
    uncertainty.push(conflict.description);
  }

  if (evidence.length === 0) {
    uncertainty.push('No normalized evidence rows found for this advisory.');
  }

  const clamped = Math.min(100, Math.round(score));
  const severity = scoreToSeverity(clamped);

  return {
    score: clamped,
    severity,
    profile,
    drivers,
    explanation: buildExplanation(clamped, severity, profile, drivers),
    uncertainty,
  };
}

function scoreToSeverity(score: number): RiskResult['severity'] {
  if (score >= 90) {
    return 'critical';
  }
  if (score >= 70) {
    return 'high';
  }
  if (score >= 40) {
    return 'medium';
  }
  if (score >= 10) {
    return 'low';
  }
  return 'none';
}

function buildExplanation(
  score: number,
  severity: RiskResult['severity'],
  profile: RiskProfileName,
  drivers: RiskDriver[],
): string {
  const top = drivers
    .slice()
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 3)
    .map((d) => d.kind)
    .join(', ');
  return `Policy score ${score}/100 (${severity}) for profile "${profile}". Top drivers: ${top || 'none'}.`;
}

function daysSince(iso: string): number {
  const then = new Date(iso).getTime();
  const now = Date.now();
  return Math.floor((now - then) / (1000 * 60 * 60 * 24));
}
