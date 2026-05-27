import type { RiskResult } from './score.js';

export function explainRiskMarkdown(advisoryId: string, result: RiskResult): string {
  const lines: string[] = [];
  lines.push(`# Risk explanation — ${advisoryId}`);
  lines.push(
    '',
    `**Score:** ${result.score}/100 (${result.severity})  `,
    `**Profile:** ${result.profile}`,
  );
  lines.push('', '## Drivers');
  if (result.drivers.length === 0) {
    lines.push('- (no positive drivers from current local evidence)');
  } else {
    for (const d of result.drivers) {
      lines.push(`- **${d.kind}** (+${d.contribution.toFixed(1)} of ${d.weight}) — ${d.detail}`);
    }
  }
  if (result.uncertainty.length > 0) {
    lines.push('', '## Uncertainty');
    for (const u of result.uncertainty) lines.push(`- ${u}`);
  }
  return lines.join('\n');
}
