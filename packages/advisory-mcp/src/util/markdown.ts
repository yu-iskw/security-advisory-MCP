import { sanitizeAdvisoryText } from '../security/content-sanitizer.js';

export function escapeMarkdownTableCell(value: string): string {
  return sanitizeAdvisoryText(value).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}
