import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { FileAuditor, NoopAuditor } from './audit.js';

describe('FileAuditor', () => {
  it('writes one JSON line per emit', () => {
    const dir = mkdtempSync(join(tmpdir(), 'advisory-mcp-audit-'));
    const path = join(dir, 'audit.log');
    const auditor = new FileAuditor({
      path,
      now: () => new Date('2026-05-27T00:00:00.000Z'),
    });
    auditor.emit('tool_called', { name: 'analyze_advisory', id: 'CVE-2024-3094' });
    auditor.emit('sync_completed', { source: 'cisa-kev', records: 3 });
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- test temp file
    const text = readFileSync(path, 'utf8');
    const lines = text.trim().split('\n');
    expect(lines).toHaveLength(2);
    const first = JSON.parse(lines[0] ?? '{}') as Record<string, unknown>;
    expect(first).toMatchObject({
      ts: '2026-05-27T00:00:00.000Z',
      event: 'tool_called',
      name: 'analyze_advisory',
      id: 'CVE-2024-3094',
    });
  });

  it('does not throw when the audit-log path is unusable', () => {
    const auditor = new FileAuditor({ path: '' });
    expect(() => {
      auditor.emit('e');
    }).not.toThrow();
  });
});

describe('NoopAuditor', () => {
  it('does nothing', () => {
    const auditor = new NoopAuditor();
    expect(() => {
      auditor.emit('e', { x: 1 });
    }).not.toThrow();
  });
});
