import { describe, expect, it } from 'vitest';

import { createLogger } from './logger.js';

function captureStream(): { write: (chunk: string) => void; lines: string[] } {
  const lines: string[] = [];
  return {
    write: (chunk: string) => {
      lines.push(chunk.trimEnd());
    },
    lines,
  };
}

describe('logger', () => {
  it('emits a JSON line per event with the configured fields', () => {
    const stream = captureStream();
    const logger = createLogger({
      level: 'debug',
      stream,
      now: () => new Date('2026-01-01T00:00:00.000Z'),
    });

    logger.info('sync_started', { source: 'cisa-kev' });

    expect(stream.lines).toHaveLength(1);
    const parsed = JSON.parse(stream.lines[0] ?? '{}') as Record<string, unknown>;
    expect(parsed).toMatchObject({
      ts: '2026-01-01T00:00:00.000Z',
      level: 'info',
      event: 'sync_started',
      source: 'cisa-kev',
    });
  });

  it('filters records below the configured level', () => {
    const stream = captureStream();
    const logger = createLogger({ level: 'warn', stream });
    logger.debug('debug_event');
    logger.info('info_event');
    logger.warn('warn_event');
    logger.error('error_event');

    expect(stream.lines).toHaveLength(2);
    expect(stream.lines.every((l) => l.includes('"warn_event"') || l.includes('"error_event"'))).toBe(true);
  });

  it('child loggers inherit and extend base fields', () => {
    const stream = captureStream();
    const root = createLogger({ level: 'info', stream });
    const child = root.child({ source: 'cveproject' });
    child.info('parsed');

    const parsed = JSON.parse(stream.lines[0] ?? '{}') as Record<string, unknown>;
    expect(parsed.source).toBe('cveproject');
  });
});
