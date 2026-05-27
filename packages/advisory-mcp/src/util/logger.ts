export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

function configuredLevel(): LogLevel {
  const raw = process.env.ADVISORY_MCP_LOG_LEVEL ?? process.env.LOG_LEVEL ?? 'info';
  if (raw === 'debug' || raw === 'info' || raw === 'warn' || raw === 'error') {
    return raw;
  }
  return 'info';
}

export interface LogEvent {
  [key: string]: unknown;
  level: LogLevel;
  event: string;
}

export function logEvent(event: LogEvent): void {
  if (LEVEL_ORDER[event.level] < LEVEL_ORDER[configuredLevel()]) {
    return;
  }
  process.stderr.write(`${JSON.stringify({ ...event, ts: new Date().toISOString() })}\n`);
}
