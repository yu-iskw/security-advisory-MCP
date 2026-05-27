export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface LogEvent {
  level: LogLevel;
  event: string;
  [key: string]: unknown;
}

export function logEvent(event: LogEvent): void {
  process.stderr.write(`${JSON.stringify({ ...event, ts: new Date().toISOString() })}\n`);
}
