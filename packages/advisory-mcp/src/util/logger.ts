export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface LogEvent {
  [key: string]: unknown;
  level: LogLevel;
  event: string;
}

export function logEvent(event: LogEvent): void {
  process.stderr.write(`${JSON.stringify({ ...event, ts: new Date().toISOString() })}\n`);
}
