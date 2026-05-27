type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_RANK: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

interface Logger {
  level: LogLevel;
  debug(event: string, fields?: Record<string, unknown>): void;
  info(event: string, fields?: Record<string, unknown>): void;
  warn(event: string, fields?: Record<string, unknown>): void;
  error(event: string, fields?: Record<string, unknown>): void;
  child(fields: Record<string, unknown>): Logger;
}

interface LoggerOptions {
  level?: LogLevel;
  stream?: { write: (chunk: string) => void };
  baseFields?: Record<string, unknown>;
  now?: () => Date;
}

export function createLogger(options: LoggerOptions = {}): Logger {
  const level: LogLevel = options.level ?? 'info';
  const stream = options.stream ?? process.stderr;
  const baseFields = options.baseFields ?? {};
  const now = options.now ?? (() => new Date());

  function emit(
    recordLevel: LogLevel,
    event: string,
    fields?: Record<string, unknown>,
  ): void {
    // Both lookups use values constrained to the LogLevel union.
    // eslint-disable-next-line security/detect-object-injection
    if (LEVEL_RANK[recordLevel] < LEVEL_RANK[level]) return;
    const payload = {
      ts: now().toISOString(),
      level: recordLevel,
      event,
      ...baseFields,
      ...fields,
    };
    stream.write(`${JSON.stringify(payload)}\n`);
  }

  const logger: Logger = {
    level,
    debug: (event, fields) => {
      emit('debug', event, fields);
    },
    info: (event, fields) => {
      emit('info', event, fields);
    },
    warn: (event, fields) => {
      emit('warn', event, fields);
    },
    error: (event, fields) => {
      emit('error', event, fields);
    },
    child: (fields) =>
      createLogger({
        level,
        stream,
        baseFields: { ...baseFields, ...fields },
        now,
      }),
  };

  return logger;
}
