type LogLevel = 'INFO' | 'WARN' | 'ERROR';

type LogFields = Record<string, unknown>;

function serializeValue(value: unknown): unknown {
  if (value instanceof Error) {
    return {
      name: value.name,
      message: value.message,
    };
  }

  if (typeof value === 'bigint') return value.toString();
  if (value === undefined) return null;
  return value;
}

function sanitizeFields(fields: LogFields): LogFields {
  return Object.fromEntries(
    Object.entries(fields).map(([key, value]) => [key, serializeValue(value)]),
  );
}

function write(level: LogLevel, message: string, fields: LogFields = {}): void {
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    service: 'cyber-shield-ai',
    message,
    ...sanitizeFields(fields),
  };

  const output = JSON.stringify(entry);
  if (level === 'ERROR') {
    console.error(output);
  } else if (level === 'WARN') {
    console.warn(output);
  } else {
    console.log(output);
  }
}

export const logger = Object.freeze({
  info(message: string, fields?: LogFields): void {
    write('INFO', message, fields);
  },
  warn(message: string, fields?: LogFields): void {
    write('WARN', message, fields);
  },
  error(message: string, fields?: LogFields): void {
    write('ERROR', message, fields);
  },
});
