type LogLevel = 'INFO' | 'WARN' | 'ERROR';

type LogFields = Record<string, unknown>;

function write(level: LogLevel, message: string, fields: LogFields = {}): void {
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    service: 'cyber-shield-ai',
    message,
    ...fields,
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
