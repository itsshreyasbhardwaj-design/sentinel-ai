/**
 * Structured logger with secret redaction baked in.
 *
 * A security platform that leaks the credentials it finds into its own logs is
 * worse than no platform at all, so redaction happens at the logger boundary
 * rather than being left to each call site.
 */

export const LOG_LEVELS = ['debug', 'info', 'warn', 'error', 'silent'] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];

const LEVEL_RANK: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
  silent: 100,
};

export interface LogFields {
  [key: string]: unknown;
}

export interface Logger {
  debug(message: string, fields?: LogFields): void;
  info(message: string, fields?: LogFields): void;
  warn(message: string, fields?: LogFields): void;
  error(message: string, fields?: LogFields): void;
  child(bindings: LogFields): Logger;
}

const SENSITIVE_KEY = /(pass|secret|token|key|credential|authorization|cookie|session|signature)/i;

/** Patterns whose *values* are self-evidently secret regardless of key name. */
const SECRET_VALUE_PATTERNS: RegExp[] = [
  /\bgh[pousr]_[A-Za-z0-9]{16,}\b/g,
  /\bsk-[A-Za-z0-9_-]{16,}\b/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
];

export function redactValue(value: string): string {
  let out = value;
  for (const pattern of SECRET_VALUE_PATTERNS) {
    out = out.replace(pattern, '[REDACTED]');
  }
  return out;
}

/** Depth-limited so a cyclic or enormous object can never wedge the logger. */
export function redact(input: unknown, depth = 0): unknown {
  if (depth > 6) return '[truncated]';
  if (typeof input === 'string') return redactValue(input);
  if (input === null || typeof input !== 'object') return input;
  if (Array.isArray(input)) return input.slice(0, 100).map((item) => redact(item, depth + 1));

  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
    out[key] = SENSITIVE_KEY.test(key) ? '[REDACTED]' : redact(value, depth + 1);
  }
  return out;
}

export interface LoggerOptions {
  level?: LogLevel;
  name?: string;
  /** `json` for production aggregation, `pretty` for local development. */
  format?: 'json' | 'pretty';
  sink?: (line: string) => void;
}

const LEVEL_COLOR: Record<Exclude<LogLevel, 'silent'>, string> = {
  debug: '[90m',
  info: '[36m',
  warn: '[33m',
  error: '[31m',
};

export function createLogger(options: LoggerOptions = {}): Logger {
  const level = options.level ?? (process.env.LOG_LEVEL as LogLevel) ?? 'info';
  const format = options.format ?? (process.env.NODE_ENV === 'production' ? 'json' : 'pretty');
  const sink = options.sink ?? ((line: string) => process.stdout.write(`${line}\n`));
  const bindings: LogFields = options.name ? { name: options.name } : {};

  function make(currentBindings: LogFields): Logger {
    function log(entryLevel: Exclude<LogLevel, 'silent'>, message: string, fields?: LogFields) {
      if (LEVEL_RANK[entryLevel] < LEVEL_RANK[level]) return;
      const payload = {
        level: entryLevel,
        time: new Date().toISOString(),
        msg: redactValue(message),
        ...(redact(currentBindings) as LogFields),
        ...((fields ? (redact(fields) as LogFields) : {}) as LogFields),
      };

      if (format === 'json') {
        sink(JSON.stringify(payload));
        return;
      }

      const { level: _l, time, msg, ...rest } = payload;
      const color = LEVEL_COLOR[entryLevel];
      const extras = Object.keys(rest).length ? ` ${JSON.stringify(rest)}` : '';
      sink(
        `${color}${entryLevel.toUpperCase().padEnd(5)}[0m ${String(time).slice(11, 23)} ${msg}${extras}`,
      );
    }

    return {
      debug: (m, f) => log('debug', m, f),
      info: (m, f) => log('info', m, f),
      warn: (m, f) => log('warn', m, f),
      error: (m, f) => log('error', m, f),
      child: (extra) => make({ ...currentBindings, ...extra }),
    };
  }

  return make(bindings);
}

/** Discards everything. Useful in tests and in the CLI's `--quiet` mode. */
export const silentLogger: Logger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
  child: () => silentLogger,
};
