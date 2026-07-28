/**
 * A small, exhaustive error taxonomy.
 *
 * Every failure that can reach an API boundary carries an HTTP status and a
 * machine-readable `code`, so route handlers never have to guess how to respond
 * and clients never have to string-match error messages.
 */

export type ErrorCode =
  | 'VALIDATION_ERROR'
  | 'NOT_FOUND'
  | 'UNAUTHORIZED'
  | 'FORBIDDEN'
  | 'CONFLICT'
  | 'RATE_LIMITED'
  | 'PAYLOAD_TOO_LARGE'
  | 'UNSUPPORTED_TARGET'
  | 'SCANNER_FAILURE'
  | 'AI_PROVIDER_ERROR'
  | 'TIMEOUT'
  | 'STORAGE_ERROR'
  | 'INTERNAL_ERROR';

const STATUS_BY_CODE: Record<ErrorCode, number> = {
  VALIDATION_ERROR: 400,
  NOT_FOUND: 404,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  CONFLICT: 409,
  RATE_LIMITED: 429,
  PAYLOAD_TOO_LARGE: 413,
  UNSUPPORTED_TARGET: 422,
  SCANNER_FAILURE: 502,
  AI_PROVIDER_ERROR: 502,
  TIMEOUT: 504,
  STORAGE_ERROR: 500,
  INTERNAL_ERROR: 500,
};

export class SentinelError extends Error {
  readonly code: ErrorCode;
  readonly status: number;
  readonly details?: unknown;
  /** False for programming errors that should page someone. */
  readonly expected: boolean;

  constructor(
    code: ErrorCode,
    message: string,
    options: { details?: unknown; cause?: unknown; expected?: boolean } = {},
  ) {
    super(message, options.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = 'SentinelError';
    this.code = code;
    this.status = STATUS_BY_CODE[code];
    this.details = options.details;
    this.expected = options.expected ?? code !== 'INTERNAL_ERROR';
  }

  toJSON(): { error: { code: ErrorCode; message: string; details?: unknown } } {
    return {
      error: {
        code: this.code,
        message: this.message,
        ...(this.details !== undefined ? { details: this.details } : {}),
      },
    };
  }
}

export const errors = {
  validation: (message: string, details?: unknown) =>
    new SentinelError('VALIDATION_ERROR', message, { details }),
  notFound: (what: string) => new SentinelError('NOT_FOUND', `${what} not found`),
  unauthorized: (message = 'Authentication required') => new SentinelError('UNAUTHORIZED', message),
  forbidden: (message = 'You do not have access to this resource') =>
    new SentinelError('FORBIDDEN', message),
  conflict: (message: string) => new SentinelError('CONFLICT', message),
  rateLimited: (retryAfterSeconds: number) =>
    new SentinelError('RATE_LIMITED', 'Too many requests', { details: { retryAfterSeconds } }),
  tooLarge: (message: string) => new SentinelError('PAYLOAD_TOO_LARGE', message),
  unsupportedTarget: (message: string) => new SentinelError('UNSUPPORTED_TARGET', message),
  scannerFailure: (scanner: string, cause?: unknown) =>
    new SentinelError('SCANNER_FAILURE', `Scanner "${scanner}" failed`, { cause }),
  aiProvider: (message: string, cause?: unknown) =>
    new SentinelError('AI_PROVIDER_ERROR', message, { cause }),
  timeout: (what: string, ms: number) =>
    new SentinelError('TIMEOUT', `${what} timed out after ${ms}ms`),
  storage: (message: string, cause?: unknown) =>
    new SentinelError('STORAGE_ERROR', message, { cause }),
  internal: (message = 'Internal server error', cause?: unknown) =>
    new SentinelError('INTERNAL_ERROR', message, { cause, expected: false }),
};

export function isSentinelError(value: unknown): value is SentinelError {
  return value instanceof SentinelError;
}

/** Never let a non-Error rejection reach a catch block untyped. */
export function toSentinelError(value: unknown): SentinelError {
  if (isSentinelError(value)) return value;
  if (value instanceof Error) return errors.internal(value.message, value);
  return errors.internal(typeof value === 'string' ? value : 'Unknown error', value);
}
