import { NextResponse } from 'next/server';
import { isSentinelError, toSentinelError, type Logger } from '@sentinel/core';
import {
  RateLimiter,
  getPlatform,
  requireUser,
  type AuthUser,
  type Platform,
  type RateLimitBucket,
} from '@sentinel/platform';

/**
 * The API request pipeline.
 *
 * Every route goes through `handle`, which means authentication, rate limiting,
 * error shaping and security headers are applied uniformly rather than being
 * re-implemented (and eventually forgotten) per route. A route that forgets to
 * call this simply will not compile against the handler signature.
 */

export interface ApiContext<TParams = Record<string, string>> {
  platform: Platform;
  user: AuthUser;
  logger: Logger;
  request: Request;
  /** Resolved dynamic route segments. Empty for static routes. */
  params: TParams;
}

/** Next.js 15 passes route params as a promise. */
interface RouteContext<TParams> {
  params: Promise<TParams>;
}

export interface HandleOptions {
  /** Which rate-limit bucket applies. */
  rateLimit?: RateLimitBucket;
  /** Set false for endpoints that must work unauthenticated (health). */
  requireAuth?: boolean;
}

const SECURITY_HEADERS = {
  'x-content-type-options': 'nosniff',
  // API responses are data, never a document to render.
  'content-security-policy': "default-src 'none'; frame-ancestors 'none'",
  'cache-control': 'no-store',
};

export function json<T>(data: T, init: ResponseInit = {}): NextResponse {
  return NextResponse.json(data, {
    ...init,
    headers: { ...SECURITY_HEADERS, ...init.headers },
  });
}

/**
 * Wrap a route handler.
 *
 * Unexpected errors are logged with their detail but returned as a generic
 * message: stack traces and internal paths in an API response are an
 * information-disclosure finding of exactly the kind this product reports.
 */
export function handle<TParams = Record<string, string>>(
  handler: (ctx: ApiContext<TParams>) => Promise<NextResponse>,
  options: HandleOptions = {},
) {
  // Next.js validates this signature: the route context is always supplied, and
  // marking it optional makes the handler fail its own type check at build time.
  return async (request: Request, routeContext: RouteContext<TParams>): Promise<NextResponse> => {
    const started = Date.now();
    let platform: Platform;

    try {
      platform = await getPlatform();
    } catch (error) {
      // Platform initialization failing means misconfiguration; surface it
      // clearly because the operator is the only one who can fix it.
      const sentinelError = toSentinelError(error);
      return json(
        { error: { code: sentinelError.code, message: sentinelError.message } },
        { status: 503 },
      );
    }

    const logger = platform.logger.child({
      method: request.method,
      path: new URL(request.url).pathname,
    });

    try {
      const auth = await platform.auth.authenticate(request);
      const user = options.requireAuth === false ? auth.user : requireUser(auth);

      if (options.rateLimit) {
        const identity = RateLimiter.identify({
          ...(user?.id ? { userId: user.id } : {}),
          ...(RateLimiter.ipFrom(request) ? { ip: RateLimiter.ipFrom(request)! } : {}),
        });
        const result = await platform.rateLimiter.check(options.rateLimit, identity);

        if (!result.allowed) {
          logger.warn('Rate limit exceeded', { bucket: options.rateLimit, identity });
          return json(
            {
              error: {
                code: 'RATE_LIMITED',
                message: `Too many requests. Retry in ${result.retryAfterSeconds} seconds.`,
              },
            },
            { status: 429, headers: RateLimiter.headers(result) },
          );
        }
      }

      const response = await handler({
        platform,
        user: user ?? ({ id: 'anonymous', role: 'viewer' } as AuthUser),
        logger,
        request,
        params: ((await routeContext?.params) ?? {}) as TParams,
      });

      for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
        if (!response.headers.has(key)) response.headers.set(key, value);
      }
      return response;
    } catch (error) {
      const sentinelError = toSentinelError(error);

      if (sentinelError.expected) {
        logger.info('Request rejected', {
          code: sentinelError.code,
          message: sentinelError.message,
        });
        return json(sentinelError.toJSON(), { status: sentinelError.status });
      }

      logger.error('Unhandled route error', {
        code: sentinelError.code,
        message: sentinelError.message,
        stack: sentinelError.stack,
      });
      return json(
        { error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred' } },
        { status: 500 },
      );
    } finally {
      logger.debug('Request completed', { durationMs: Date.now() - started });
    }
  };
}

/** Parse query parameters, coercing the repeated/CSV forms clients actually send. */
export function searchParams(request: Request): {
  get(key: string): string | undefined;
  getAll(key: string): string[] | undefined;
  getNumber(key: string, fallback?: number): number | undefined;
  getBoolean(key: string): boolean | undefined;
} {
  const url = new URL(request.url);

  return {
    get: (key) => url.searchParams.get(key) ?? undefined,
    getAll: (key) => {
      const repeated = url.searchParams.getAll(key);
      if (!repeated.length) return undefined;
      // Accept both `?severity=high&severity=low` and `?severity=high,low`.
      return repeated
        .flatMap((value) => value.split(','))
        .map((v) => v.trim())
        .filter(Boolean);
    },
    getNumber: (key, fallback) => {
      const raw = url.searchParams.get(key);
      if (raw === null) return fallback;
      const value = Number(raw);
      return Number.isFinite(value) ? value : fallback;
    },
    getBoolean: (key) => {
      const raw = url.searchParams.get(key);
      if (raw === null) return undefined;
      return raw === 'true' || raw === '1';
    },
  };
}

/** Read and validate a JSON body, rejecting oversized payloads. */
export async function readJsonBody(request: Request, maxBytes = 1024 * 1024): Promise<unknown> {
  const contentLength = Number(request.headers.get('content-length') ?? 0);
  if (contentLength > maxBytes) {
    throw toSentinelError(new Error('Request body is too large'));
  }

  const text = await request.text();
  if (text.length > maxBytes) throw toSentinelError(new Error('Request body is too large'));
  if (!text.trim()) return {};

  try {
    return JSON.parse(text);
  } catch {
    const { errors } = await import('@sentinel/core');
    throw errors.validation('Request body is not valid JSON');
  }
}

export { isSentinelError };
