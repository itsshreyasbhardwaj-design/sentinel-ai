import { createHash } from 'node:crypto';
import type { Cache } from './cache/index.js';

/**
 * Rate limiting.
 *
 * Sliding-window counters over the cache, so the same code path works with the
 * in-memory cache on one instance and Redis across many. Scan creation is
 * limited far more aggressively than reads because a scan is minutes of CPU and
 * an unbounded scan endpoint is a free denial-of-service against yourself.
 */

export interface RateLimitRule {
  /** Requests permitted per window. */
  limit: number;
  windowMs: number;
}

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  /** Unix ms when the window resets. */
  resetAt: number;
  retryAfterSeconds: number;
}

export const RATE_LIMITS = {
  /** Scans are expensive; this is the limit that actually protects the service. */
  createScan: { limit: 10, windowMs: 60 * 60_000 },
  /** Uploads additionally consume disk and CPU during extraction. */
  upload: { limit: 20, windowMs: 60 * 60_000 },
  read: { limit: 300, windowMs: 60_000 },
  export: { limit: 60, windowMs: 60_000 },
  webhook: { limit: 600, windowMs: 60_000 },
} as const satisfies Record<string, RateLimitRule>;

export type RateLimitBucket = keyof typeof RATE_LIMITS;

interface WindowState {
  count: number;
  windowStart: number;
}

export type RateLimitOverrides = Partial<Record<RateLimitBucket, Partial<RateLimitRule>>>;

export class RateLimiter {
  private readonly rules: Record<RateLimitBucket, RateLimitRule>;

  /**
   * Limits are configurable, because the right value is deployment-specific: a
   * shared hosted instance needs them tight, a self-hosted CI runner needs them
   * loose, and a test suite needs them effectively off. Hard-coding them turns
   * a policy decision into a code change.
   */
  constructor(
    private readonly cache: Cache,
    overrides: RateLimitOverrides = {},
  ) {
    this.rules = Object.fromEntries(
      (Object.keys(RATE_LIMITS) as RateLimitBucket[]).map((bucket) => [
        bucket,
        { ...RATE_LIMITS[bucket], ...overrides[bucket] },
      ]),
    ) as Record<RateLimitBucket, RateLimitRule>;
  }

  /**
   * Identify the caller.
   *
   * User id when authenticated, hashed IP otherwise. The IP is hashed because
   * a rate-limit key is stored and may be logged, and raw client IPs are
   * personal data we have no reason to retain.
   */
  static identify(options: { userId?: string; ip?: string }): string {
    if (options.userId) return `user:${options.userId}`;
    if (options.ip)
      return `ip:${createHash('sha256').update(options.ip).digest('hex').slice(0, 24)}`;
    return 'anonymous';
  }

  /** Read the client IP from the usual proxy headers. */
  static ipFrom(request: Request): string | undefined {
    const forwarded = request.headers.get('x-forwarded-for');
    // The left-most entry is the original client; the rest are proxies.
    if (forwarded) return forwarded.split(',')[0]?.trim();
    return request.headers.get('x-real-ip') ?? request.headers.get('cf-connecting-ip') ?? undefined;
  }

  async check(bucket: RateLimitBucket, identity: string): Promise<RateLimitResult> {
    const rule = this.rules[bucket];
    const now = Date.now();
    const key = `ratelimit:${bucket}:${identity}`;

    const state = (await this.cache.get<WindowState>(key)) ?? { count: 0, windowStart: now };
    const elapsed = now - state.windowStart;

    // Window expired — start a fresh one.
    if (elapsed >= rule.windowMs) {
      const next: WindowState = { count: 1, windowStart: now };
      await this.cache.set(key, next, Math.ceil(rule.windowMs / 1000));
      return {
        allowed: true,
        limit: rule.limit,
        remaining: rule.limit - 1,
        resetAt: now + rule.windowMs,
        retryAfterSeconds: 0,
      };
    }

    const resetAt = state.windowStart + rule.windowMs;

    if (state.count >= rule.limit) {
      return {
        allowed: false,
        limit: rule.limit,
        remaining: 0,
        resetAt,
        retryAfterSeconds: Math.max(1, Math.ceil((resetAt - now) / 1000)),
      };
    }

    const next: WindowState = { count: state.count + 1, windowStart: state.windowStart };
    await this.cache.set(key, next, Math.ceil((resetAt - now) / 1000));

    return {
      allowed: true,
      limit: rule.limit,
      remaining: rule.limit - next.count,
      resetAt,
      retryAfterSeconds: 0,
    };
  }

  /** Standard headers so clients can back off intelligently. */
  static headers(result: RateLimitResult): Record<string, string> {
    return {
      'ratelimit-limit': String(result.limit),
      'ratelimit-remaining': String(result.remaining),
      'ratelimit-reset': String(Math.ceil((result.resetAt - Date.now()) / 1000)),
      ...(result.allowed ? {} : { 'retry-after': String(result.retryAfterSeconds) }),
    };
  }
}
