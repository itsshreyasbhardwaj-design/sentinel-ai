import { getEnv, createLogger, type Env, type Logger } from '@sentinel/core';
import { SqliteStorage } from './storage/sqlite.js';
import { PostgresStorage } from './storage/postgres.js';
import { createCache, type Cache } from './cache/index.js';
import { createQueue, type JobQueue } from './jobs/index.js';
import { createAuthProvider, type AuthProvider } from './auth/index.js';
import { RateLimiter } from './rate-limit.js';
import type { Storage } from './storage/types.js';

export * from './storage/types.js';
export { SqliteStorage } from './storage/sqlite.js';
export { PostgresStorage } from './storage/postgres.js';
export * from './cache/index.js';
export * from './jobs/index.js';
export * from './auth/index.js';
export * from './rate-limit.js';
export * from './crypto.js';

/**
 * The composed platform.
 *
 * One object holds every infrastructure dependency, wired from the environment.
 * Route handlers take this rather than reaching for globals, which is what makes
 * them testable and what keeps "which storage am I using" a single decision made
 * in one place.
 */
export interface Platform {
  env: Env;
  logger: Logger;
  storage: Storage;
  cache: Cache;
  queue: JobQueue;
  auth: AuthProvider;
  rateLimiter: RateLimiter;
  shutdown(): Promise<void>;
  /** What is actually wired up — surfaced by the health endpoint. */
  describe(): PlatformDescription;
}

export interface PlatformDescription {
  storage: string;
  cache: string;
  queue: string;
  auth: string;
  authEnforcing: boolean;
  aiProvider: string;
  networkScanners: boolean;
}

export interface CreatePlatformOptions {
  env?: Env;
  logger?: Logger;
}

/**
 * The platform singleton lives on `globalThis`, not in a module variable.
 *
 * Next.js compiles each route handler into its own server bundle, and dev-mode
 * hot reload replaces module instances. A module-scoped cache therefore gives
 * every route its *own* storage connection and — worse — its own in-process job
 * queue, so a scan started by `POST /api/scans` is invisible to
 * `GET /api/scans/[id]/stream`. Keying off the global object is the standard
 * fix for exactly this class of bug.
 */
const PLATFORM_KEY = Symbol.for('sentinel.platform');

interface PlatformGlobal {
  [PLATFORM_KEY]?: Promise<Platform>;
}

const globalRef = globalThis as unknown as PlatformGlobal;

async function build(options: CreatePlatformOptions): Promise<Platform> {
  const env = options.env ?? getEnv();
  const logger = options.logger ?? createLogger({ name: 'sentinel', level: env.LOG_LEVEL });

  const storage: Storage = env.DATABASE_URL
    ? new PostgresStorage({ connectionString: env.DATABASE_URL, logger })
    : new SqliteStorage({ path: env.SQLITE_PATH, logger });

  await storage.init();

  const cache = await createCache({
    ...(env.REDIS_URL ? { redisUrl: env.REDIS_URL } : {}),
    logger,
  });

  const queue = createQueue({
    logger,
    ...(env.TRIGGER_SECRET_KEY ? { triggerSecretKey: env.TRIGGER_SECRET_KEY } : {}),
  });

  const auth = createAuthProvider({
    ...(env.CLERK_SECRET_KEY ? { clerkSecretKey: env.CLERK_SECRET_KEY } : {}),
    ...(env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY
      ? { clerkPublishableKey: env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY }
      : {}),
    nodeEnv: env.NODE_ENV,
    logger,
  });

  const platform: Platform = {
    env,
    logger,
    storage,
    cache,
    queue,
    auth,
    rateLimiter: new RateLimiter(cache, {
      createScan: { limit: env.RATE_LIMIT_SCAN_MAX, windowMs: env.RATE_LIMIT_SCAN_WINDOW_MS },
      upload: { limit: env.RATE_LIMIT_SCAN_MAX * 2, windowMs: env.RATE_LIMIT_SCAN_WINDOW_MS },
      read: { limit: env.RATE_LIMIT_MAX_REQUESTS, windowMs: env.RATE_LIMIT_WINDOW_MS },
    }),
    async shutdown() {
      await queue.shutdown();
      await cache.close();
      await storage.close();
    },
    describe() {
      return {
        storage: storage.kind,
        cache: cache.kind,
        queue: queue.kind,
        auth: auth.kind,
        authEnforcing: auth.enforcing,
        aiProvider:
          env.OPENROUTER_API_KEY && env.AI_PROVIDER !== 'knowledge-base'
            ? 'openrouter'
            : 'knowledge-base',
        networkScanners: env.ALLOW_NETWORK_SCANNERS,
      };
    },
  };

  logger.info('Platform ready', platform.describe() as unknown as Record<string, unknown>);
  return platform;
}

/**
 * Memoized so Next.js route handlers, which are invoked per request, share one
 * connection pool and one job queue instead of opening a database per request.
 */
export function getPlatform(options: CreatePlatformOptions = {}): Promise<Platform> {
  globalRef[PLATFORM_KEY] ??= build(options).catch((error) => {
    // Do not cache a failed initialization: the next request should retry.
    delete globalRef[PLATFORM_KEY];
    throw error;
  });
  return globalRef[PLATFORM_KEY];
}

/** Test seam. */
export async function resetPlatform(): Promise<void> {
  const existing = globalRef[PLATFORM_KEY];
  delete globalRef[PLATFORM_KEY];
  if (existing) await existing.then((platform) => platform.shutdown()).catch(() => {});
}
