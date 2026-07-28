import type { Logger } from '@sentinel/core';
import { optionalImport } from '../optional-import.js';

/**
 * Cache abstraction.
 *
 * In-memory LRU by default so a single-instance deployment needs no Redis;
 * Redis when `REDIS_URL` is set, for multi-instance deployments where the cache
 * has to be shared. Callers never see the difference.
 */

export interface Cache {
  readonly kind: 'memory' | 'redis';
  get<T>(key: string): Promise<T | undefined>;
  set<T>(key: string, value: T, ttlSeconds?: number): Promise<void>;
  delete(key: string): Promise<void>;
  /** Remove every key with this prefix — used to invalidate a project's views. */
  deletePrefix(prefix: string): Promise<void>;
  clear(): Promise<void>;
  close(): Promise<void>;
}

interface Entry<T> {
  value: T;
  expiresAt: number | undefined;
}

/**
 * LRU with TTL.
 *
 * Insertion order in a `Map` is the recency order as long as a read re-inserts,
 * so eviction is `delete` on the first key — no separate list to maintain.
 */
export class MemoryCache implements Cache {
  readonly kind = 'memory' as const;
  private readonly store = new Map<string, Entry<unknown>>();

  constructor(private readonly maxEntries = 1000) {}

  async get<T>(key: string): Promise<T | undefined> {
    const entry = this.store.get(key);
    if (!entry) return undefined;

    if (entry.expiresAt !== undefined && entry.expiresAt < Date.now()) {
      this.store.delete(key);
      return undefined;
    }

    // Re-insert to mark as recently used.
    this.store.delete(key);
    this.store.set(key, entry);
    return entry.value as T;
  }

  async set<T>(key: string, value: T, ttlSeconds?: number): Promise<void> {
    if (this.store.has(key)) this.store.delete(key);
    else if (this.store.size >= this.maxEntries) {
      const oldest = this.store.keys().next().value;
      if (oldest !== undefined) this.store.delete(oldest);
    }

    this.store.set(key, {
      value,
      expiresAt: ttlSeconds ? Date.now() + ttlSeconds * 1000 : undefined,
    });
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  async deletePrefix(prefix: string): Promise<void> {
    for (const key of [...this.store.keys()]) {
      if (key.startsWith(prefix)) this.store.delete(key);
    }
  }

  async clear(): Promise<void> {
    this.store.clear();
  }

  async close(): Promise<void> {
    this.store.clear();
  }

  /** Exposed for tests and the health endpoint. */
  get size(): number {
    return this.store.size;
  }
}

interface RedisLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, mode?: string, ttl?: number): Promise<unknown>;
  del(...keys: string[]): Promise<number>;
  scan(cursor: string, ...args: string[]): Promise<[string, string[]]>;
  flushdb(): Promise<unknown>;
  quit(): Promise<unknown>;
}

export class RedisCache implements Cache {
  readonly kind = 'redis' as const;

  constructor(
    private readonly client: RedisLike,
    private readonly logger: Logger,
    private readonly prefix = 'sentinel:',
  ) {}

  private key(key: string): string {
    return `${this.prefix}${key}`;
  }

  async get<T>(key: string): Promise<T | undefined> {
    try {
      const raw = await this.client.get(this.key(key));
      return raw ? (JSON.parse(raw) as T) : undefined;
    } catch (error) {
      // A cache miss is always a safe answer; a cache outage must not become an
      // application outage.
      this.logger.warn('Redis read failed; treating as a miss', { key, error: String(error) });
      return undefined;
    }
  }

  async set<T>(key: string, value: T, ttlSeconds?: number): Promise<void> {
    try {
      const payload = JSON.stringify(value);
      if (ttlSeconds) await this.client.set(this.key(key), payload, 'EX', ttlSeconds);
      else await this.client.set(this.key(key), payload);
    } catch (error) {
      this.logger.warn('Redis write failed', { key, error: String(error) });
    }
  }

  async delete(key: string): Promise<void> {
    try {
      await this.client.del(this.key(key));
    } catch (error) {
      this.logger.warn('Redis delete failed', { key, error: String(error) });
    }
  }

  async deletePrefix(prefix: string): Promise<void> {
    try {
      // SCAN rather than KEYS: KEYS blocks the server for the whole keyspace.
      let cursor = '0';
      do {
        const [next, keys] = await this.client.scan(
          cursor,
          'MATCH',
          `${this.key(prefix)}*`,
          'COUNT',
          '100',
        );
        cursor = next;
        if (keys.length) await this.client.del(...keys);
      } while (cursor !== '0');
    } catch (error) {
      this.logger.warn('Redis prefix delete failed', { prefix, error: String(error) });
    }
  }

  async clear(): Promise<void> {
    await this.client.flushdb().catch(() => {});
  }

  async close(): Promise<void> {
    await this.client.quit().catch(() => {});
  }
}

export interface CreateCacheOptions {
  redisUrl?: string;
  logger: Logger;
  maxEntries?: number;
}

export async function createCache(options: CreateCacheOptions): Promise<Cache> {
  if (!options.redisUrl) {
    options.logger.debug('Using in-memory cache');
    return new MemoryCache(options.maxEntries);
  }

  try {
    const { default: Redis } = await optionalImport<{
      default: new (url: string, opts?: Record<string, unknown>) => RedisLike;
    }>('ioredis', 'the Redis cache (selected because REDIS_URL is set)');
    const client = new Redis(options.redisUrl, { maxRetriesPerRequest: 2, lazyConnect: false });
    options.logger.info('Using Redis cache');
    return new RedisCache(client, options.logger);
  } catch (error) {
    // Degrade rather than fail: an unreachable cache should never stop a scan.
    options.logger.warn('Redis unavailable; falling back to the in-memory cache', {
      error: String(error),
    });
    return new MemoryCache(options.maxEntries);
  }
}

/**
 * Namespaced cache key helpers.
 *
 * Note that `analysis` sits under its own top-level prefix rather than under
 * `scan:{id}:`. Invalidating scan data (on triage, or on re-save) must not
 * discard the AI analysis, which is expensive to recompute and unaffected by a
 * status change — and a shared prefix makes that mistake inevitable.
 */
export const cacheKeys = {
  scan: (id: string) => `scan:${id}`,
  scanAnalysis: (id: string) => `analysis:${id}`,
  scanFindings: (id: string, query: string) => `scan:${id}:findings:${query}`,
  project: (id: string) => `project:${id}`,
  projectScans: (id: string) => `project:${id}:scans`,
  projectTrend: (id: string) => `project:${id}:trend`,
  stats: (id: string) => `scan:${id}:stats`,
  scannerCatalog: () => 'scanners:catalog',
};
