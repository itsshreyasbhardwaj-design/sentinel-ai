import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  newId,
  normalizeFindings,
  silentLogger,
  type Project,
  type ScanResult,
} from '@sentinel/core';
import { SqliteStorage } from './storage/sqlite.js';
import { MemoryCache, cacheKeys } from './cache/index.js';
import { InProcessQueue } from './jobs/index.js';
import {
  ClerkAuthProvider,
  DevelopmentAuthProvider,
  assertOwnership,
  createAuthProvider,
  generateApiKey,
  requireRole,
  requireUser,
  verifyApiKey,
} from './auth/index.js';
import { RATE_LIMITS, RateLimiter } from './rate-limit.js';
import { decryptSecret, encryptSecret, verifyWebhookSignature } from './crypto.js';
import { SentinelError } from '@sentinel/core';

/* ------------------------------------------------------------------ */
/* Fixtures                                                            */
/* ------------------------------------------------------------------ */

function makeProject(overrides: Partial<Project> = {}): Project {
  const now = new Date().toISOString();
  return {
    id: newId('proj'),
    name: 'Demo',
    slug: 'demo',
    ownerId: 'user_1',
    target: { type: 'local', path: '/repo' },
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
}

function makeScan(projectId: string, overrides: Partial<ScanResult> = {}): ScanResult {
  const findings = normalizeFindings(
    [
      {
        ruleId: 'js-sql-injection',
        title: 'SQL injection',
        severity: 'critical',
        kind: 'sast',
        location: { path: 'src/db.ts', startLine: 4 },
      },
      {
        ruleId: 'js-insecure-cookie',
        title: 'Insecure cookie',
        severity: 'low',
        kind: 'sast',
        location: { path: 'src/session.ts', startLine: 9 },
      },
    ],
    { scanId: 'scan_fixed', scanner: 'native-sast', scannerKind: 'native' },
  );

  return {
    id: newId('scan'),
    projectId,
    status: 'completed',
    target: { type: 'local', path: '/repo' },
    options: {},
    repository: { name: 'demo', languages: [], fileCount: 2, totalBytes: 100, linesOfCode: 50 },
    findings,
    scannerRuns: [
      {
        scanner: 'native-sast',
        kind: 'sast',
        scannerKind: 'native',
        status: 'ok',
        durationMs: 5,
        findingCount: 2,
      },
    ],
    scores: {
      overall: 55,
      grade: 'D',
      riskLevel: 'elevated',
      categories: [],
      counts: { info: 0, low: 1, medium: 0, high: 0, critical: 1 },
      totalFindings: 2,
      computedAt: new Date().toISOString(),
    },
    startedAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    durationMs: 500,
    ...overrides,
  };
}

/* ------------------------------------------------------------------ */
/* Storage                                                             */
/* ------------------------------------------------------------------ */

describe('SqliteStorage', () => {
  let storage: SqliteStorage;

  beforeEach(async () => {
    storage = new SqliteStorage({ path: ':memory:', logger: silentLogger });
    await storage.init();
  });

  afterEach(async () => {
    await storage.close();
  });

  it('refuses to operate before init', async () => {
    const uninitialized = new SqliteStorage({ path: ':memory:', logger: silentLogger });
    await expect(uninitialized.getProject('x')).rejects.toThrow(/not been initialized/);
  });

  it('is idempotent on repeated init', async () => {
    await expect(storage.init()).resolves.toBeUndefined();
  });

  describe('projects', () => {
    it('creates and reads back a project', async () => {
      const project = makeProject();
      await storage.createProject(project);

      const loaded = await storage.getProject(project.id);
      expect(loaded?.name).toBe('Demo');
      expect(loaded?.target).toEqual({ type: 'local', path: '/repo' });
    });

    it('looks up by owner and slug', async () => {
      const project = makeProject({ slug: 'my-app' });
      await storage.createProject(project);
      expect((await storage.getProjectBySlug('user_1', 'my-app'))?.id).toBe(project.id);
      expect(await storage.getProjectBySlug('user_2', 'my-app')).toBeUndefined();
    });

    it('enforces slug uniqueness per owner', async () => {
      await storage.createProject(makeProject({ slug: 'dup' }));
      await expect(storage.createProject(makeProject({ slug: 'dup' }))).rejects.toThrow();
      // A different owner may reuse the slug.
      await expect(
        storage.createProject(makeProject({ slug: 'dup', ownerId: 'user_2' })),
      ).resolves.toBeDefined();
    });

    it('updates and deletes', async () => {
      const project = makeProject();
      await storage.createProject(project);

      const updated = await storage.updateProject(project.id, { name: 'Renamed' });
      expect(updated?.name).toBe('Renamed');
      expect(await storage.deleteProject(project.id)).toBe(true);
      expect(await storage.getProject(project.id)).toBeUndefined();
    });

    it('returns undefined when updating a missing project', async () => {
      expect(await storage.updateProject('nope', { name: 'x' })).toBeUndefined();
      expect(await storage.deleteProject('nope')).toBe(false);
    });

    it('lists a single owner projects only', async () => {
      await storage.createProject(makeProject({ slug: 'a' }));
      await storage.createProject(makeProject({ slug: 'b' }));
      await storage.createProject(makeProject({ slug: 'c', ownerId: 'user_2' }));
      expect(await storage.listProjects('user_1')).toHaveLength(2);
    });
  });

  describe('scans', () => {
    it('persists a scan with its findings', async () => {
      const project = makeProject();
      await storage.createProject(project);
      const scan = makeScan(project.id);
      await storage.saveScan(scan);

      const loaded = await storage.getScan(scan.id);
      expect(loaded?.findings).toHaveLength(2);
      expect(loaded?.scores.overall).toBe(55);
    });

    it('cascades scan deletion when a project is removed', async () => {
      const project = makeProject();
      await storage.createProject(project);
      const scan = makeScan(project.id);
      await storage.saveScan(scan);

      await storage.deleteProject(project.id);
      expect(await storage.getScan(scan.id)).toBeUndefined();
    });

    it('updates the project last scan pointer', async () => {
      const project = makeProject();
      await storage.createProject(project);
      const scan = makeScan(project.id);
      await storage.saveScan(scan);

      expect((await storage.getProject(project.id))?.lastScanId).toBe(scan.id);
    });

    it('returns the most recent completed scan', async () => {
      const project = makeProject();
      await storage.createProject(project);

      const older = makeScan(project.id, { startedAt: '2026-01-01T00:00:00.000Z' });
      const newer = makeScan(project.id, { startedAt: '2026-06-01T00:00:00.000Z' });
      const failed = makeScan(project.id, {
        startedAt: '2026-07-01T00:00:00.000Z',
        status: 'failed',
      });

      await storage.saveScan(older);
      await storage.saveScan(newer);
      await storage.saveScan(failed);

      // A failed scan must never be used as the diff baseline.
      expect((await storage.getLatestScan(project.id))?.id).toBe(newer.id);
    });

    it('paginates the scan list', async () => {
      const project = makeProject();
      await storage.createProject(project);
      for (let i = 0; i < 5; i += 1) {
        await storage.saveScan(
          makeScan(project.id, { startedAt: `2026-0${i + 1}-01T00:00:00.000Z` }),
        );
      }

      const page = await storage.listScans({ projectId: project.id, limit: 2, offset: 0 });
      expect(page.items).toHaveLength(2);
      expect(page.total).toBe(5);
      // Newest first.
      expect(page.items[0]?.startedAt.startsWith('2026-05')).toBe(true);
    });

    it('replaces findings rather than duplicating on re-save', async () => {
      const project = makeProject();
      await storage.createProject(project);
      const scan = makeScan(project.id);

      await storage.saveScan(scan);
      await storage.saveScan(scan);

      const findings = await storage.listFindings(scan.id, {});
      expect(findings.total).toBe(2);
    });
  });

  describe('findings', () => {
    it('filters by severity and kind', async () => {
      const project = makeProject();
      await storage.createProject(project);
      const scan = makeScan(project.id);
      await storage.saveScan(scan);

      expect((await storage.listFindings(scan.id, { severity: ['critical'] })).total).toBe(1);
      expect((await storage.listFindings(scan.id, { kind: ['dependencies'] })).total).toBe(0);
    });

    it('supports free-text search', async () => {
      const project = makeProject();
      await storage.createProject(project);
      const scan = makeScan(project.id);
      await storage.saveScan(scan);

      expect((await storage.listFindings(scan.id, { search: 'cookie' })).total).toBe(1);
      expect((await storage.listFindings(scan.id, { search: 'nothing' })).total).toBe(0);
    });

    it('updates finding status and keeps the scan payload consistent', async () => {
      const project = makeProject();
      await storage.createProject(project);
      const scan = makeScan(project.id);
      await storage.saveScan(scan);

      const target = scan.findings[0]!;
      const updated = await storage.updateFindingStatus(
        scan.id,
        target.id,
        'false-positive',
        'Query is parameterized by the ORM',
      );

      expect(updated?.status).toBe('false-positive');
      expect(updated?.suppressed).toBe(true);

      // The denormalized copy inside the scan payload must agree, or an export
      // would show the pre-triage status.
      const reloaded = await storage.getScan(scan.id);
      expect(reloaded?.findings.find((f) => f.id === target.id)?.status).toBe('false-positive');
    });

    it('returns undefined for an unknown finding', async () => {
      expect(await storage.getFinding('nope', 'nope')).toBeUndefined();
      expect(await storage.updateFindingStatus('nope', 'nope', 'fixed')).toBeUndefined();
    });
  });

  describe('score history', () => {
    it('records a point per completed scan, oldest first', async () => {
      const project = makeProject();
      await storage.createProject(project);

      await storage.saveScan(makeScan(project.id, { completedAt: '2026-01-01T00:00:00.000Z' }));
      await storage.saveScan(makeScan(project.id, { completedAt: '2026-02-01T00:00:00.000Z' }));

      const history = await storage.getScoreHistory(project.id);
      expect(history).toHaveLength(2);
      expect(history[0]!.timestamp < history[1]!.timestamp).toBe(true);
    });

    it('excludes failed scans from history', async () => {
      const project = makeProject();
      await storage.createProject(project);
      await storage.saveScan(makeScan(project.id, { status: 'failed' }));
      expect(await storage.getScoreHistory(project.id)).toHaveLength(0);
    });
  });
});

/* ------------------------------------------------------------------ */
/* Cache                                                               */
/* ------------------------------------------------------------------ */

describe('MemoryCache', () => {
  it('stores and retrieves values', async () => {
    const cache = new MemoryCache();
    await cache.set('a', { value: 1 });
    expect(await cache.get<{ value: number }>('a')).toEqual({ value: 1 });
    expect(await cache.get('missing')).toBeUndefined();
  });

  it('expires entries after their TTL', async () => {
    vi.useFakeTimers();
    try {
      const cache = new MemoryCache();
      await cache.set('a', 'value', 10);
      expect(await cache.get('a')).toBe('value');

      vi.advanceTimersByTime(11_000);
      expect(await cache.get('a')).toBeUndefined();
    } finally {
      vi.useRealTimers();
    }
  });

  it('evicts the least recently used entry at capacity', async () => {
    const cache = new MemoryCache(3);
    await cache.set('a', 1);
    await cache.set('b', 2);
    await cache.set('c', 3);

    // Touch 'a' so 'b' becomes the least recently used.
    await cache.get('a');
    await cache.set('d', 4);

    expect(await cache.get('b')).toBeUndefined();
    expect(await cache.get('a')).toBe(1);
    expect(cache.size).toBe(3);
  });

  it('deletes by prefix', async () => {
    const cache = new MemoryCache();
    await cache.set(cacheKeys.scan('1'), 'a');
    await cache.set(cacheKeys.scanFindings('1', 'q'), 'b');
    await cache.set(cacheKeys.project('9'), 'c');

    await cache.deletePrefix('scan:1');
    expect(await cache.get(cacheKeys.scan('1'))).toBeUndefined();
    expect(await cache.get(cacheKeys.scanFindings('1', 'q'))).toBeUndefined();
    expect(await cache.get(cacheKeys.project('9'))).toBe('c');
  });
});

/* ------------------------------------------------------------------ */
/* Jobs                                                                */
/* ------------------------------------------------------------------ */

describe('InProcessQueue', () => {
  let queue: InProcessQueue;

  beforeEach(() => {
    queue = new InProcessQueue({ logger: silentLogger, concurrency: 2 });
  });

  afterEach(async () => {
    await queue.shutdown();
  });

  const settle = async (jobId: string, timeoutMs = 3000) => {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const job = await queue.get(jobId);
      if (job && ['completed', 'failed', 'cancelled'].includes(job.status)) return job;
      if (Date.now() > deadline) throw new Error(`Job ${jobId} did not settle`);
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  };

  it('runs a job and records its result', async () => {
    queue.register<{ n: number }, number>('double', async (input) => input.n * 2);
    const job = await queue.enqueue('double', { n: 21 });
    expect((await settle(job.id)).result).toBe(42);
  });

  it('rejects an unregistered job type', async () => {
    await expect(queue.enqueue('unknown', {})).rejects.toThrow(/No handler registered/);
  });

  it('records a failure without throwing to the enqueuer', async () => {
    queue.register('boom', async () => {
      throw new Error('handler exploded');
    });
    const job = await queue.enqueue('boom', {});
    const settled = await settle(job.id);
    expect(settled.status).toBe('failed');
    expect(settled.error).toContain('handler exploded');
  });

  it('retries up to maxAttempts', async () => {
    const retrying = new InProcessQueue({ logger: silentLogger, maxAttempts: 3 });
    let attempts = 0;
    retrying.register('flaky', async () => {
      attempts += 1;
      if (attempts < 3) throw new Error('not yet');
      return 'ok';
    });

    const job = await retrying.enqueue('flaky', {});
    const deadline = Date.now() + 3000;
    let settled = await retrying.get(job.id);
    while (settled && !['completed', 'failed'].includes(settled.status) && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 10));
      settled = await retrying.get(job.id);
    }

    expect(settled?.status).toBe('completed');
    expect(attempts).toBe(3);
    await retrying.shutdown();
  });

  it('cancels a queued job', async () => {
    // Observes the abort signal so queue shutdown is not blocked by this test.
    queue.register('slow', async (_input, ctx) => {
      while (!ctx.signal.aborted) await new Promise((resolve) => setTimeout(resolve, 10));
      return null;
    });
    // Fill both worker slots so the third job stays queued.
    await queue.enqueue('slow', {});
    await queue.enqueue('slow', {});
    const queued = await queue.enqueue('slow', {});

    expect(await queue.cancel(queued.id)).toBe(true);
    expect((await queue.get(queued.id))?.status).toBe('cancelled');
  });

  it('signals cancellation to a running job', async () => {
    let observed = false;
    queue.register('watch', async (_input, ctx) => {
      while (!ctx.signal.aborted) await new Promise((resolve) => setTimeout(resolve, 5));
      observed = true;
      return 'stopped';
    });

    const job = await queue.enqueue('watch', {});
    await new Promise((resolve) => setTimeout(resolve, 30));
    await queue.cancel(job.id);
    await settle(job.id);

    expect(observed).toBe(true);
    expect((await queue.get(job.id))?.status).toBe('cancelled');
  });

  it('streams progress events to a subscriber', async () => {
    queue.register('progress', async (_input, ctx) => {
      for (const percent of [25, 50, 100]) {
        ctx.reportProgress({
          scanId: 's',
          status: percent === 100 ? 'completed' : 'running',
          percent,
          phase: 'scanning',
          completedScanners: [],
          totalScanners: 1,
          findingsSoFar: 0,
          startedAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        });
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
      return 'done';
    });

    const job = await queue.enqueue('progress', {});
    const seen: number[] = [];
    for await (const progress of queue.subscribe(job.id)) seen.push(progress.percent);

    expect(seen).toContain(100);
    expect(seen.length).toBeGreaterThanOrEqual(2);
  });

  it('ends the subscription immediately for an unknown job', async () => {
    const seen: unknown[] = [];
    for await (const progress of queue.subscribe('nope')) seen.push(progress);
    expect(seen).toHaveLength(0);
  });

  it('respects the concurrency limit', async () => {
    let concurrent = 0;
    let peak = 0;
    queue.register('count', async () => {
      concurrent += 1;
      peak = Math.max(peak, concurrent);
      await new Promise((resolve) => setTimeout(resolve, 30));
      concurrent -= 1;
      return null;
    });

    const jobs = await Promise.all(Array.from({ length: 6 }, () => queue.enqueue('count', {})));
    await Promise.all(jobs.map((job) => settle(job.id)));
    expect(peak).toBeLessThanOrEqual(2);
  });
});

/* ------------------------------------------------------------------ */
/* Auth                                                                */
/* ------------------------------------------------------------------ */

describe('auth', () => {
  it('generates and verifies API keys in constant time', () => {
    const { key, hash } = generateApiKey();
    expect(key.startsWith('sk_sentinel_')).toBe(true);
    expect(verifyApiKey(key, hash)).toBe(true);
    expect(verifyApiKey('sk_sentinel_wrong', hash)).toBe(false);
    // The plaintext key must never equal what is stored.
    expect(hash).not.toContain(key);
  });

  it('refuses the development provider in production', () => {
    expect(() => new DevelopmentAuthProvider(silentLogger, 'production')).toThrow(
      /Refusing to start/,
    );
    expect(() => new DevelopmentAuthProvider(silentLogger, 'development')).not.toThrow();
  });

  it('selects Clerk when both keys are present', () => {
    const provider = createAuthProvider({
      clerkSecretKey: 'sk_test_x',
      clerkPublishableKey: 'pk_test_x',
      nodeEnv: 'development',
      logger: silentLogger,
    });
    expect(provider.kind).toBe('clerk');
    expect(provider.enforcing).toBe(true);
  });

  it('falls back to development auth when Clerk is only half-configured', () => {
    const provider = createAuthProvider({
      clerkSecretKey: 'sk_test_x',
      nodeEnv: 'development',
      logger: silentLogger,
    });
    expect(provider.kind).toBe('development');
    expect(provider.enforcing).toBe(false);
  });

  describe('ClerkAuthProvider', () => {
    const provider = new ClerkAuthProvider({
      secretKey: 'sk',
      publishableKey: 'pk',
      logger: silentLogger,
      verifyToken: async (token) =>
        token === 'good' ? { sub: 'user_42', email: 'a@b.com', org_role: 'org:admin' } : undefined,
    });

    it('accepts a valid bearer token', async () => {
      const result = await provider.authenticate(
        new Request('http://localhost', { headers: { authorization: 'Bearer good' } }),
      );
      expect(result.user?.id).toBe('user_42');
      expect(result.user?.role).toBe('admin');
      expect(result.method).toBe('clerk');
    });

    it('accepts a session cookie', async () => {
      const result = await provider.authenticate(
        new Request('http://localhost', { headers: { cookie: '__session=good; other=x' } }),
      );
      expect(result.user?.id).toBe('user_42');
    });

    it('rejects a missing or invalid token', async () => {
      expect((await provider.authenticate(new Request('http://localhost'))).user).toBeUndefined();
      const bad = await provider.authenticate(
        new Request('http://localhost', { headers: { authorization: 'Bearer bad' } }),
      );
      expect(bad.user).toBeUndefined();
      expect(bad.method).toBe('none');
    });

    it('does not authenticate when verification throws', async () => {
      const throwing = new ClerkAuthProvider({
        secretKey: 'sk',
        publishableKey: 'pk',
        logger: silentLogger,
        verifyToken: async () => {
          throw new Error('network down');
        },
      });
      const result = await throwing.authenticate(
        new Request('http://localhost', { headers: { authorization: 'Bearer any' } }),
      );
      expect(result.user).toBeUndefined();
    });
  });

  describe('guards', () => {
    const user = { id: 'user_1', role: 'member' as const };

    it('requireUser throws when unauthenticated', () => {
      expect(() => requireUser({ user: undefined, method: 'none' })).toThrow(SentinelError);
      expect(requireUser({ user, method: 'development' })).toBe(user);
    });

    it('requireRole enforces the hierarchy', () => {
      expect(() => requireRole(user, 'admin')).toThrow(/requires the admin role/);
      expect(() => requireRole({ ...user, role: 'owner' }, 'admin')).not.toThrow();
      expect(() => requireRole(user, 'member')).not.toThrow();
    });

    it('assertOwnership allows the owner and refuses others', () => {
      expect(() => assertOwnership(user, 'user_1')).not.toThrow();
      // Refused as a 404 so the resource existence is not disclosed.
      expect(() => assertOwnership(user, 'user_2')).toThrow(/not found/i);
    });

    it('allows an org admin to act on org-owned resources', () => {
      const admin = { id: 'user_9', role: 'admin' as const, organizationId: 'org_1' };
      expect(() => assertOwnership(admin, 'org_1')).not.toThrow();
      // A plain member of the org may not.
      expect(() => assertOwnership({ ...admin, role: 'member' }, 'org_1')).toThrow();
    });
  });
});

/* ------------------------------------------------------------------ */
/* Rate limiting                                                       */
/* ------------------------------------------------------------------ */

describe('RateLimiter', () => {
  it('allows requests up to the limit and then refuses', async () => {
    const limiter = new RateLimiter(new MemoryCache());
    const identity = 'user:test';
    const limit = RATE_LIMITS.createScan.limit;

    for (let i = 0; i < limit; i += 1) {
      const result = await limiter.check('createScan', identity);
      expect(result.allowed, `request ${i + 1}`).toBe(true);
      expect(result.remaining).toBe(limit - i - 1);
    }

    const blocked = await limiter.check('createScan', identity);
    expect(blocked.allowed).toBe(false);
    expect(blocked.remaining).toBe(0);
    expect(blocked.retryAfterSeconds).toBeGreaterThan(0);
  });

  it('tracks identities independently', async () => {
    const limiter = new RateLimiter(new MemoryCache());
    for (let i = 0; i < RATE_LIMITS.createScan.limit; i += 1) {
      await limiter.check('createScan', 'user:a');
    }
    expect((await limiter.check('createScan', 'user:a')).allowed).toBe(false);
    expect((await limiter.check('createScan', 'user:b')).allowed).toBe(true);
  });

  it('resets after the window elapses', async () => {
    vi.useFakeTimers();
    try {
      const limiter = new RateLimiter(new MemoryCache());
      for (let i = 0; i < RATE_LIMITS.createScan.limit; i += 1) {
        await limiter.check('createScan', 'user:c');
      }
      expect((await limiter.check('createScan', 'user:c')).allowed).toBe(false);

      vi.advanceTimersByTime(RATE_LIMITS.createScan.windowMs + 1000);
      expect((await limiter.check('createScan', 'user:c')).allowed).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it('hashes the IP rather than storing it', () => {
    const identity = RateLimiter.identify({ ip: '203.0.113.42' });
    expect(identity.startsWith('ip:')).toBe(true);
    expect(identity).not.toContain('203.0.113.42');
  });

  it('prefers the user id over the IP', () => {
    expect(RateLimiter.identify({ userId: 'u1', ip: '1.2.3.4' })).toBe('user:u1');
    expect(RateLimiter.identify({})).toBe('anonymous');
  });

  it('reads the original client from x-forwarded-for', () => {
    const request = new Request('http://localhost', {
      headers: { 'x-forwarded-for': '203.0.113.9, 70.41.3.18' },
    });
    expect(RateLimiter.ipFrom(request)).toBe('203.0.113.9');
  });

  it('emits standard rate-limit headers', () => {
    const headers = RateLimiter.headers({
      allowed: false,
      limit: 10,
      remaining: 0,
      resetAt: Date.now() + 60_000,
      retryAfterSeconds: 60,
    });
    expect(headers['ratelimit-limit']).toBe('10');
    expect(headers['retry-after']).toBe('60');
  });
});

/* ------------------------------------------------------------------ */
/* Crypto                                                              */
/* ------------------------------------------------------------------ */

describe('secret encryption', () => {
  const masterKey = 'a'.repeat(48);

  it('round-trips a value', () => {
    const encrypted = encryptSecret('ghp_supersecrettoken', masterKey);
    expect(encrypted).not.toContain('ghp_');
    expect(decryptSecret(encrypted, masterKey)).toBe('ghp_supersecrettoken');
  });

  it('produces different ciphertext each time', () => {
    // A per-encryption salt and IV mean identical plaintext must not produce
    // identical ciphertext, or the store leaks which values are equal.
    const a = encryptSecret('same value', masterKey);
    const b = encryptSecret('same value', masterKey);
    expect(a).not.toBe(b);
    expect(decryptSecret(a, masterKey)).toBe(decryptSecret(b, masterKey));
  });

  it('rejects a tampered ciphertext', () => {
    const encrypted = encryptSecret('sensitive', masterKey);
    const blob = Buffer.from(encrypted, 'base64');
    blob[blob.length - 1] ^= 0xff;

    expect(() => decryptSecret(blob.toString('base64'), masterKey)).toThrow(/modified|malformed/i);
  });

  it('rejects the wrong key', () => {
    const encrypted = encryptSecret('sensitive', masterKey);
    expect(() => decryptSecret(encrypted, 'b'.repeat(48))).toThrow();
  });

  it('requires a sufficiently long master key', () => {
    expect(() => encryptSecret('x', 'short')).toThrow(/at least 32/);
  });

  it('rejects a truncated blob', () => {
    expect(() => decryptSecret('AAAA', masterKey)).toThrow(/malformed/i);
  });
});

describe('verifyWebhookSignature', () => {
  const secret = 'webhook-secret';
  const body = JSON.stringify({ action: 'opened' });

  it('accepts a correct signature', async () => {
    const { createHmac } = await import('node:crypto');
    const signature = `sha256=${createHmac('sha256', secret).update(body).digest('hex')}`;
    expect(await verifyWebhookSignature(body, signature, secret)).toBe(true);
  });

  it('rejects a wrong or missing signature', async () => {
    expect(await verifyWebhookSignature(body, 'sha256=deadbeef', secret)).toBe(false);
    expect(await verifyWebhookSignature(body, null, secret)).toBe(false);
    expect(await verifyWebhookSignature(body, 'sha256=x', '')).toBe(false);
  });

  it('rejects a signature over a different body', async () => {
    const { createHmac } = await import('node:crypto');
    const signature = `sha256=${createHmac('sha256', secret).update('other body').digest('hex')}`;
    expect(await verifyWebhookSignature(body, signature, secret)).toBe(false);
  });
});
