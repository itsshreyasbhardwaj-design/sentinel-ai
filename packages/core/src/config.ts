import { z } from 'zod';

/**
 * Environment contract.
 *
 * Sentinel is designed to run with **zero** external services: every integration
 * below is optional and falls back to a bundled implementation. Validation
 * happens once at startup so a typo in a connection string fails loudly rather
 * than surfacing as a mystery 500 an hour later.
 */
const booleanish = z
  .union([z.boolean(), z.string()])
  .transform((v) =>
    typeof v === 'boolean' ? v : ['1', 'true', 'yes', 'on'].includes(v.toLowerCase()),
  );

export const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error', 'silent']).default('info'),

  /** Absolute base URL, used for webhook callbacks and absolute links in reports. */
  APP_URL: z.string().url().default('http://localhost:3000'),

  // --- Storage: SQLite by default, Postgres/Supabase when a URL is supplied ---
  DATABASE_URL: z.string().url().optional(),
  SQLITE_PATH: z.string().default('.sentinel/sentinel.db'),

  // --- Cache: in-memory LRU by default, Redis when a URL is supplied ---
  REDIS_URL: z.string().url().optional(),

  // --- Auth: local dev identity by default, Clerk when keys are supplied ---
  NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY: z.string().optional(),
  CLERK_SECRET_KEY: z.string().optional(),

  // --- AI: deterministic offline analyst by default, OpenRouter when keyed ---
  OPENROUTER_API_KEY: z.string().optional(),
  OPENROUTER_MODEL: z.string().default('anthropic/claude-3.5-sonnet'),
  AI_PROVIDER: z.enum(['auto', 'knowledge-base', 'openrouter']).default('auto'),
  /** Hard ceiling on explained findings per scan — bounds token spend. */
  AI_MAX_EXPLANATIONS: z.coerce.number().int().positive().max(500).default(50),

  // --- Background jobs: in-process by default, Trigger.dev when keyed ---
  TRIGGER_SECRET_KEY: z.string().optional(),
  TRIGGER_API_URL: z.string().url().optional(),

  // --- GitHub integration ---
  GITHUB_TOKEN: z.string().optional(),
  GITHUB_WEBHOOK_SECRET: z.string().optional(),
  GITHUB_APP_ID: z.string().optional(),

  // --- Security controls ---
  /** Encrypts stored integration tokens at rest. Required in production. */
  ENCRYPTION_KEY: z.string().min(32).optional(),
  /** Read-endpoint budget. */
  RATE_LIMIT_WINDOW_MS: z.coerce.number().int().positive().default(60_000),
  RATE_LIMIT_MAX_REQUESTS: z.coerce.number().int().positive().default(300),
  /**
   * Scan-creation budget, kept separate because a scan costs minutes of CPU
   * while a read costs a database round trip. Self-hosted CI runners routinely
   * need this far higher than a shared instance would allow.
   */
  RATE_LIMIT_SCAN_WINDOW_MS: z.coerce
    .number()
    .int()
    .positive()
    .default(60 * 60_000),
  RATE_LIMIT_SCAN_MAX: z.coerce.number().int().positive().default(10),
  MAX_UPLOAD_BYTES: z.coerce
    .number()
    .int()
    .positive()
    .default(100 * 1024 * 1024),
  /** Master switch for any scanner egress (advisory lookups). */
  ALLOW_NETWORK_SCANNERS: booleanish.default(false),

  // --- Scan limits ---
  SCAN_MAX_FILES: z.coerce.number().int().positive().default(25_000),
  SCAN_MAX_FILE_BYTES: z.coerce
    .number()
    .int()
    .positive()
    .default(2 * 1024 * 1024),
  SCAN_CONCURRENCY: z.coerce.number().int().positive().max(64).default(8),
  SCAN_TIMEOUT_MS: z.coerce
    .number()
    .int()
    .positive()
    .default(15 * 60_000),
});

export type Env = z.infer<typeof envSchema>;

export interface FeatureFlags {
  postgres: boolean;
  redis: boolean;
  clerk: boolean;
  openrouter: boolean;
  triggerDev: boolean;
  github: boolean;
  networkScanners: boolean;
}

export function featureFlags(env: Env): FeatureFlags {
  return {
    postgres: Boolean(env.DATABASE_URL),
    redis: Boolean(env.REDIS_URL),
    clerk: Boolean(env.CLERK_SECRET_KEY && env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY),
    openrouter: Boolean(env.OPENROUTER_API_KEY) && env.AI_PROVIDER !== 'knowledge-base',
    triggerDev: Boolean(env.TRIGGER_SECRET_KEY),
    github: Boolean(env.GITHUB_TOKEN),
    networkScanners: env.ALLOW_NETWORK_SCANNERS,
  };
}

export class EnvValidationError extends Error {
  constructor(public readonly issues: string[]) {
    super(`Invalid environment configuration:\n${issues.map((i) => `  - ${i}`).join('\n')}`);
    this.name = 'EnvValidationError';
  }
}

/**
 * Production adds requirements that would be hostile during local development —
 * notably an encryption key, without which stored integration tokens would sit
 * in plaintext.
 */
function assertProductionInvariants(env: Env): string[] {
  if (env.NODE_ENV !== 'production') return [];
  const issues: string[] = [];
  if (!env.ENCRYPTION_KEY) {
    issues.push('ENCRYPTION_KEY is required in production to encrypt stored integration tokens');
  }
  if (env.APP_URL.startsWith('http://') && !env.APP_URL.includes('localhost')) {
    issues.push('APP_URL must use HTTPS in production');
  }
  return issues;
}

let cached: Env | undefined;

export function parseEnv(source: NodeJS.ProcessEnv = process.env): Env {
  const result = envSchema.safeParse(source);
  if (!result.success) {
    throw new EnvValidationError(
      result.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`),
    );
  }
  const issues = assertProductionInvariants(result.data);
  if (issues.length) throw new EnvValidationError(issues);
  return result.data;
}

/** Memoized accessor — parse once per process. */
export function getEnv(): Env {
  cached ??= parseEnv();
  return cached;
}

/** Test seam: forget the memoized environment. */
export function resetEnvCache(): void {
  cached = undefined;
}
