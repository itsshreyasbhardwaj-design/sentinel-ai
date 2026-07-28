import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { errors, type Logger } from '@sentinel/core';
import { optionalImport } from '../optional-import.js';

/**
 * Authentication and authorization.
 *
 * Clerk when configured, a local development identity otherwise. The local
 * identity is deliberately obvious about what it is — it never pretends to be
 * real auth, and the API surfaces which provider is active so a misconfigured
 * production deployment is visible rather than silently open.
 */

export interface AuthUser {
  id: string;
  email?: string;
  name?: string;
  /** Organization/tenant scope, when the provider supplies one. */
  organizationId?: string;
  role: 'owner' | 'admin' | 'member' | 'viewer';
}

export interface AuthResult {
  user: AuthUser | undefined;
  /** How the caller authenticated. */
  method: 'clerk' | 'api-key' | 'development' | 'none';
}

export interface AuthProvider {
  readonly kind: 'clerk' | 'development';
  /** True when this provider actually verifies identity. */
  readonly enforcing: boolean;
  authenticate(request: Request): Promise<AuthResult>;
}

/* ------------------------------------------------------------------ */
/* API keys                                                            */
/* ------------------------------------------------------------------ */

/**
 * API keys are stored hashed, never in plaintext: the database is the thing
 * most likely to leak, and a stolen key list is a complete compromise.
 */
export function hashApiKey(key: string): string {
  return createHash('sha256').update(key).digest('hex');
}

export function generateApiKey(): { key: string; hash: string } {
  // Prefixed so the value is recognizable in logs and by secret scanners —
  // including our own.
  const key = `sk_sentinel_${randomBytes(24).toString('base64url')}`;
  return { key, hash: hashApiKey(key) };
}

/** Constant-time comparison, so response timing cannot be used to guess a key. */
export function verifyApiKey(candidate: string, storedHash: string): boolean {
  const candidateHash = Buffer.from(hashApiKey(candidate), 'hex');
  const expected = Buffer.from(storedHash, 'hex');
  if (candidateHash.length !== expected.length) return false;
  return timingSafeEqual(candidateHash, expected);
}

/* ------------------------------------------------------------------ */
/* Development provider                                                */
/* ------------------------------------------------------------------ */

export const DEVELOPMENT_USER: AuthUser = {
  id: 'user_local_development',
  email: 'developer@localhost',
  name: 'Local Developer',
  role: 'owner',
};

/**
 * Local identity for development.
 *
 * Refuses to run in production: an unauthenticated security dashboard exposed
 * to the internet would leak every finding for every scanned repository, so
 * this fails loudly at construction rather than serving requests.
 */
export class DevelopmentAuthProvider implements AuthProvider {
  readonly kind = 'development' as const;
  readonly enforcing = false;

  constructor(logger: Logger, nodeEnv: string) {
    if (nodeEnv === 'production') {
      throw errors.internal(
        'Refusing to start: no authentication provider is configured but NODE_ENV=production. Set CLERK_SECRET_KEY and NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY, or run with NODE_ENV=development.',
      );
    }
    logger.warn(
      'Authentication is disabled (development mode). Every request is treated as the local developer.',
    );
  }

  async authenticate(): Promise<AuthResult> {
    return { user: DEVELOPMENT_USER, method: 'development' };
  }
}

/* ------------------------------------------------------------------ */
/* Clerk provider                                                      */
/* ------------------------------------------------------------------ */

export interface ClerkAuthOptions {
  secretKey: string;
  publishableKey: string;
  logger: Logger;
  /** Injected in tests. */
  verifyToken?: (token: string, secretKey: string) => Promise<ClerkClaims | undefined>;
}

export interface ClerkClaims {
  sub: string;
  email?: string;
  name?: string;
  org_id?: string;
  org_role?: string;
  exp?: number;
}

const CLERK_ROLE_MAP: Record<string, AuthUser['role']> = {
  'org:admin': 'admin',
  'org:owner': 'owner',
  'org:member': 'member',
  admin: 'admin',
  owner: 'owner',
  member: 'member',
};

export class ClerkAuthProvider implements AuthProvider {
  readonly kind = 'clerk' as const;
  readonly enforcing = true;

  constructor(private readonly options: ClerkAuthOptions) {}

  async authenticate(request: Request): Promise<AuthResult> {
    const header = request.headers.get('authorization');
    const token = header?.startsWith('Bearer ') ? header.slice(7).trim() : undefined;

    // Clerk's browser SDK sets a session cookie; API clients send a bearer token.
    const cookieToken = readCookie(request.headers.get('cookie'), '__session');
    const candidate = token ?? cookieToken;
    if (!candidate) return { user: undefined, method: 'none' };

    try {
      const verify = this.options.verifyToken ?? defaultVerifyToken;
      const claims = await verify(candidate, this.options.secretKey);
      if (!claims?.sub) return { user: undefined, method: 'none' };

      return {
        user: {
          id: claims.sub,
          ...(claims.email ? { email: claims.email } : {}),
          ...(claims.name ? { name: claims.name } : {}),
          ...(claims.org_id ? { organizationId: claims.org_id } : {}),
          role: CLERK_ROLE_MAP[claims.org_role ?? ''] ?? 'member',
        },
        method: 'clerk',
      };
    } catch (error) {
      this.options.logger.debug('Token verification failed', { error: String(error) });
      return { user: undefined, method: 'none' };
    }
  }
}

/**
 * Verify a Clerk session token.
 *
 * Uses Clerk's backend SDK when installed. If it is not, this returns
 * `undefined` — refusing the request — rather than falling back to decoding the
 * token without verification, which would accept forged sessions.
 */
async function defaultVerifyToken(
  token: string,
  secretKey: string,
): Promise<ClerkClaims | undefined> {
  const { verifyToken } = await optionalImport<{
    verifyToken: (token: string, options: { secretKey: string }) => Promise<ClerkClaims>;
  }>('@clerk/backend', 'Clerk authentication (selected because CLERK_SECRET_KEY is set)');
  return verifyToken(token, { secretKey });
}

function readCookie(header: string | null, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key === name) return decodeURIComponent(rest.join('='));
  }
  return undefined;
}

/* ------------------------------------------------------------------ */
/* Factory and guards                                                  */
/* ------------------------------------------------------------------ */

export interface CreateAuthOptions {
  clerkSecretKey?: string;
  clerkPublishableKey?: string;
  nodeEnv: string;
  logger: Logger;
}

export function createAuthProvider(options: CreateAuthOptions): AuthProvider {
  if (options.clerkSecretKey && options.clerkPublishableKey) {
    options.logger.info('Using Clerk authentication');
    return new ClerkAuthProvider({
      secretKey: options.clerkSecretKey,
      publishableKey: options.clerkPublishableKey,
      logger: options.logger,
    });
  }
  return new DevelopmentAuthProvider(options.logger, options.nodeEnv);
}

/** Throw a typed 401 when there is no authenticated user. */
export function requireUser(result: AuthResult): AuthUser {
  if (!result.user) throw errors.unauthorized();
  return result.user;
}

const ROLE_RANK: Record<AuthUser['role'], number> = {
  viewer: 0,
  member: 1,
  admin: 2,
  owner: 3,
};

export function requireRole(user: AuthUser, minimum: AuthUser['role']): void {
  if (ROLE_RANK[user.role] < ROLE_RANK[minimum]) {
    throw errors.forbidden(`This action requires the ${minimum} role or higher`);
  }
}

/** Ownership check — every project read/write goes through this. */
export function assertOwnership(user: AuthUser, resourceOwnerId: string): void {
  if (user.id === resourceOwnerId) return;
  // An org admin may act on resources owned by their organization.
  if (user.organizationId && resourceOwnerId === user.organizationId && ROLE_RANK[user.role] >= 2) {
    return;
  }
  // Deliberately a 404-shaped 403: confirming a resource exists to someone who
  // cannot see it is itself a disclosure.
  throw errors.notFound('Project');
}
