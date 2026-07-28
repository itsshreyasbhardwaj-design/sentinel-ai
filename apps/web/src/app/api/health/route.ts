import { handle, json } from '@/lib/api';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * GET /api/health
 *
 * Deliberately unauthenticated so load balancers can reach it, and deliberately
 * explicit about *which* implementations are wired up. A deployment that thinks
 * it is using Postgres and Clerk but silently fell back to SQLite and no
 * authentication is exactly the failure this endpoint exists to expose.
 */
export const GET = handle(
  async ({ platform }) => {
    const description = platform.describe();

    return json({
      status: 'ok',
      version: '0.1.0',
      timestamp: new Date().toISOString(),
      components: description,
      warnings: [
        ...(description.authEnforcing
          ? []
          : ['Authentication is not enforced. Configure Clerk before exposing this deployment.']),
        ...(description.networkScanners
          ? []
          : [
              'Network access is disabled; dependency analysis uses the bundled advisory snapshot.',
            ]),
      ],
    });
  },
  { requireAuth: false },
);
