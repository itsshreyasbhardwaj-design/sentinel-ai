import { errors } from '@sentinel/core';
import { handle, json } from '@/lib/api';
import { getScanAnalysis, loadScanForUser } from '@/lib/scan-service';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

type Params = { scanId: string };

/** GET /api/scans/{scanId} — the full scan result with its AI analysis. */
export const GET = handle<Params>(
  async ({ platform, user, params }) => {
    const scan = await loadScanForUser(platform, params.scanId, user.id);
    const analysis = await getScanAnalysis(platform, params.scanId);

    return json({
      scan,
      summary: analysis.summary,
      priorities: analysis.priorities,
    });
  },
  { rateLimit: 'read' },
);

/** DELETE /api/scans/{scanId} */
export const DELETE = handle<Params>(
  async ({ platform, user, params, logger }) => {
    // Load first so ownership is enforced before anything is destroyed.
    const scan = await loadScanForUser(platform, params.scanId, user.id);

    const deleted = await platform.storage.deleteScan(scan.id);
    if (!deleted) throw errors.notFound('Scan');

    await platform.cache.deletePrefix(`scan:${scan.id}`);
    await platform.cache.deletePrefix(`project:${scan.projectId}`);
    logger.info('Scan deleted', { scanId: scan.id });

    return json({ deleted: true, scanId: scan.id });
  },
  { rateLimit: 'read' },
);
