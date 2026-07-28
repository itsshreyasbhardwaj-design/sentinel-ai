import { toStatistics } from '@sentinel/reports';
import { handle, json } from '@/lib/api';
import { getScanAnalysis, loadScanForUser } from '@/lib/scan-service';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

type Params = { scanId: string };

/** GET /api/scans/{scanId}/stats — aggregates for the dashboard and API clients. */
export const GET = handle<Params>(
  async ({ platform, user, params }) => {
    const scan = await loadScanForUser(platform, params.scanId, user.id);
    const analysis = await getScanAnalysis(platform, params.scanId);

    return json({
      ...toStatistics(scan),
      summary: analysis.summary,
      // The ten highest-priority items, which is what a dashboard actually shows.
      topPriorities: (analysis.priorities ?? []).slice(0, 10),
    });
  },
  { rateLimit: 'read' },
);
