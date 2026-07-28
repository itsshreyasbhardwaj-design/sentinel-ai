import { FRAMEWORKS, assessCompliance, errors, getFramework, type ScanKind } from '@sentinel/core';
import { handle, json, searchParams } from '@/lib/api';
import { loadScanForUser } from '@/lib/scan-service';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

type Params = { scanId: string };

/**
 * GET /api/scans/{scanId}/compliance
 *
 * Assessed against the domains the scan actually covered, so a control is never
 * reported as passing because it was simply never evaluated.
 */
export const GET = handle<Params>(
  async ({ platform, user, params, request }) => {
    const query = searchParams(request);
    const scan = await loadScanForUser(platform, params.scanId, user.id);

    const requested = query.getAll('framework');
    const frameworks = requested?.length
      ? requested.map((id) => {
          const framework = getFramework(id);
          if (!framework) throw errors.validation(`Unknown compliance framework: ${id}`);
          return framework;
        })
      : FRAMEWORKS;

    const analyzedKinds = [
      ...new Set(scan.scannerRuns.filter((run) => run.status === 'ok').map((run) => run.kind)),
    ] as ScanKind[];

    return json({
      scanId: scan.id,
      analyzedKinds,
      reports: frameworks.map((framework) =>
        assessCompliance(framework, scan.findings, scan.id, analyzedKinds),
      ),
      available: FRAMEWORKS.map((f) => ({
        id: f.id,
        name: f.name,
        version: f.version,
        description: f.description,
        controls: f.controls.length,
      })),
    });
  },
  { rateLimit: 'read' },
);
