import {
  SCAN_KINDS,
  SEVERITIES,
  filterFindings,
  sortFindings,
  type ScanKind,
  type Severity,
} from '@sentinel/core';
import { handle, json, searchParams } from '@/lib/api';
import { getScanAnalysis, loadScanForUser } from '@/lib/scan-service';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

type Params = { scanId: string };

/** Only accept values from the known enums — an unknown filter must not 500. */
function narrow<T extends string>(
  values: string[] | undefined,
  allowed: readonly T[],
): T[] | undefined {
  if (!values?.length) return undefined;
  const filtered = values.filter((value): value is T =>
    (allowed as readonly string[]).includes(value),
  );
  return filtered.length ? filtered : undefined;
}

/**
 * GET /api/scans/{scanId}/findings
 *
 * Filtered, sorted and paginated. Priority order is used when the AI analysis
 * is available, falling back to risk score so the ordering is always
 * meaningful.
 */
export const GET = handle<Params>(
  async ({ platform, user, params, request }) => {
    const query = searchParams(request);
    const scan = await loadScanForUser(platform, params.scanId, user.id);
    const analysis = await getScanAnalysis(platform, params.scanId);

    const limit = Math.min(query.getNumber('limit', 50) ?? 50, 500);
    const offset = Math.max(0, query.getNumber('offset', 0) ?? 0);

    const filtered = filterFindings(scan.findings, {
      ...(narrow<Severity>(query.getAll('severity'), SEVERITIES)
        ? { severity: narrow<Severity>(query.getAll('severity'), SEVERITIES)! }
        : {}),
      ...(narrow<ScanKind>(query.getAll('kind'), SCAN_KINDS)
        ? { kind: narrow<ScanKind>(query.getAll('kind'), SCAN_KINDS)! }
        : {}),
      ...(query.getAll('status') ? { status: query.getAll('status')! } : {}),
      ...(query.getAll('scanner') ? { scanner: query.getAll('scanner')! } : {}),
      ...(query.get('search') ? { search: query.get('search')! } : {}),
      ...(query.get('path') ? { path: query.get('path')! } : {}),
      ...(query.getBoolean('suppressed') !== undefined
        ? { suppressed: query.getBoolean('suppressed')! }
        : {}),
    });

    const priorityById = new Map((analysis.priorities ?? []).map((p) => [p.findingId, p]));
    const ordered = analysis.priorities?.length
      ? [...filtered].sort(
          (a, b) =>
            (priorityById.get(b.id)?.priorityScore ?? b.riskScore) -
            (priorityById.get(a.id)?.priorityScore ?? a.riskScore),
        )
      : sortFindings(filtered);

    return json({
      items: ordered.slice(offset, offset + limit).map((finding) => ({
        ...finding,
        priority: priorityById.get(finding.id),
      })),
      total: ordered.length,
      limit,
      offset,
      // Counts over the *unfiltered* set, so the filter UI can show what is
      // available rather than only what is currently selected.
      facets: {
        severity: countBy(scan.findings, (f) => f.severity),
        kind: countBy(scan.findings, (f) => f.kind),
        scanner: countBy(scan.findings, (f) => f.scanner),
        status: countBy(scan.findings, (f) => f.status),
      },
    });
  },
  { rateLimit: 'read' },
);

function countBy<T>(items: readonly T[], key: (item: T) => string): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const item of items) {
    const value = key(item);
    counts[value] = (counts[value] ?? 0) + 1;
  }
  return counts;
}
