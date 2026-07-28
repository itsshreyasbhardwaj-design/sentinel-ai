import { exportFormatSchema, parseOrThrow } from '@sentinel/core';
import { exportReport } from '@sentinel/reports';
import { handle, searchParams } from '@/lib/api';
import { getScanAnalysis, loadScanForUser } from '@/lib/scan-service';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

type Params = { scanId: string };

const DEFAULT_FRAMEWORKS = ['owasp-top-10-2021', 'owasp-llm-top-10-2025', 'nist-ssdf-1.1'];

/**
 * GET /api/scans/{scanId}/export?format=sarif
 *
 * Streams a report in any supported format. The `Content-Disposition` filename
 * is sanitized upstream in `exportReport`, since repository names for archive
 * uploads are entirely user-controlled.
 */
export const GET = handle<Params>(
  async ({ platform, user, params, request }) => {
    const query = searchParams(request);
    const format = parseOrThrow(exportFormatSchema, query.get('format') ?? 'json');

    const scan = await loadScanForUser(platform, params.scanId, user.id);
    const analysis = await getScanAnalysis(platform, params.scanId);

    const report = exportReport(scan, format, {
      ...(analysis.summary ? { summary: analysis.summary } : {}),
      ...(analysis.priorities ? { priorities: analysis.priorities } : {}),
      frameworks: query.getAll('framework') ?? DEFAULT_FRAMEWORKS,
      maxFindings: query.getNumber('maxFindings', 200) ?? 200,
      ...(scan.repository.url
        ? { repoUrlBase: `${scan.repository.url}/blob/${scan.repository.ref ?? 'main'}` }
        : {}),
    });

    const body = typeof report.body === 'string' ? report.body : new Uint8Array(report.body);

    return new Response(body, {
      headers: {
        'content-type': report.contentType,
        // `attachment` is deliberate: rendering an HTML report inline would
        // execute it in this origin.
        'content-disposition': `attachment; filename="${report.filename}"`,
        'x-content-type-options': 'nosniff',
        'content-security-policy': "default-src 'none'; frame-ancestors 'none'",
        'cache-control': 'private, max-age=300',
      },
    }) as never;
  },
  { rateLimit: 'export' },
);
