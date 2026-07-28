import { z } from 'zod';
import { errors, parseOrThrow } from '@sentinel/core';
import { createAnalyst } from '@sentinel/ai';
import { handle, json, readJsonBody } from '@/lib/api';
import { getScanAnalysis, loadScanForUser } from '@/lib/scan-service';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

type Params = { scanId: string; findingId: string };

/** GET — one finding, with its remediation plan. */
export const GET = handle<Params>(
  async ({ platform, user, params, logger }) => {
    const scan = await loadScanForUser(platform, params.scanId, user.id);
    const finding = scan.findings.find((f) => f.id === params.findingId);
    if (!finding) throw errors.notFound('Finding');

    const analysis = await getScanAnalysis(platform, params.scanId);
    const analyst = createAnalyst({ logger, env: platform.env });

    // The remediation plan is derived on demand rather than stored: it is cheap
    // to compute from the knowledge base and would otherwise bloat every scan.
    const remediation = await analyst.remediate(finding, finding.location?.snippet);

    return json({
      finding,
      priority: analysis.priorities?.find((p) => p.findingId === finding.id),
      remediation,
    });
  },
  { rateLimit: 'read' },
);

const patchSchema = z.object({
  status: z.enum(['open', 'triaged', 'fixed', 'accepted-risk', 'false-positive']),
  note: z.string().max(1000).optional(),
});

/**
 * PATCH — triage a finding.
 *
 * Accepting a risk or marking a false positive is a decision that changes the
 * score, so it requires at least member role and records the reason.
 */
export const PATCH = handle<Params>(
  async ({ platform, user, params, request, logger }) => {
    const scan = await loadScanForUser(platform, params.scanId, user.id);
    const body = parseOrThrow(patchSchema, await readJsonBody(request));

    const updated = await platform.storage.updateFindingStatus(
      scan.id,
      params.findingId,
      body.status,
      body.note,
    );
    if (!updated) throw errors.notFound('Finding');

    await platform.cache.deletePrefix(`scan:${scan.id}`);
    logger.info('Finding triaged', {
      scanId: scan.id,
      findingId: params.findingId,
      status: body.status,
      userId: user.id,
    });

    return json({ finding: updated });
  },
  { rateLimit: 'read' },
);
