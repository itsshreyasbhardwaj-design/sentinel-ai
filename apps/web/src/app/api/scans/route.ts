import { createScanSchema, parseOrThrow, errors } from '@sentinel/core';
import { handle, json, readJsonBody, searchParams } from '@/lib/api';
import { SCAN_JOB_TYPE, registerScanHandler, resolveProject } from '@/lib/scan-service';

export const runtime = 'nodejs';
// Scans are long-running and stateful; nothing about this route is cacheable.
export const dynamic = 'force-dynamic';

/**
 * POST /api/scans — start a scan.
 *
 * Returns 202 with a job id rather than blocking: a scan can take minutes, and
 * holding the connection open for that would fail behind most proxies. The
 * client follows progress on `/api/scans/{id}/stream`.
 */
export const POST = handle(
  async ({ platform, user, logger, request }) => {
    const body = await readJsonBody(request);
    const input = parseOrThrow(createScanSchema, body);

    // A hosted deployment must never scan arbitrary host paths on request.
    if (input.target.type === 'local' && platform.env.NODE_ENV === 'production') {
      throw errors.forbidden(
        'Local path scanning is disabled in this deployment. Use a GitHub repository or upload an archive.',
      );
    }

    registerScanHandler(platform);

    const project = await resolveProject(
      platform,
      user.id,
      input.target,
      input.projectId,
      input.name,
    );

    const job = await platform.queue.enqueue(SCAN_JOB_TYPE, {
      projectId: project.id,
      target: input.target,
      ownerId: user.id,
      options: {
        // Deployment-wide limits always win over per-request options, so a
        // client cannot ask for an unbounded scan.
        maxFiles: platform.env.SCAN_MAX_FILES,
        maxFileSizeBytes: platform.env.SCAN_MAX_FILE_BYTES,
        concurrency: platform.env.SCAN_CONCURRENCY,
        timeoutMs: platform.env.SCAN_TIMEOUT_MS,
        ...input.options,
        allowNetwork: platform.env.ALLOW_NETWORK_SCANNERS && (input.options?.allowNetwork ?? true),
      },
    }, user.id);

    logger.info('Scan enqueued', {
      jobId: job.id,
      projectId: project.id,
      target: input.target.type,
    });

    return json(
      {
        jobId: job.id,
        status: job.status,
        project: { id: project.id, name: project.name, slug: project.slug },
        links: {
          progress: `/api/scans/stream?jobId=${job.id}`,
          job: `/api/scans?jobId=${job.id}`,
        },
      },
      { status: 202 },
    );
  },
  { rateLimit: 'createScan' },
);

/**
 * GET /api/scans — list scans, or poll a job when `jobId` is supplied.
 */
export const GET = handle(
  async ({ platform, user, request }) => {
    const params = searchParams(request);
    const jobId = params.get('jobId');

    if (jobId) {
      const job = await platform.queue.get(jobId);
      if (!job || job.ownerId !== user.id) throw errors.notFound('Job');

      return json({
        jobId: job.id,
        status: job.status,
        progress: job.progress,
        error: job.error,
        result: job.result,
      });
    }

    const projectId = params.get('projectId');
    if (projectId) {
      const project = await platform.storage.getProject(projectId);
      if (!project || project.ownerId !== user.id) throw errors.notFound('Project');
    }

    const scans = await platform.storage.listScans({
      ...(projectId ? { projectId } : {}),
      limit: params.getNumber('limit', 20),
      offset: params.getNumber('offset', 0),
    });

    // Without a project filter, restrict to the caller's own projects.
    if (!projectId) {
      const owned = new Set((await platform.storage.listProjects(user.id)).map((p) => p.id));
      scans.items = scans.items.filter((scan) => owned.has(scan.projectId));
    }

    return json(scans);
  },
  { rateLimit: 'read' },
);
