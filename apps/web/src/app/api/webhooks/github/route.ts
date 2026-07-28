import { getPlatform, verifyWebhookSignature } from '@sentinel/platform';
import { SCAN_JOB_TYPE, registerScanHandler, resolveProject } from '@/lib/scan-service';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * POST /api/webhooks/github
 *
 * Outside the normal `handle` pipeline because a webhook authenticates with an
 * HMAC signature rather than a user session, and the raw body must be read
 * before parsing so the signature covers exactly the bytes GitHub signed.
 */

interface PushEvent {
  ref?: string;
  after?: string;
  repository?: {
    name: string;
    owner: { login: string };
    default_branch?: string;
    private?: boolean;
  };
}

interface PullRequestEvent {
  action?: string;
  number?: number;
  pull_request?: { head: { ref: string; sha: string }; base: { ref: string } };
  repository?: { name: string; owner: { login: string }; private?: boolean };
}

export async function POST(request: Request): Promise<Response> {
  const platform = await getPlatform();
  const logger = platform.logger.child({ route: 'webhooks/github' });

  const secret = platform.env.GITHUB_WEBHOOK_SECRET;
  if (!secret) {
    logger.warn('GitHub webhook received but GITHUB_WEBHOOK_SECRET is not configured');
    return Response.json(
      { error: { code: 'FORBIDDEN', message: 'Webhooks are not configured on this deployment' } },
      { status: 403 },
    );
  }

  // Read the raw text first — re-serializing parsed JSON would change the bytes
  // and break signature verification.
  const body = await request.text();

  const valid = await verifyWebhookSignature(
    body,
    request.headers.get('x-hub-signature-256'),
    secret,
  );
  if (!valid) {
    logger.warn('Rejected GitHub webhook with an invalid signature');
    return Response.json(
      { error: { code: 'UNAUTHORIZED', message: 'Invalid signature' } },
      { status: 401 },
    );
  }

  const event = request.headers.get('x-github-event') ?? 'unknown';
  const deliveryId = request.headers.get('x-github-delivery') ?? 'unknown';

  // GitHub retries deliveries; ignoring a repeat is cheaper than scanning twice.
  const seenKey = `webhook:github:${deliveryId}`;
  if (await platform.cache.get(seenKey)) {
    return Response.json({ ok: true, deduplicated: true });
  }
  await platform.cache.set(seenKey, true, 3600);

  if (event === 'ping') return Response.json({ ok: true, pong: true });

  let payload: PushEvent & PullRequestEvent;
  try {
    payload = JSON.parse(body);
  } catch {
    return Response.json(
      { error: { code: 'VALIDATION_ERROR', message: 'Body is not valid JSON' } },
      { status: 400 },
    );
  }

  const repository = payload.repository;
  if (!repository?.owner?.login || !repository.name) {
    return Response.json({ ok: true, ignored: 'no repository in payload' });
  }

  /* Decide whether this event warrants a scan. */
  let ref: string | undefined;

  if (event === 'push') {
    // Only branch pushes; tag and branch-delete events carry no scannable state.
    if (!payload.ref?.startsWith('refs/heads/')) {
      return Response.json({ ok: true, ignored: 'not a branch push' });
    }
    ref = payload.ref.replace('refs/heads/', '');
  } else if (event === 'pull_request') {
    if (!['opened', 'synchronize', 'reopened'].includes(payload.action ?? '')) {
      return Response.json({ ok: true, ignored: `pull_request action "${payload.action}"` });
    }
    ref = payload.pull_request?.head.ref;
  } else {
    return Response.json({ ok: true, ignored: `event "${event}"` });
  }

  if (!ref) return Response.json({ ok: true, ignored: 'no ref resolved' });

  // Private repositories need a token; without one the clone fails with a
  // confusing error, so decline explicitly instead.
  if (repository.private && !platform.env.GITHUB_TOKEN) {
    logger.warn('Skipping private repository scan: GITHUB_TOKEN is not configured', {
      repo: `${repository.owner.login}/${repository.name}`,
    });
    return Response.json({
      ok: true,
      ignored: 'private repository and no GITHUB_TOKEN configured',
    });
  }

  try {
    registerScanHandler(platform);

    const target = {
      type: 'github' as const,
      owner: repository.owner.login,
      repo: repository.name,
      ref,
      ...(platform.env.GITHUB_TOKEN ? { token: platform.env.GITHUB_TOKEN } : {}),
    };

    // Webhook-initiated scans are attributed to a system identity: there is no
    // authenticated user behind them.
    const ownerId = `github:${repository.owner.login}`;
    const project = await resolveProject(platform, ownerId, target);

    const job = await platform.queue.enqueue(SCAN_JOB_TYPE, {
      projectId: project.id,
      target,
      ownerId,
      options: {
        maxFiles: platform.env.SCAN_MAX_FILES,
        maxFileSizeBytes: platform.env.SCAN_MAX_FILE_BYTES,
        concurrency: platform.env.SCAN_CONCURRENCY,
        timeoutMs: platform.env.SCAN_TIMEOUT_MS,
        allowNetwork: platform.env.ALLOW_NETWORK_SCANNERS,
      },
    });

    logger.info('Webhook scan enqueued', {
      event,
      jobId: job.id,
      repo: `${repository.owner.login}/${repository.name}`,
      ref,
    });

    return Response.json({ ok: true, jobId: job.id, projectId: project.id });
  } catch (error) {
    // Always 200 on internal failure: a non-2xx makes GitHub retry and
    // eventually disable the webhook, which is worse than a missed scan.
    logger.error('Failed to enqueue webhook scan', { error: String(error) });
    return Response.json({ ok: false, error: 'Failed to enqueue scan' });
  }
}
