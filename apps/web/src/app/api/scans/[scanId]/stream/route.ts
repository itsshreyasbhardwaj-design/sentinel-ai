import { errors } from '@sentinel/core';
import { getPlatform } from '@sentinel/platform';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * GET /api/scans/{jobId}/stream — server-sent progress events.
 *
 * SSE rather than WebSockets: progress is one-directional, SSE reconnects
 * automatically, and it survives the HTTP/1.1 proxies that sit in front of most
 * deployments without a protocol upgrade.
 *
 * Deliberately outside the `handle` wrapper because it returns a streaming body
 * rather than a JSON response, and needs its own lifecycle handling.
 */
export async function GET(
  request: Request,
  context: { params: Promise<{ scanId: string }> },
): Promise<Response> {
  const platform = await getPlatform();
  const { scanId: jobId } = await context.params;

  const auth = await platform.auth.authenticate(request);
  if (!auth.user) {
    return Response.json(
      { error: { code: 'UNAUTHORIZED', message: 'Authentication required' } },
      { status: 401 },
    );
  }

  const job = await platform.queue.get(jobId);
  if (!job || job.ownerId !== auth.user.id) {
    const error = errors.notFound('Job');
    return Response.json(error.toJSON(), { status: error.status });
  }

  const encoder = new TextEncoder();
  let heartbeat: NodeJS.Timeout | undefined;

  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const send = (event: string, data: unknown) => {
        try {
          controller.enqueue(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
        } catch {
          // The client disconnected between the check and the write.
        }
      };

      // Proxies and load balancers commonly close an idle connection at 30-60s;
      // a comment frame keeps it open without emitting a spurious event.
      heartbeat = setInterval(() => {
        try {
          controller.enqueue(encoder.encode(': keepalive\n\n'));
        } catch {
          /* closed */
        }
      }, 15_000);
      heartbeat.unref?.();

      send('status', { jobId, status: job.status });

      try {
        for await (const progress of platform.queue.subscribe(jobId)) {
          if (request.signal.aborted) break;
          send('progress', progress);
        }

        const final = await platform.queue.get(jobId);
        send('done', {
          jobId,
          status: final?.status ?? 'completed',
          result: final?.result,
          error: final?.error,
        });
      } catch (error) {
        send('error', { message: String(error) });
      } finally {
        if (heartbeat) clearInterval(heartbeat);
        try {
          controller.close();
        } catch {
          /* already closed */
        }
      }
    },
    cancel() {
      // The client navigated away; stop the heartbeat so the timer is not leaked.
      if (heartbeat) clearInterval(heartbeat);
    },
  });

  return new Response(stream, {
    headers: {
      'content-type': 'text/event-stream; charset=utf-8',
      'cache-control': 'no-cache, no-transform',
      connection: 'keep-alive',
      // Nginx buffers proxied responses by default, which would defeat streaming.
      'x-accel-buffering': 'no',
    },
  });
}
