import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { errors, validateArchiveUpload } from '@sentinel/core';
import type { Platform } from '@sentinel/platform';
import { handle, json } from '@/lib/api';
import { SCAN_JOB_TYPE, registerScanHandler, resolveProject } from '@/lib/scan-service';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * POST /api/upload — scan an uploaded ZIP archive.
 *
 * The most attacker-reachable endpoint in the product: the client chooses every
 * byte. Validation is layered — declared size, filename, magic bytes here, then
 * per-entry path and zip-bomb checks during extraction — and the file is written
 * to a fresh temporary directory that is removed when the scan finishes.
 */
export const POST = handle(
  async ({ platform, user, logger, request }) => {
    const contentType = request.headers.get('content-type') ?? '';
    if (!contentType.includes('multipart/form-data')) {
      throw errors.validation('Expected a multipart/form-data upload');
    }

    // Reject on the declared length before reading the body into memory.
    const declaredLength = Number(request.headers.get('content-length') ?? 0);
    if (declaredLength > platform.env.MAX_UPLOAD_BYTES) {
      throw errors.tooLarge(
        `Upload exceeds the ${Math.round(platform.env.MAX_UPLOAD_BYTES / 1024 / 1024)}MB limit`,
      );
    }

    const form = await request.formData();
    const file = form.get('file');
    if (!(file instanceof File))
      throw errors.validation('No file was provided in the "file" field');

    const buffer = Buffer.from(await file.arrayBuffer());

    validateArchiveUpload({
      maxBytes: platform.env.MAX_UPLOAD_BYTES,
      filename: file.name,
      size: buffer.length,
      // Content sniffing: the extension and Content-Type are both client-controlled.
      head: buffer.subarray(0, 8),
    });

    const workDir = await mkdtemp(join(tmpdir(), 'sentinel-upload-'));
    const archivePath = join(workDir, 'upload.zip');
    await writeFile(archivePath, buffer);

    try {
      registerScanHandler(platform);

      const target = {
        type: 'archive' as const,
        archivePath,
        originalName: file.name.replace(/[^\w.-]/g, '_').slice(0, 200),
      };

      const project = await resolveProject(
        platform,
        user.id,
        target,
        (form.get('projectId') as string | null) ?? undefined,
        (form.get('name') as string | null) ?? undefined,
      );

      const job = await platform.queue.enqueue(SCAN_JOB_TYPE, {
        projectId: project.id,
        target,
        ownerId: user.id,
        options: {
          maxFiles: platform.env.SCAN_MAX_FILES,
          maxFileSizeBytes: platform.env.SCAN_MAX_FILE_BYTES,
          concurrency: platform.env.SCAN_CONCURRENCY,
          timeoutMs: platform.env.SCAN_TIMEOUT_MS,
          allowNetwork: platform.env.ALLOW_NETWORK_SCANNERS,
        },
      }, user.id);

      logger.info('Archive upload accepted', {
        jobId: job.id,
        bytes: buffer.length,
        projectId: project.id,
      });

      // The extracted workspace is cleaned up by the engine; the uploaded
      // archive itself is removed once the job leaves the queue.
      void cleanupWhenSettled(platform, job.id, workDir);

      return json(
        {
          jobId: job.id,
          status: job.status,
          project: { id: project.id, name: project.name, slug: project.slug },
        },
        { status: 202 },
      );
    } catch (error) {
      await rm(workDir, { recursive: true, force: true }).catch(() => {});
      throw error;
    }
  },
  { rateLimit: 'upload' },
);

/** Poll until the job settles, then remove the uploaded archive. */
async function cleanupWhenSettled(
  platform: Platform,
  jobId: string,
  workDir: string,
): Promise<void> {
  const deadline = Date.now() + platform.env.SCAN_TIMEOUT_MS + 60_000;

  while (Date.now() < deadline) {
    const job = await platform.queue.get(jobId);
    if (!job || ['completed', 'failed', 'cancelled'].includes(job.status)) break;
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }

  await rm(workDir, { recursive: true, force: true }).catch(() => {});
}
