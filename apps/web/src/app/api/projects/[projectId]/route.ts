import { errors } from '@sentinel/core';
import type { Platform } from '@sentinel/platform';
import { handle, json } from '@/lib/api';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

type Params = { projectId: string };

/** Ownership is checked before any read, and refused as 404 to avoid disclosure. */
async function loadOwnedProject(platform: Platform, projectId: string, userId: string) {
  const project = await platform.storage.getProject(projectId);
  if (!project || project.ownerId !== userId) throw errors.notFound('Project');
  return project;
}

export const GET = handle<Params>(
  async ({ platform, user, params }) => {
    const project = await loadOwnedProject(platform, params.projectId, user.id);

    const [latest, scans, history] = await Promise.all([
      platform.storage.getLatestScan(project.id),
      platform.storage.listScans({ projectId: project.id, limit: 20 }),
      platform.storage.getScoreHistory(project.id, 60),
    ]);

    return json({ project, latestScan: latest, scans, trend: history });
  },
  { rateLimit: 'read' },
);

export const DELETE = handle<Params>(
  async ({ platform, user, params, logger }) => {
    const project = await loadOwnedProject(platform, params.projectId, user.id);
    await platform.storage.deleteProject(project.id);
    await platform.cache.deletePrefix(`project:${project.id}`);
    logger.info('Project deleted', { projectId: project.id });
    return json({ deleted: true, projectId: project.id });
  },
  { rateLimit: 'read' },
);
