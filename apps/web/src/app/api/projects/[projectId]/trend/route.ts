import { errors, summarizeTrend } from '@sentinel/core';
import { handle, json, searchParams } from '@/lib/api';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

type Params = { projectId: string };

/** GET /api/projects/{id}/trend — score history for the trend chart. */
export const GET = handle<Params>(
  async ({ platform, user, params, request }) => {
    const query = searchParams(request);
    const project = await platform.storage.getProject(params.projectId);
    if (!project || project.ownerId !== user.id) throw errors.notFound('Project');

    const history = await platform.storage.getScoreHistory(
      project.id,
      Math.min(query.getNumber('limit', 60) ?? 60, 365),
    );

    return json({ projectId: project.id, points: history, summary: summarizeTrend(history) });
  },
  { rateLimit: 'read' },
);
