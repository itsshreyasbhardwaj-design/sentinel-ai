import { z } from 'zod';
import { newId, parseOrThrow, scanTargetSchema, summarizeTrend } from '@sentinel/core';
import { handle, json, readJsonBody } from '@/lib/api';
import { slugify } from '@/lib/scan-service';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/** GET /api/projects — the caller's projects with their latest posture. */
export const GET = handle(
  async ({ platform, user }) => {
    const projects = await platform.storage.listProjects(user.id);

    const summaries = await Promise.all(
      projects.map(async (project) => {
        const [latest, history] = await Promise.all([
          platform.storage.getLatestScan(project.id),
          platform.storage.getScoreHistory(project.id, 30),
        ]);

        const open = latest?.findings.filter((f) => !f.suppressed) ?? [];

        return {
          ...project,
          latestScores: latest?.scores,
          lastScannedAt: latest?.completedAt,
          openFindings: open.length,
          criticalFindings: open.filter((f) => f.severity === 'critical').length,
          trend: history,
          trendSummary: summarizeTrend(history),
        };
      }),
    );

    return json({ items: summaries, total: summaries.length });
  },
  { rateLimit: 'read' },
);

const createProjectSchema = z.object({
  name: z.string().min(1).max(120),
  description: z.string().max(500).optional(),
  target: scanTargetSchema,
});

/** POST /api/projects */
export const POST = handle(
  async ({ platform, user, request }) => {
    const input = parseOrThrow(createProjectSchema, await readJsonBody(request));
    const slug = slugify(input.name);

    const existing = await platform.storage.getProjectBySlug(user.id, slug);
    if (existing) {
      const { errors } = await import('@sentinel/core');
      throw errors.conflict(`A project with the slug "${slug}" already exists`);
    }

    const now = new Date().toISOString();
    const project = await platform.storage.createProject({
      id: newId('proj'),
      name: input.name,
      slug,
      ownerId: user.id,
      target: input.target,
      ...(input.description ? { description: input.description } : {}),
      createdAt: now,
      updatedAt: now,
    });

    return json({ project }, { status: 201 });
  },
  { rateLimit: 'read' },
);
