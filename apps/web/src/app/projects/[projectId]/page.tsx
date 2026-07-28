import Link from 'next/link';
import { cache } from 'react';
import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { ArrowRight, Plus, TrendingDown, TrendingUp } from 'lucide-react';
import { summarizeTrend } from '@sentinel/core';
import { getPlatform } from '@sentinel/platform';
import { Badge, Card, CardContent, EmptyState, ScoreRing, Stat } from '@/components/primitives';
import { TrendChart } from '@/components/trend-sparkline';
import { CATEGORY_LABEL, formatDuration, formatNumber, relativeTime, scoreColor } from '@/lib/ui';

export const dynamic = 'force-dynamic';

/** Deduplicated per request; shared with `generateMetadata`. */
const loadProject = cache(async (projectId: string) => {
  const platform = await getPlatform();
  return platform.storage.getProject(projectId);
});

/**
 * Checked here so a missing project returns a real 404. See the scan page for
 * why the component body alone is not enough once the response is streaming.
 */
export async function generateMetadata({
  params,
}: {
  params: Promise<{ projectId: string }>;
}): Promise<Metadata> {
  const { projectId } = await params;
  const project = await loadProject(projectId);
  if (!project) notFound();
  return { title: project.name };
}

/**
 * Project detail: posture over time.
 *
 * The single-scan view answers "what is wrong now". This one answers "are we
 * getting better", which is the question that actually drives behaviour.
 */
export default async function ProjectPage({ params }: { params: Promise<{ projectId: string }> }) {
  const { projectId } = await params;
  const platform = await getPlatform();

  const project = await loadProject(projectId);
  if (!project) notFound();

  const [latest, scans, history] = await Promise.all([
    platform.storage.getLatestScan(project.id),
    platform.storage.listScans({ projectId: project.id, limit: 20 }),
    platform.storage.getScoreHistory(project.id, 60),
  ]);

  const trend = summarizeTrend(history);
  const open = latest?.findings.filter((f) => !f.suppressed) ?? [];

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{project.name}</h1>
          <p className="mt-1 text-[13px] text-[var(--color-fg-subtle)]">
            {project.target.type === 'github'
              ? `${project.target.owner}/${project.target.repo}`
              : project.target.type}{' '}
            · created {relativeTime(project.createdAt)}
          </p>
        </div>
        <Link
          href="/scan"
          className="inline-flex h-9 items-center gap-2 rounded-lg bg-[var(--color-accent)] px-4 text-[13px] font-medium text-white transition-colors hover:bg-[var(--color-accent-hover)]"
        >
          <Plus className="h-3.5 w-3.5" aria-hidden="true" />
          New scan
        </Link>
      </div>

      {!latest ? (
        <Card>
          <EmptyState
            title="No completed scans yet"
            description="Run a scan to establish this project's baseline security posture."
          />
        </Card>
      ) : (
        <>
          <div className="grid gap-3 lg:grid-cols-[auto_1fr]">
            <Card className="flex items-center justify-center p-6">
              <ScoreRing score={latest.scores.overall} grade={latest.scores.grade} size={132} />
            </Card>

            <Card>
              <CardContent className="pt-5">
                <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                  <h2 className="text-[13px] font-medium text-[var(--color-fg-muted)]">
                    Score history
                  </h2>
                  {trend.direction !== 'stable' && (
                    <span
                      className="inline-flex items-center gap-1.5 text-[12px] font-medium"
                      style={{
                        color:
                          trend.direction === 'improving'
                            ? 'var(--color-success)'
                            : 'var(--color-critical)',
                      }}
                    >
                      {trend.direction === 'improving' ? (
                        <TrendingUp className="h-3.5 w-3.5" aria-hidden="true" />
                      ) : (
                        <TrendingDown className="h-3.5 w-3.5" aria-hidden="true" />
                      )}
                      {trend.delta > 0 ? '+' : ''}
                      {trend.delta} points across {history.length} scans
                    </span>
                  )}
                </div>
                <TrendChart points={history} height={180} />
              </CardContent>
            </Card>
          </div>

          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Stat value={formatNumber(open.length)} label="Open findings" />
            <Stat
              value={formatNumber(open.filter((f) => f.severity === 'critical').length)}
              label="Critical"
              tone={
                open.some((f) => f.severity === 'critical') ? 'var(--color-critical)' : undefined
              }
            />
            <Stat value={formatNumber(scans.total)} label="Scans run" />
            <Stat value={formatNumber(latest.repository.fileCount)} label="Files" />
          </div>

          <section>
            <h2 className="mb-3 text-sm font-medium text-[var(--color-fg-muted)]">
              Category breakdown
            </h2>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {latest.scores.categories.map((category) => (
                <Card key={category.category} className="p-4">
                  <div className="flex items-baseline justify-between">
                    <span className="text-[13px] font-medium">
                      {CATEGORY_LABEL[category.category] ?? category.category}
                    </span>
                    <span
                      className="text-[15px] font-semibold tabular-nums"
                      style={{
                        color: category.analyzed
                          ? scoreColor(category.score)
                          : 'var(--color-fg-subtle)',
                      }}
                    >
                      {category.analyzed ? category.score : '—'}
                    </span>
                  </div>
                  <p className="mt-2 text-[12px] text-[var(--color-fg-subtle)]">
                    {category.rationale}
                  </p>
                </Card>
              ))}
            </div>
          </section>

          <section>
            <h2 className="mb-3 text-sm font-medium text-[var(--color-fg-muted)]">Scan history</h2>
            <div className="space-y-2">
              {scans.items.map((scan) => (
                <Link
                  key={scan.id}
                  href={`/scans/${scan.id}`}
                  className="group flex flex-wrap items-center gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-3 transition-colors hover:bg-[var(--color-surface-raised)]"
                >
                  <span
                    className="text-[15px] font-semibold tabular-nums"
                    style={{ color: scoreColor(scan.scores.overall) }}
                  >
                    {scan.scores.overall}
                  </span>
                  <Badge tone={scan.status === 'completed' ? 'neutral' : 'warning'}>
                    {scan.status}
                  </Badge>
                  <span className="text-[13px] text-[var(--color-fg-muted)]">
                    {formatNumber(scan.findingCount)} findings
                  </span>
                  <span className="text-[12.5px] text-[var(--color-fg-subtle)]">
                    {formatDuration(scan.durationMs)}
                  </span>
                  <span className="ml-auto text-[12.5px] text-[var(--color-fg-subtle)]">
                    {relativeTime(scan.completedAt ?? scan.startedAt)}
                  </span>
                  <ArrowRight
                    className="h-4 w-4 text-[var(--color-fg-subtle)] transition-transform group-hover:translate-x-0.5"
                    aria-hidden="true"
                  />
                </Link>
              ))}
            </div>
          </section>
        </>
      )}
    </div>
  );
}
