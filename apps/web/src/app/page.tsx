import Link from 'next/link';
import {
  AlertTriangle,
  FolderGit2,
  Plus,
  ShieldCheck,
  TrendingDown,
  TrendingUp,
} from 'lucide-react';
import {
  summarizeTrend,
  type Project,
  type ScoreHistoryPoint,
  type HealthScores,
} from '@sentinel/core';
import { getPlatform } from '@sentinel/platform';
import { Badge, Card, EmptyState, ScoreRing, Stat } from '@/components/primitives';
import { TrendSparkline } from '@/components/trend-sparkline';
import { formatNumber, relativeTime } from '@/lib/ui';

export const dynamic = 'force-dynamic';

interface ProjectRow {
  project: Project;
  scores?: HealthScores;
  openFindings: number;
  criticalFindings: number;
  lastScannedAt?: string;
  trend: ScoreHistoryPoint[];
}

/**
 * Overview.
 *
 * Rendered on the server so the first paint already contains real data — a
 * dashboard that flashes skeletons before showing a security score trains
 * people to ignore it.
 */
async function loadOverview(): Promise<{ rows: ProjectRow[]; authEnforcing: boolean }> {
  const platform = await getPlatform();

  // The development identity is the only user in an unauthenticated deployment.
  const ownerId = platform.auth.enforcing ? undefined : 'user_local_development';
  const projects = ownerId ? await platform.storage.listProjects(ownerId) : [];

  const rows = await Promise.all(
    projects.map(async (project) => {
      const [latest, trend] = await Promise.all([
        platform.storage.getLatestScan(project.id),
        platform.storage.getScoreHistory(project.id, 30),
      ]);
      const open = latest?.findings.filter((f) => !f.suppressed) ?? [];

      return {
        project,
        scores: latest?.scores,
        openFindings: open.length,
        criticalFindings: open.filter((f) => f.severity === 'critical').length,
        lastScannedAt: latest?.completedAt,
        trend,
      };
    }),
  );

  rows.sort((a, b) => (a.scores?.overall ?? 101) - (b.scores?.overall ?? 101));
  return { rows, authEnforcing: platform.auth.enforcing };
}

export default async function OverviewPage() {
  const { rows, authEnforcing } = await loadOverview();

  const scanned = rows.filter((row) => row.scores);
  const totalOpen = rows.reduce((sum, row) => sum + row.openFindings, 0);
  const totalCritical = rows.reduce((sum, row) => sum + row.criticalFindings, 0);
  const averageScore = scanned.length
    ? Math.round(scanned.reduce((sum, row) => sum + (row.scores?.overall ?? 0), 0) / scanned.length)
    : undefined;

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Security overview</h1>
          <p className="mt-1 text-sm text-[var(--color-fg-subtle)]">
            {rows.length
              ? `${rows.length} ${rows.length === 1 ? 'project' : 'projects'} monitored`
              : 'No projects scanned yet'}
          </p>
        </div>
        <Link
          href="/scan"
          className="inline-flex h-10 items-center gap-2 rounded-lg bg-[var(--color-accent)] px-4 text-sm font-medium text-white transition-colors hover:bg-[var(--color-accent-hover)]"
        >
          <Plus className="h-4 w-4" aria-hidden="true" />
          New scan
        </Link>
      </div>

      {!authEnforcing && (
        <div className="flex items-start gap-3 rounded-lg border border-[var(--color-high)]/30 bg-[var(--color-high)]/8 px-4 py-3">
          <AlertTriangle
            className="mt-0.5 h-4 w-4 shrink-0 text-[var(--color-high)]"
            aria-hidden="true"
          />
          <div className="text-[13px]">
            <span className="font-medium text-[var(--color-high)]">
              Authentication is not enforced.
            </span>{' '}
            <span className="text-[var(--color-fg-muted)]">
              This deployment treats every request as the local developer. Configure Clerk before
              exposing it beyond localhost.
            </span>
          </div>
        </div>
      )}

      {rows.length === 0 ? (
        <Card>
          <EmptyState
            icon={<ShieldCheck className="h-10 w-10" />}
            title="Nothing scanned yet"
            description="Point Sentinel at a local directory, a GitHub repository, or upload a ZIP archive to get a full security assessment in seconds."
            action={
              <Link
                href="/scan"
                className="inline-flex h-10 items-center rounded-lg bg-[var(--color-accent)] px-5 text-sm font-medium text-white transition-colors hover:bg-[var(--color-accent-hover)]"
              >
                Run your first scan
              </Link>
            }
          />
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Stat
              value={averageScore ?? '—'}
              label="Average score"
              tone={averageScore !== undefined ? undefined : 'var(--color-fg-subtle)'}
            />
            <Stat value={formatNumber(totalOpen)} label="Open findings" />
            <Stat
              value={formatNumber(totalCritical)}
              label="Critical"
              tone={totalCritical > 0 ? 'var(--color-critical)' : undefined}
            />
            <Stat value={formatNumber(rows.length)} label="Projects" />
          </div>

          <section aria-labelledby="projects-heading" className="space-y-3">
            <h2 id="projects-heading" className="text-sm font-medium text-[var(--color-fg-muted)]">
              Projects
            </h2>

            <div className="grid gap-3">
              {rows.map((row) => {
                const trend = summarizeTrend(row.trend);
                return (
                  <Link
                    key={row.project.id}
                    href={`/projects/${row.project.id}`}
                    className="group block rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5 transition-all hover:border-[var(--color-border-strong)] hover:bg-[var(--color-surface-raised)]"
                  >
                    <div className="flex flex-wrap items-center gap-5">
                      {row.scores ? (
                        <ScoreRing score={row.scores.overall} grade={row.scores.grade} size={72} />
                      ) : (
                        <div className="flex h-[72px] w-[72px] items-center justify-center rounded-full border border-dashed border-[var(--color-border-strong)] text-[11px] text-[var(--color-fg-subtle)]">
                          no scan
                        </div>
                      )}

                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <h3 className="truncate text-[15px] font-semibold">{row.project.name}</h3>
                          {row.criticalFindings > 0 && (
                            <Badge tone="warning">{row.criticalFindings} critical</Badge>
                          )}
                          {trend.direction !== 'stable' && (
                            <span
                              className="inline-flex items-center gap-1 text-[11px] font-medium"
                              style={{
                                color:
                                  trend.direction === 'improving'
                                    ? 'var(--color-success)'
                                    : 'var(--color-critical)',
                              }}
                            >
                              {trend.direction === 'improving' ? (
                                <TrendingUp className="h-3 w-3" aria-hidden="true" />
                              ) : (
                                <TrendingDown className="h-3 w-3" aria-hidden="true" />
                              )}
                              {trend.delta > 0 ? '+' : ''}
                              {trend.delta}
                            </span>
                          )}
                        </div>

                        <div className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-[12.5px] text-[var(--color-fg-subtle)]">
                          <span className="inline-flex items-center gap-1.5">
                            <FolderGit2 className="h-3.5 w-3.5" aria-hidden="true" />
                            {row.project.target.type === 'github'
                              ? `${row.project.target.owner}/${row.project.target.repo}`
                              : row.project.target.type}
                          </span>
                          <span>{formatNumber(row.openFindings)} open findings</span>
                          {row.lastScannedAt && (
                            <span>scanned {relativeTime(row.lastScannedAt)}</span>
                          )}
                        </div>
                      </div>

                      {row.trend.length > 1 && (
                        <TrendSparkline points={row.trend} width={110} height={36} />
                      )}
                    </div>
                  </Link>
                );
              })}
            </div>
          </section>
        </>
      )}
    </div>
  );
}
