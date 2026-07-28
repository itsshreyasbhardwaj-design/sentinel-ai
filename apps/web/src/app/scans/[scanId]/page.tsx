import { cache } from 'react';
import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import Link from 'next/link';
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  FileCode2,
  GitBranch,
  MinusCircle,
  XCircle,
} from 'lucide-react';
import { assessCompliance, getFramework, type ScanKind } from '@sentinel/core';
import { getPlatform } from '@sentinel/platform';
import {
  Badge,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  ScoreBar,
  ScoreRing,
  Stat,
} from '@/components/primitives';
import { FindingsExplorer } from '@/components/findings-explorer';
import { ExportMenu } from '@/components/export-menu';
import { CATEGORY_LABEL, formatDuration, formatNumber, relativeTime, scoreColor } from '@/lib/ui';
import { getScanAnalysis } from '@/lib/scan-service';

export const dynamic = 'force-dynamic';

const FRAMEWORK_IDS = ['owasp-top-10-2021', 'owasp-llm-top-10-2025', 'nist-ssdf-1.1'];

/**
 * Deduplicated per request, so the existence check in `generateMetadata` and
 * the page body share one database read.
 */
const loadScan = cache(async (scanId: string) => {
  const platform = await getPlatform();
  return platform.storage.getScan(scanId);
});

/**
 * The existence check lives here rather than only in the component body.
 *
 * Next awaits `generateMetadata` *before* it begins streaming the response, so
 * calling `notFound()` from here produces a real HTTP 404. Calling it from the
 * component — after an async storage read, with a `loading.tsx` boundary above —
 * renders the right page but with a 200 status already committed, which breaks
 * caching, uptime monitoring and link checkers.
 */
export async function generateMetadata({
  params,
}: {
  params: Promise<{ scanId: string }>;
}): Promise<Metadata> {
  const { scanId } = await params;
  const scan = await loadScan(scanId);
  if (!scan) notFound();

  return {
    title: `${scan.repository.name} — security report`,
    description: `${scan.findings.length} findings · score ${scan.scores.overall}/100 (grade ${scan.scores.grade})`,
  };
}

export default async function ScanPage({ params }: { params: Promise<{ scanId: string }> }) {
  const { scanId } = await params;
  const platform = await getPlatform();

  const scan = await loadScan(scanId);
  if (!scan) notFound();

  const analysis = await getScanAnalysis(platform, scanId);
  const active = scan.findings.filter((f) => !f.suppressed);
  const counts = scan.scores.counts;

  const analyzedKinds = [
    ...new Set(scan.scannerRuns.filter((r) => r.status === 'ok').map((r) => r.kind)),
  ] as ScanKind[];

  if (scan.status === 'failed') {
    return (
      <div className="mx-auto max-w-2xl">
        <Card>
          <CardContent className="pt-6 text-center">
            <XCircle
              className="mx-auto h-10 w-10 text-[var(--color-critical)]"
              aria-hidden="true"
            />
            <h1 className="mt-4 text-lg font-semibold">Scan did not complete</h1>
            <p className="mt-2 text-sm text-[var(--color-fg-muted)]">{scan.error}</p>
            <Link
              href="/scan"
              className="mt-6 inline-flex h-10 items-center rounded-lg bg-[var(--color-accent)] px-5 text-sm font-medium text-white"
            >
              Try again
            </Link>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* ---------------- Header ---------------- */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-2xl font-semibold tracking-tight">{scan.repository.name}</h1>
          <div className="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-[13px] text-[var(--color-fg-subtle)]">
            {scan.repository.ref && (
              <span className="inline-flex items-center gap-1.5">
                <GitBranch className="h-3.5 w-3.5" aria-hidden="true" />
                {scan.repository.ref}
                {scan.repository.commit && ` · ${scan.repository.commit.slice(0, 8)}`}
              </span>
            )}
            <span className="inline-flex items-center gap-1.5">
              <FileCode2 className="h-3.5 w-3.5" aria-hidden="true" />
              {formatNumber(scan.repository.fileCount)} files
            </span>
            <span className="inline-flex items-center gap-1.5">
              <Clock className="h-3.5 w-3.5" aria-hidden="true" />
              {formatDuration(scan.durationMs)} · {relativeTime(scan.completedAt ?? scan.startedAt)}
            </span>
          </div>
        </div>
        <ExportMenu scanId={scan.id} />
      </div>

      {/* ---------------- Score + summary ---------------- */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex flex-wrap items-start gap-8">
            <ScoreRing score={scan.scores.overall} grade={scan.scores.grade} size={132} />

            <div className="min-w-0 flex-1 space-y-4">
              {analysis.summary && (
                <>
                  <p className="text-[15px] leading-relaxed text-balance">
                    {analysis.summary.headline}
                  </p>
                  <p className="text-[13px] leading-relaxed text-[var(--color-fg-muted)]">
                    {analysis.summary.posture}
                  </p>
                </>
              )}

              <div className="flex flex-wrap gap-2">
                {(['critical', 'high', 'medium', 'low', 'info'] as const).map((severity) => (
                  <div
                    key={severity}
                    className="flex items-baseline gap-1.5 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-2.5 py-1"
                  >
                    <span
                      className="text-[15px] font-semibold tabular-nums"
                      style={{ color: `var(--color-${severity})` }}
                    >
                      {counts[severity]}
                    </span>
                    <span className="text-[11px] uppercase tracking-wide text-[var(--color-fg-subtle)]">
                      {severity}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {analysis.summary && analysis.summary.recommendedActions.length > 0 && (
            <div className="mt-6 rounded-lg border border-[var(--color-accent)]/25 bg-[var(--color-accent)]/6 p-4">
              <h2 className="text-[13px] font-semibold text-[var(--color-accent)]">
                Recommended actions
              </h2>
              <ol className="mt-2.5 space-y-1.5">
                {analysis.summary.recommendedActions.map((action, index) => (
                  <li
                    key={action}
                    className="flex gap-2.5 text-[13px] text-[var(--color-fg-muted)]"
                  >
                    <span className="tabular-nums text-[var(--color-fg-subtle)]">{index + 1}.</span>
                    {action}
                  </li>
                ))}
              </ol>
            </div>
          )}
        </CardContent>
      </Card>

      {/* ---------------- Category scores ---------------- */}
      <section aria-labelledby="health-heading">
        <h2 id="health-heading" className="mb-3 text-sm font-medium text-[var(--color-fg-muted)]">
          Repository health
        </h2>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {scan.scores.categories.map((category) => (
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
              <ScoreBar score={category.score} analyzed={category.analyzed} className="mt-2.5" />
              <p className="mt-2 text-[12px] leading-relaxed text-[var(--color-fg-subtle)]">
                {category.rationale}
              </p>
            </Card>
          ))}
        </div>
      </section>

      {/* ---------------- Findings ---------------- */}
      <section aria-labelledby="findings-heading">
        <h2 id="findings-heading" className="mb-3 text-sm font-medium text-[var(--color-fg-muted)]">
          Findings
        </h2>
        <FindingsExplorer
          scanId={scan.id}
          findings={active}
          priorities={analysis.priorities ?? []}
          repositoryUrl={scan.repository.url}
          repositoryRef={scan.repository.ref}
        />
      </section>

      {/* ---------------- Compliance ---------------- */}
      <section aria-labelledby="compliance-heading">
        <h2
          id="compliance-heading"
          className="mb-3 text-sm font-medium text-[var(--color-fg-muted)]"
        >
          Compliance
        </h2>
        <div className="grid gap-3 lg:grid-cols-3">
          {FRAMEWORK_IDS.map((id) => {
            const framework = getFramework(id);
            if (!framework) return null;
            const report = assessCompliance(framework, scan.findings, scan.id, analyzedKinds);

            return (
              <Card key={id}>
                <CardHeader>
                  <CardTitle className="text-[13px]">{framework.name}</CardTitle>
                  <p className="mt-0.5 text-[11px] text-[var(--color-fg-subtle)]">
                    {framework.version}
                  </p>
                </CardHeader>
                <CardContent>
                  <div className="mb-3 flex items-baseline gap-2">
                    <span
                      className="text-2xl font-semibold tabular-nums"
                      style={{ color: scoreColor(report.coveragePercent) }}
                    >
                      {report.coveragePercent}%
                    </span>
                    <span className="text-[11px] text-[var(--color-fg-subtle)]">
                      of applicable controls passing
                    </span>
                  </div>

                  <div className="space-y-1">
                    {report.assessments.slice(0, 6).map((assessment) => (
                      <div
                        key={assessment.controlId}
                        className="flex items-start gap-2 text-[12px]"
                      >
                        {assessment.status === 'pass' && (
                          <CheckCircle2
                            className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--color-success)]"
                            aria-label="Pass"
                          />
                        )}
                        {assessment.status === 'fail' && (
                          <XCircle
                            className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--color-critical)]"
                            aria-label="Fail"
                          />
                        )}
                        {assessment.status === 'needs-review' && (
                          <MinusCircle
                            className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--color-fg-subtle)]"
                            aria-label="Not evaluated"
                          />
                        )}
                        <span className="truncate text-[var(--color-fg-muted)]">
                          <span className="font-mono text-[11px]">{assessment.controlId}</span>{' '}
                          {assessment.title}
                        </span>
                      </div>
                    ))}
                    {report.assessments.length > 6 && (
                      <p className="pt-1 text-[11px] text-[var(--color-fg-subtle)]">
                        +{report.assessments.length - 6} more controls
                      </p>
                    )}
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      </section>

      {/* ---------------- Coverage ---------------- */}
      <section aria-labelledby="coverage-heading">
        <h2 id="coverage-heading" className="mb-3 text-sm font-medium text-[var(--color-fg-muted)]">
          Scanner coverage
        </h2>
        <Card>
          <CardContent className="pt-5">
            <div className="grid gap-2">
              {scan.scannerRuns.map((run) => (
                <div
                  key={run.scanner}
                  className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-[var(--color-border)] pb-2 last:border-0 last:pb-0"
                >
                  {run.status === 'ok' && (
                    <CheckCircle2
                      className="h-3.5 w-3.5 text-[var(--color-success)]"
                      aria-label="Ran"
                    />
                  )}
                  {run.status === 'failed' && (
                    <AlertTriangle
                      className="h-3.5 w-3.5 text-[var(--color-critical)]"
                      aria-label="Failed"
                    />
                  )}
                  {run.status === 'skipped' && (
                    <MinusCircle
                      className="h-3.5 w-3.5 text-[var(--color-fg-subtle)]"
                      aria-label="Skipped"
                    />
                  )}

                  <span className="font-mono text-[12.5px]">{run.scanner}</span>
                  <Badge tone={run.scannerKind === 'external' ? 'accent' : 'neutral'}>
                    {run.scannerKind}
                  </Badge>

                  {run.status === 'ok' && (
                    <span className="text-[12px] tabular-nums text-[var(--color-fg-subtle)]">
                      {run.findingCount} findings · {formatDuration(run.durationMs)}
                    </span>
                  )}
                  {run.reason && (
                    <span className="min-w-0 flex-1 truncate text-[12px] text-[var(--color-fg-subtle)]">
                      {run.reason}
                    </span>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </section>

      {/* ---------------- Caveats ---------------- */}
      {analysis.summary && analysis.summary.caveats.length > 0 && (
        <section aria-labelledby="caveats-heading">
          <h2
            id="caveats-heading"
            className="mb-3 text-sm font-medium text-[var(--color-fg-muted)]"
          >
            Caveats and coverage limits
          </h2>
          <Card>
            <CardContent className="pt-5">
              <ul className="space-y-2">
                {analysis.summary.caveats.map((caveat) => (
                  <li
                    key={caveat}
                    className="flex gap-2.5 text-[13px] text-[var(--color-fg-subtle)]"
                  >
                    <span aria-hidden="true">·</span>
                    {caveat}
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>
        </section>
      )}

      {/* ---------------- Repository facts ---------------- */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat value={formatNumber(scan.repository.fileCount)} label="Files analyzed" />
        <Stat value={formatNumber(scan.repository.linesOfCode)} label="Lines of code" />
        <Stat value={formatNumber(active.length)} label="Open findings" />
        <Stat value={formatNumber(scan.sbom?.components.length ?? 0)} label="SBOM components" />
      </div>
    </div>
  );
}
