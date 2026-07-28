'use client';

import { useMemo, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { ChevronRight, ExternalLink, Search, ShieldCheck } from 'lucide-react';
import { SEVERITIES, type Finding, type Severity } from '@sentinel/core/constants';
import type { PrioritizedFinding } from '@sentinel/ai';
import { Badge, Card, Code, EmptyState, SeverityBadge } from '@/components/primitives';
import { KIND_LABEL, cn, truncatePath } from '@/lib/ui';

/**
 * Findings explorer.
 *
 * Filtering happens client-side over the already-loaded set: a scan's findings
 * are bounded and small enough to hold, and instant filtering is the difference
 * between a list people triage and a list people export to a spreadsheet.
 */
export function FindingsExplorer({
  scanId,
  findings,
  priorities,
  repositoryUrl,
  repositoryRef,
}: {
  scanId: string;
  findings: Finding[];
  priorities: PrioritizedFinding[];
  repositoryUrl?: string;
  repositoryRef?: string;
}) {
  const [severityFilter, setSeverityFilter] = useState<Severity[]>([]);
  const [kindFilter, setKindFilter] = useState<string[]>([]);
  const [search, setSearch] = useState('');
  const [expanded, setExpanded] = useState<string | undefined>();
  const [limit, setLimit] = useState(25);

  const priorityById = useMemo(
    () => new Map(priorities.map((p) => [p.findingId, p])),
    [priorities],
  );

  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const finding of findings) counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
    return counts;
  }, [findings]);

  const kindCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const finding of findings) counts[finding.kind] = (counts[finding.kind] ?? 0) + 1;
    return counts;
  }, [findings]);

  const visible = useMemo(() => {
    const query = search.trim().toLowerCase();

    return findings
      .filter((finding) => {
        if (severityFilter.length && !severityFilter.includes(finding.severity)) return false;
        if (kindFilter.length && !kindFilter.includes(finding.kind)) return false;
        if (!query) return true;

        return [
          finding.title,
          finding.ruleId,
          finding.description ?? '',
          finding.location?.path ?? '',
          finding.component?.name ?? '',
        ]
          .join(' ')
          .toLowerCase()
          .includes(query);
      })
      .sort(
        (a, b) =>
          (priorityById.get(b.id)?.priorityScore ?? b.riskScore) -
          (priorityById.get(a.id)?.priorityScore ?? a.riskScore),
      );
  }, [findings, severityFilter, kindFilter, search, priorityById]);

  function toggle<T>(list: T[], value: T, setter: (next: T[]) => void) {
    setter(list.includes(value) ? list.filter((item) => item !== value) : [...list, value]);
  }

  function sourceLink(finding: Finding): string | undefined {
    if (!repositoryUrl || !finding.location) return undefined;
    return `${repositoryUrl}/blob/${repositoryRef ?? 'main'}/${finding.location.path}#L${finding.location.startLine}`;
  }

  return (
    <div className="space-y-3">
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-[220px] flex-1">
          <Search
            className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--color-fg-subtle)]"
            aria-hidden="true"
          />
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search findings, files, packages…"
            aria-label="Search findings"
            className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] py-2 pl-9 pr-3 text-[13px] placeholder:text-[var(--color-fg-subtle)] focus:border-[var(--color-accent)] focus:outline-none"
          />
        </div>

        <div className="flex flex-wrap gap-1.5" role="group" aria-label="Filter by severity">
          {SEVERITIES.filter((severity) => severityCounts[severity])
            .reverse()
            .map((severity) => (
              <button
                key={severity}
                type="button"
                aria-pressed={severityFilter.includes(severity)}
                onClick={() => toggle(severityFilter, severity, setSeverityFilter)}
                className={cn(
                  'rounded-md border px-2 py-1 text-[11.5px] font-medium capitalize transition-all',
                  severityFilter.includes(severity)
                    ? 'border-[var(--color-accent)] bg-[var(--color-accent)]/12 text-[var(--color-fg)]'
                    : 'border-[var(--color-border)] text-[var(--color-fg-subtle)] hover:border-[var(--color-border-strong)]',
                )}
              >
                {severity}
                <span className="ml-1.5 tabular-nums opacity-70">{severityCounts[severity]}</span>
              </button>
            ))}
        </div>
      </div>

      <div className="flex flex-wrap gap-1.5" role="group" aria-label="Filter by analysis domain">
        {Object.entries(kindCounts)
          .sort(([, a], [, b]) => b - a)
          .map(([kind, count]) => (
            <button
              key={kind}
              type="button"
              aria-pressed={kindFilter.includes(kind)}
              onClick={() => toggle(kindFilter, kind, setKindFilter)}
              className={cn(
                'rounded-md border px-2 py-0.5 text-[11.5px] transition-all',
                kindFilter.includes(kind)
                  ? 'border-[var(--color-accent)] bg-[var(--color-accent)]/12 text-[var(--color-fg)]'
                  : 'border-[var(--color-border)] text-[var(--color-fg-subtle)] hover:border-[var(--color-border-strong)]',
              )}
            >
              {KIND_LABEL[kind as keyof typeof KIND_LABEL] ?? kind}
              <span className="ml-1.5 tabular-nums opacity-70">{count}</span>
            </button>
          ))}
      </div>

      {/* Results */}
      {visible.length === 0 ? (
        <Card>
          <EmptyState
            icon={<ShieldCheck className="h-9 w-9" />}
            title={findings.length ? 'No findings match these filters' : 'No open findings'}
            description={
              findings.length
                ? 'Try widening the severity or domain filters.'
                : 'Nothing was detected in the analyzed scope. Check the scanner coverage table for what was assessed.'
            }
          />
        </Card>
      ) : (
        <>
          <p className="text-[12px] text-[var(--color-fg-subtle)]">
            Showing {Math.min(limit, visible.length)} of {visible.length}
            {visible.length !== findings.length && ` (filtered from ${findings.length})`}
          </p>

          <div className="space-y-2">
            {visible.slice(0, limit).map((finding) => {
              const priority = priorityById.get(finding.id);
              const isOpen = expanded === finding.id;
              const link = sourceLink(finding);

              return (
                <Card key={finding.id} className="overflow-hidden">
                  <button
                    type="button"
                    onClick={() => setExpanded(isOpen ? undefined : finding.id)}
                    aria-expanded={isOpen}
                    className="flex w-full items-start gap-3 px-4 py-3 text-left transition-colors hover:bg-[var(--color-surface-raised)]"
                  >
                    <ChevronRight
                      className={cn(
                        'mt-1 h-4 w-4 shrink-0 text-[var(--color-fg-subtle)] transition-transform',
                        isOpen && 'rotate-90',
                      )}
                      aria-hidden="true"
                    />

                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={finding.severity} />
                        <span className="text-[14px] font-medium">{finding.title}</span>
                      </div>

                      <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px] text-[var(--color-fg-subtle)]">
                        {finding.location && (
                          <Code>
                            {truncatePath(`${finding.location.path}:${finding.location.startLine}`)}
                          </Code>
                        )}
                        {finding.component && (
                          <Code>
                            {finding.component.name}@{finding.component.version}
                          </Code>
                        )}
                        <span>{KIND_LABEL[finding.kind]}</span>
                        <span>·</span>
                        <span>{finding.scanner}</span>
                        {priority && (
                          <>
                            <span>·</span>
                            <span>priority #{priority.rank}</span>
                          </>
                        )}
                      </div>
                    </div>
                  </button>

                  <AnimatePresence initial={false}>
                    {isOpen && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.18, ease: 'easeOut' }}
                        className="overflow-hidden"
                      >
                        <div className="space-y-4 border-t border-[var(--color-border)] px-4 py-4">
                          {finding.explanation ? (
                            <>
                              <p className="text-[13.5px] leading-relaxed">
                                {finding.explanation.plainEnglish}
                              </p>

                              <div className="rounded-lg border-l-2 border-[var(--color-accent)] bg-[var(--color-surface-raised)] px-3.5 py-2.5">
                                <span className="text-[11px] font-semibold uppercase tracking-wide text-[var(--color-accent)]">
                                  Business impact
                                </span>
                                <p className="mt-1 text-[13px] leading-relaxed text-[var(--color-fg-muted)]">
                                  {finding.explanation.businessImpact}
                                </p>
                              </div>

                              <Detail label="How it happens">
                                {finding.explanation.howItHappens}
                              </Detail>
                              <Detail label="Technical impact">
                                {finding.explanation.technicalImpact}
                              </Detail>
                            </>
                          ) : (
                            finding.description && (
                              <p className="text-[13.5px] leading-relaxed">{finding.description}</p>
                            )
                          )}

                          {finding.location?.snippet && (
                            <pre className="scroll-slim overflow-x-auto rounded-lg border border-[var(--color-border)] bg-[var(--color-canvas)] px-3.5 py-3 font-mono text-[12px] leading-relaxed">
                              <code>{finding.location.snippet}</code>
                            </pre>
                          )}

                          {finding.explanation?.suggestedFixes.length ? (
                            <div>
                              <h4 className="text-[11px] font-semibold uppercase tracking-wide text-[var(--color-fg-subtle)]">
                                How to fix
                              </h4>
                              <div className="mt-2 space-y-3">
                                {finding.explanation.suggestedFixes.map((fix) => (
                                  <div key={fix.title}>
                                    <div className="flex flex-wrap items-center gap-2">
                                      <span className="text-[13px] font-medium">{fix.title}</span>
                                      <Badge>{fix.effort}</Badge>
                                      {fix.autoApplicable && (
                                        <Badge tone="success">automatable</Badge>
                                      )}
                                    </div>
                                    <p className="mt-1 text-[13px] leading-relaxed text-[var(--color-fg-muted)]">
                                      {fix.description}
                                    </p>
                                    {fix.code && (
                                      <pre className="scroll-slim mt-2 overflow-x-auto rounded-lg border border-[var(--color-border)] bg-[var(--color-canvas)] px-3.5 py-3 font-mono text-[12px] leading-relaxed">
                                        <code>{fix.code}</code>
                                      </pre>
                                    )}
                                  </div>
                                ))}
                              </div>
                            </div>
                          ) : (
                            finding.remediationHint && (
                              <Detail label="How to fix">{finding.remediationHint}</Detail>
                            )
                          )}

                          <div className="flex flex-wrap items-center gap-2 pt-1">
                            {[
                              ...(finding.taxonomy?.cwe ?? []),
                              ...(finding.taxonomy?.owaspTop10 ?? []),
                              ...(finding.taxonomy?.owaspLlmTop10 ?? []),
                              ...(finding.taxonomy?.cve ?? []),
                            ].map((tag) => (
                              <Badge key={tag}>{tag}</Badge>
                            ))}

                            {link && (
                              <a
                                href={link}
                                target="_blank"
                                rel="noreferrer noopener"
                                className="ml-auto inline-flex items-center gap-1.5 text-[12px] text-[var(--color-accent)] hover:underline"
                              >
                                View source
                                <ExternalLink className="h-3 w-3" aria-hidden="true" />
                              </a>
                            )}
                          </div>

                          {priority && (
                            <p className="border-t border-[var(--color-border)] pt-3 text-[12px] text-[var(--color-fg-subtle)]">
                              <span className="font-medium">
                                Priority #{priority.rank} ({priority.priorityScore}/100)
                              </span>{' '}
                              — {priority.reasoning}
                            </p>
                          )}

                          <p className="text-[11px] text-[var(--color-fg-subtle)]">
                            Rule <span className="font-mono">{finding.ruleId}</span> · confidence{' '}
                            {finding.confidence} · scan {scanId.slice(0, 12)}
                          </p>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </Card>
              );
            })}
          </div>

          {visible.length > limit && (
            <button
              type="button"
              onClick={() => setLimit((current) => current + 50)}
              className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] py-2.5 text-[13px] font-medium text-[var(--color-fg-muted)] transition-colors hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-fg)]"
            >
              Show {Math.min(50, visible.length - limit)} more
            </button>
          )}
        </>
      )}
    </div>
  );
}

function Detail({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <h4 className="text-[11px] font-semibold uppercase tracking-wide text-[var(--color-fg-subtle)]">
        {label}
      </h4>
      <p className="mt-1 text-[13px] leading-relaxed text-[var(--color-fg-muted)]">{children}</p>
    </div>
  );
}
