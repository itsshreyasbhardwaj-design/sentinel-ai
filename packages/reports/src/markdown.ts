import { assessCompliance, getFramework, type ScanResult, type Severity } from '@sentinel/core';
import type { ExecutiveSummary, PrioritizedFinding } from '@sentinel/ai';

/**
 * Markdown report.
 *
 * The format that goes into a pull request comment, a GitHub issue, or a
 * release checklist — so it has to be readable in a diff view, degrade
 * gracefully without CSS, and stay under GitHub's 65 536-character comment
 * limit.
 */

const SEVERITY_ICON: Record<Severity, string> = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🔵',
  info: '⚪',
};

const GRADE_ICON: Record<string, string> = { A: '🟢', B: '🟢', C: '🟡', D: '🟠', F: '🔴' };

export interface MarkdownOptions {
  summary?: ExecutiveSummary;
  priorities?: PrioritizedFinding[];
  /** Cap the detailed finding list. */
  maxFindings?: number;
  /** Include the per-control compliance section. */
  frameworks?: string[];
  /** Absolute base URL so file links resolve in a comment. */
  repoUrlBase?: string;
  /** Compact mode for pull-request comments. */
  compact?: boolean;
}

function escapeTableCell(text: string): string {
  return text.replace(/\|/g, '\\|').replace(/\n/g, ' ').slice(0, 160);
}

function locationLink(
  path: string | undefined,
  line: number | undefined,
  base: string | undefined,
): string {
  if (!path) return '—';
  const label = line ? `${path}:${line}` : path;
  if (!base) return `\`${label}\``;
  return `[\`${label}\`](${base}/${path}${line ? `#L${line}` : ''})`;
}

export function toMarkdown(result: ScanResult, options: MarkdownOptions = {}): string {
  const lines: string[] = [];
  const active = result.findings.filter((f) => !f.suppressed);
  const counts = result.scores.counts;
  const maxFindings = options.maxFindings ?? (options.compact ? 10 : 50);

  /* ---------------- Header ---------------- */
  lines.push(`# Security Report: ${result.repository.name}`);
  lines.push('');

  if (result.status === 'failed') {
    lines.push(`> ⚠️ **This scan did not complete.** ${result.error ?? 'Unknown error.'}`);
    lines.push('');
    return lines.join('\n');
  }

  lines.push(
    `${GRADE_ICON[result.scores.grade] ?? '⚪'} **Score ${result.scores.overall}/100 (Grade ${result.scores.grade})** · Risk level: **${result.scores.riskLevel}** · ${active.length} open ${active.length === 1 ? 'finding' : 'findings'}`,
  );
  lines.push('');

  if (options.summary) {
    lines.push(options.summary.headline);
    lines.push('');
    lines.push(options.summary.posture);
    lines.push('');
  }

  /* ---------------- Severity table ---------------- */
  lines.push('| Severity | Count |');
  lines.push('| --- | ---: |');
  for (const severity of ['critical', 'high', 'medium', 'low', 'info'] as const) {
    if (counts[severity] > 0 || severity === 'critical' || severity === 'high') {
      lines.push(`| ${SEVERITY_ICON[severity]} ${severity} | ${counts[severity]} |`);
    }
  }
  lines.push('');

  /* ---------------- Category scores ---------------- */
  if (!options.compact) {
    lines.push('## Repository health');
    lines.push('');
    lines.push('| Category | Score | Grade | Findings | Notes |');
    lines.push('| --- | ---: | :---: | ---: | --- |');
    for (const category of result.scores.categories) {
      lines.push(
        `| ${category.category} | ${category.analyzed ? category.score : '—'} | ${category.analyzed ? category.grade : '—'} | ${category.findingCount} | ${escapeTableCell(category.rationale)} |`,
      );
    }
    lines.push('');
  }

  /* ---------------- Recommended actions ---------------- */
  if (options.summary?.recommendedActions.length) {
    lines.push('## Recommended actions');
    lines.push('');
    for (const action of options.summary.recommendedActions) lines.push(`1. ${action}`);
    lines.push('');
  }

  /* ---------------- Findings ---------------- */
  const priorityById = new Map((options.priorities ?? []).map((p) => [p.findingId, p]));
  const ordered = [...active].sort(
    (a, b) =>
      (priorityById.get(b.id)?.priorityScore ?? b.riskScore) -
      (priorityById.get(a.id)?.priorityScore ?? a.riskScore),
  );

  if (ordered.length) {
    lines.push(
      `## Findings${ordered.length > maxFindings ? ` (top ${maxFindings} of ${ordered.length})` : ''}`,
    );
    lines.push('');

    if (options.compact) {
      lines.push('| | Severity | Finding | Location |');
      lines.push('| :---: | --- | --- | --- |');
      for (const finding of ordered.slice(0, maxFindings)) {
        lines.push(
          `| ${SEVERITY_ICON[finding.severity]} | ${finding.severity} | ${escapeTableCell(finding.title)} | ${locationLink(finding.location?.path, finding.location?.startLine, options.repoUrlBase)} |`,
        );
      }
      lines.push('');
    } else {
      for (const finding of ordered.slice(0, maxFindings)) {
        const priority = priorityById.get(finding.id);
        lines.push(`### ${SEVERITY_ICON[finding.severity]} ${finding.title}`);
        lines.push('');
        lines.push(
          `**Severity:** ${finding.severity} · **Confidence:** ${finding.confidence} · **Scanner:** \`${finding.scanner}\`${priority ? ` · **Priority:** #${priority.rank} (${priority.priorityScore}/100)` : ''}`,
        );
        lines.push('');
        lines.push(
          `**Location:** ${locationLink(finding.location?.path, finding.location?.startLine, options.repoUrlBase)}`,
        );
        lines.push('');

        if (finding.explanation) {
          lines.push(finding.explanation.plainEnglish);
          lines.push('');
          lines.push(`> **Business impact.** ${finding.explanation.businessImpact}`);
          lines.push('');
          lines.push(`**How it happens.** ${finding.explanation.howItHappens}`);
          lines.push('');
        } else if (finding.description) {
          lines.push(finding.description);
          lines.push('');
        }

        if (finding.location?.snippet) {
          lines.push('```');
          lines.push(finding.location.snippet);
          lines.push('```');
          lines.push('');
        }

        const fixes = finding.explanation?.suggestedFixes ?? [];
        if (fixes.length) {
          lines.push('**How to fix**');
          lines.push('');
          for (const fix of fixes) {
            lines.push(`- **${fix.title}** (${fix.effort}) — ${fix.description}`);
            if (fix.code) {
              lines.push('');
              lines.push(`  \`\`\`${fix.language ?? ''}`);
              for (const codeLine of fix.code.split('\n')) lines.push(`  ${codeLine}`);
              lines.push('  ```');
              lines.push('');
            }
          }
          lines.push('');
        } else if (finding.remediationHint) {
          lines.push(`**How to fix.** ${finding.remediationHint}`);
          lines.push('');
        }

        const taxonomy = [
          ...(finding.taxonomy?.cwe ?? []),
          ...(finding.taxonomy?.owaspTop10 ?? []),
          ...(finding.taxonomy?.owaspLlmTop10 ?? []),
          ...(finding.taxonomy?.cve ?? []),
        ];
        if (taxonomy.length) {
          lines.push(`**Standards:** ${taxonomy.map((t) => `\`${t}\``).join(', ')}`);
          lines.push('');
        }

        lines.push('---');
        lines.push('');
      }
    }
  } else {
    lines.push('## Findings');
    lines.push('');
    lines.push('No open findings in the analyzed scope. ✅');
    lines.push('');
  }

  /* ---------------- Compliance ---------------- */
  if (options.frameworks?.length && !options.compact) {
    lines.push('## Compliance');
    lines.push('');
    const analyzedKinds = [
      ...new Set(result.scannerRuns.filter((r) => r.status === 'ok').map((r) => r.kind)),
    ];

    for (const frameworkId of options.frameworks) {
      const framework = getFramework(frameworkId);
      if (!framework) continue;
      const report = assessCompliance(framework, result.findings, result.id, analyzedKinds);

      lines.push(`### ${framework.name} ${framework.version}`);
      lines.push('');
      lines.push(
        `${report.passed} passed · ${report.failed} failed · ${report.needsReview} need review · **${report.coveragePercent}% of applicable controls passing**`,
      );
      lines.push('');
      lines.push('| Control | Status | Evidence |');
      lines.push('| --- | :---: | --- |');
      for (const assessment of report.assessments) {
        const icon =
          assessment.status === 'pass' ? '✅' : assessment.status === 'fail' ? '❌' : '⚠️';
        lines.push(
          `| ${assessment.controlId} — ${escapeTableCell(assessment.title)} | ${icon} | ${escapeTableCell(assessment.evidence)} |`,
        );
      }
      lines.push('');
    }
  }

  /* ---------------- Coverage ---------------- */
  lines.push('## Scanner coverage');
  lines.push('');
  lines.push('| Scanner | Type | Status | Findings | Notes |');
  lines.push('| --- | --- | :---: | ---: | --- |');
  for (const run of result.scannerRuns) {
    const icon = run.status === 'ok' ? '✅' : run.status === 'failed' ? '❌' : '⏭️';
    lines.push(
      `| \`${run.scanner}\` | ${run.scannerKind} | ${icon} ${run.status} | ${run.findingCount} | ${escapeTableCell(run.reason ?? '')} |`,
    );
  }
  lines.push('');

  /* ---------------- Caveats ---------------- */
  if (options.summary?.caveats.length) {
    lines.push('## Caveats');
    lines.push('');
    for (const caveat of options.summary.caveats) lines.push(`- ${caveat}`);
    lines.push('');
  }

  lines.push('---');
  lines.push('');
  lines.push(
    `<sub>Generated by [Sentinel AI](https://github.com/sentinel-ai/sentinel-ai) · ${result.repository.fileCount} files · ${(result.durationMs / 1000).toFixed(1)}s · ${new Date(result.completedAt ?? result.startedAt).toISOString()}</sub>`,
  );

  return lines.join('\n');
}

/** GitHub rejects comments over 65 536 characters, so trim rather than fail. */
export function toPullRequestComment(result: ScanResult, options: MarkdownOptions = {}): string {
  const markdown = toMarkdown(result, {
    ...options,
    compact: true,
    maxFindings: options.maxFindings ?? 15,
  });
  const LIMIT = 65_000;
  if (markdown.length <= LIMIT) return markdown;
  return `${markdown.slice(0, LIMIT - 200)}\n\n---\n\n_Report truncated. See the full report in the Sentinel dashboard._`;
}
