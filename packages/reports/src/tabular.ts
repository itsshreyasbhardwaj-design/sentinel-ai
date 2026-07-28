import type { ScanResult } from '@sentinel/core';
import type { ExecutiveSummary, PrioritizedFinding } from '@sentinel/ai';

/**
 * CSV and JSON export.
 *
 * CSV is what security teams actually paste into a tracker or a spreadsheet, so
 * the column set is chosen for triage rather than for completeness.
 */

/**
 * Escape a CSV field.
 *
 * Also neutralizes formula injection: a value starting with `=`, `+`, `-` or
 * `@` is executed by Excel and Sheets when the file is opened, which turns an
 * exported finding title into code execution on an analyst machine. Prefixing
 * with a single quote is the standard mitigation.
 */
export function csvEscape(value: unknown): string {
  if (value === null || value === undefined) return '';
  let text = Array.isArray(value) ? value.join('; ') : String(value);

  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  if (/[",\n\r]/.test(text)) text = `"${text.replace(/"/g, '""')}"`;
  return text;
}

const CSV_COLUMNS = [
  'id',
  'severity',
  'riskScore',
  'priority',
  'kind',
  'ruleId',
  'title',
  'file',
  'line',
  'component',
  'version',
  'fixedVersion',
  'confidence',
  'scanner',
  'status',
  'cwe',
  'owasp',
  'cve',
  'remediation',
  'firstSeen',
] as const;

export function toCsv(result: ScanResult, priorities: PrioritizedFinding[] = []): string {
  const priorityById = new Map(priorities.map((p) => [p.findingId, p]));
  const rows: string[] = [CSV_COLUMNS.join(',')];

  for (const finding of result.findings) {
    const fixedVersions = finding.metadata?.['fixedVersions'];
    rows.push(
      [
        finding.id,
        finding.severity,
        finding.riskScore,
        priorityById.get(finding.id)?.rank ?? '',
        finding.kind,
        finding.ruleId,
        finding.title,
        finding.location?.path ?? '',
        finding.location?.startLine ?? '',
        finding.component?.name ?? '',
        finding.component?.version ?? '',
        Array.isArray(fixedVersions) ? fixedVersions[0] : '',
        finding.confidence,
        finding.scanner,
        finding.status,
        finding.taxonomy?.cwe ?? [],
        [...(finding.taxonomy?.owaspTop10 ?? []), ...(finding.taxonomy?.owaspLlmTop10 ?? [])],
        finding.taxonomy?.cve ?? [],
        finding.explanation?.suggestedFixes[0]?.title ?? finding.remediationHint ?? '',
        finding.firstSeenAt,
      ]
        .map(csvEscape)
        .join(','),
    );
  }

  return rows.join('\n');
}

export interface JsonReportOptions {
  summary?: ExecutiveSummary;
  priorities?: PrioritizedFinding[];
  pretty?: boolean;
  /** Omit snippets and explanations for a lightweight machine-readable feed. */
  minimal?: boolean;
}

/**
 * Canonical JSON export.
 *
 * Versioned from day one: consumers build on this shape, and changing it
 * silently would break them.
 */
export function toJson(result: ScanResult, options: JsonReportOptions = {}): string {
  const payload = {
    schemaVersion: '1.0',
    generator: { name: 'Sentinel AI', version: '0.1.0' },
    generatedAt: new Date().toISOString(),
    scan: {
      id: result.id,
      projectId: result.projectId,
      status: result.status,
      startedAt: result.startedAt,
      completedAt: result.completedAt,
      durationMs: result.durationMs,
      ...(result.error ? { error: result.error } : {}),
    },
    repository: result.repository,
    scores: result.scores,
    scannerRuns: result.scannerRuns,
    ...(options.summary ? { summary: options.summary } : {}),
    ...(options.priorities ? { priorities: options.priorities } : {}),
    findings: options.minimal
      ? result.findings.map((finding) => ({
          id: finding.id,
          fingerprint: finding.fingerprint,
          ruleId: finding.ruleId,
          title: finding.title,
          severity: finding.severity,
          kind: finding.kind,
          confidence: finding.confidence,
          riskScore: finding.riskScore,
          status: finding.status,
          path: finding.location?.path,
          line: finding.location?.startLine,
          taxonomy: finding.taxonomy,
        }))
      : result.findings,
    ...(result.sbom ? { sbom: result.sbom } : {}),
    ...(result.diff ? { diff: result.diff } : {}),
  };

  return JSON.stringify(payload, null, options.pretty === false ? 0 : 2);
}

/** Aggregate statistics for the dashboard and the `/stats` API. */
export function toStatistics(result: ScanResult) {
  const active = result.findings.filter((f) => !f.suppressed);

  const byKind: Record<string, number> = {};
  const byScanner: Record<string, number> = {};
  const byFile: Record<string, number> = {};
  const byRule: Record<string, number> = {};

  for (const finding of active) {
    byKind[finding.kind] = (byKind[finding.kind] ?? 0) + 1;
    byScanner[finding.scanner] = (byScanner[finding.scanner] ?? 0) + 1;
    byRule[finding.ruleId] = (byRule[finding.ruleId] ?? 0) + 1;
    const path = finding.location?.path;
    if (path) byFile[path] = (byFile[path] ?? 0) + 1;
  }

  const top = (record: Record<string, number>, limit: number) =>
    Object.entries(record)
      .sort(([, a], [, b]) => b - a)
      .slice(0, limit)
      .map(([name, count]) => ({ name, count }));

  return {
    scanId: result.id,
    totalFindings: active.length,
    suppressed: result.findings.length - active.length,
    counts: result.scores.counts,
    scores: {
      overall: result.scores.overall,
      grade: result.scores.grade,
      riskLevel: result.scores.riskLevel,
      categories: Object.fromEntries(result.scores.categories.map((c) => [c.category, c.score])),
    },
    byKind,
    byScanner,
    topFiles: top(byFile, 10),
    topRules: top(byRule, 10),
    repository: {
      name: result.repository.name,
      files: result.repository.fileCount,
      linesOfCode: result.repository.linesOfCode,
      languages: result.repository.languages,
    },
    coverage: {
      scannersRun: result.scannerRuns.filter((r) => r.status === 'ok').length,
      scannersFailed: result.scannerRuns.filter((r) => r.status === 'failed').length,
      scannersSkipped: result.scannerRuns.filter((r) => r.status === 'skipped').length,
      analyzedKinds: [
        ...new Set(result.scannerRuns.filter((r) => r.status === 'ok').map((r) => r.kind)),
      ],
    },
    durationMs: result.durationMs,
  };
}
