import { computeFingerprint, findingIdFromFingerprint } from './id.js';
import { compareSeverityDesc, computeRiskScore, normalizeConfidence } from './severity.js';
import type { Finding, RawFinding, Severity } from './types.js';

export interface NormalizeContext {
  scanId: string;
  scanner: string;
  scannerKind: 'native' | 'external';
  now?: string;
  /** Fingerprints seen in previous scans, mapped to their original sighting. */
  previouslySeen?: Map<string, string>;
  suppressions?: SuppressionRule[];
}

export interface SuppressionRule {
  /** Glob-ish path prefix or `*` wildcard. */
  path?: string;
  ruleId?: string;
  reason: string;
  /** ISO date after which the suppression stops applying. */
  expiresAt?: string;
}

const MAX_SNIPPET_LENGTH = 400;

/** Truncate long snippets so a minified line cannot blow up storage or the UI. */
function trimSnippet(snippet: string | undefined): string | undefined {
  if (!snippet) return undefined;
  const collapsed = snippet.replace(/\r\n/g, '\n');
  if (collapsed.length <= MAX_SNIPPET_LENGTH) return collapsed;
  return `${collapsed.slice(0, MAX_SNIPPET_LENGTH)}…`;
}

/** Normalize to POSIX separators and strip leading `./`, so paths compare cleanly. */
export function normalizePath(path: string): string {
  return path.replace(/\\/g, '/').replace(/^\.\//, '');
}

/**
 * Matched against the *normalized* path — matching before normalization means
 * `./src/db.ts` silently fails to match a `src/*` rule, which would make
 * suppressions look broken at random.
 */
function matchesSuppression(
  finding: RawFinding,
  normalizedPath: string | undefined,
  rule: SuppressionRule,
  now: Date,
): boolean {
  if (rule.expiresAt && new Date(rule.expiresAt) < now) return false;
  if (rule.ruleId && rule.ruleId !== finding.ruleId && rule.ruleId !== '*') return false;
  if (rule.path) {
    const path = normalizedPath;
    if (!path) return false;
    const pattern = normalizePath(rule.path);
    if (pattern.endsWith('*')) {
      if (!path.startsWith(pattern.slice(0, -1))) return false;
    } else if (path !== pattern && !path.startsWith(`${pattern}/`)) {
      return false;
    }
  }
  return true;
}

/**
 * Turn scanner output into canonical findings: stable identity, computed risk,
 * suppression applied, and paths/snippets sanitized.
 */
export function normalizeFindings(raw: readonly RawFinding[], ctx: NormalizeContext): Finding[] {
  const now = ctx.now ?? new Date().toISOString();
  const nowDate = new Date(now);
  const suppressions = ctx.suppressions ?? [];

  return raw.map((item) => {
    const location = item.location
      ? {
          ...item.location,
          path: normalizePath(item.location.path),
          snippet: trimSnippet(item.location.snippet),
        }
      : undefined;

    const fingerprint = computeFingerprint({
      ruleId: item.ruleId,
      path: location?.path,
      snippet: location?.snippet,
      component: item.component
        ? `${item.component.name}@${item.component.version ?? '*'}`
        : undefined,
      discriminator: item.taxonomy?.cve?.join(',') ?? undefined,
    });

    const confidence = normalizeConfidence(item.confidence);
    const suppression = suppressions.find((rule) =>
      matchesSuppression(item, location?.path, rule, nowDate),
    );

    return {
      ...item,
      location,
      id: findingIdFromFingerprint(ctx.scanId, fingerprint),
      fingerprint,
      scanId: ctx.scanId,
      scanner: ctx.scanner,
      scannerKind: ctx.scannerKind,
      confidence,
      status: suppression ? 'accepted-risk' : 'open',
      riskScore: computeRiskScore(item.severity, confidence),
      firstSeenAt: ctx.previouslySeen?.get(fingerprint) ?? now,
      lastSeenAt: now,
      ...(suppression ? { suppressed: true, suppressionReason: suppression.reason } : {}),
    } satisfies Finding;
  });
}

/**
 * Collapse findings that different scanners reported for the same underlying
 * issue. The highest-severity copy wins; the loser's scanner is recorded in
 * metadata so corroboration is visible rather than lost.
 */
export function dedupeFindings(findings: readonly Finding[]): Finding[] {
  const byFingerprint = new Map<string, Finding>();

  for (const finding of findings) {
    const existing = byFingerprint.get(finding.fingerprint);
    if (!existing) {
      byFingerprint.set(finding.fingerprint, finding);
      continue;
    }

    const winner =
      compareSeverityDesc(finding.severity, existing.severity) < 0 ? finding : existing;
    const loser = winner === finding ? existing : finding;
    const corroborating = new Set<string>([
      ...((winner.metadata?.corroboratedBy as string[] | undefined) ?? []),
      loser.scanner,
    ]);

    byFingerprint.set(finding.fingerprint, {
      ...winner,
      // Agreement between independent scanners is strong evidence; promote it.
      confidence: winner.scanner !== loser.scanner ? 'high' : winner.confidence,
      riskScore:
        winner.scanner !== loser.scanner
          ? computeRiskScore(winner.severity, 'high')
          : winner.riskScore,
      metadata: { ...winner.metadata, corroboratedBy: [...corroborating] },
    });
  }

  return [...byFingerprint.values()];
}

/** Highest risk first, then severity, then path — deterministic for snapshots. */
export function sortFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    if (b.riskScore !== a.riskScore) return b.riskScore - a.riskScore;
    const bySeverity = compareSeverityDesc(a.severity, b.severity);
    if (bySeverity !== 0) return bySeverity;
    const pathA = a.location?.path ?? '';
    const pathB = b.location?.path ?? '';
    if (pathA !== pathB) return pathA.localeCompare(pathB);
    return (a.location?.startLine ?? 0) - (b.location?.startLine ?? 0);
  });
}

export interface FindingFilter {
  severity?: Severity[];
  kind?: string[];
  status?: string[];
  scanner?: string[];
  path?: string;
  search?: string;
  suppressed?: boolean;
}

export function filterFindings(findings: readonly Finding[], filter: FindingFilter): Finding[] {
  const search = filter.search?.toLowerCase();

  return findings.filter((finding) => {
    if (filter.severity?.length && !filter.severity.includes(finding.severity)) return false;
    if (filter.kind?.length && !filter.kind.includes(finding.kind)) return false;
    if (filter.status?.length && !filter.status.includes(finding.status)) return false;
    if (filter.scanner?.length && !filter.scanner.includes(finding.scanner)) return false;
    if (filter.suppressed === false && finding.suppressed) return false;
    if (filter.suppressed === true && !finding.suppressed) return false;
    if (filter.path && !(finding.location?.path ?? '').includes(filter.path)) return false;
    if (search) {
      const haystack = [
        finding.title,
        finding.description ?? '',
        finding.ruleId,
        finding.location?.path ?? '',
        finding.component?.name ?? '',
      ]
        .join(' ')
        .toLowerCase();
      if (!haystack.includes(search)) return false;
    }
    return true;
  });
}
