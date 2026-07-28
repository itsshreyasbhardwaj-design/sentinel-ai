import { countBySeverity, emptySeverityCounts } from './severity.js';
import {
  SCORE_CATEGORIES,
  type CategoryScore,
  type Finding,
  type Grade,
  type HealthScores,
  type ScanKind,
  type ScoreCategory,
  type ScoreHistoryPoint,
  type Severity,
  type SeverityCounts,
} from './types.js';

/** Which analysis domains roll up into which score dimension. */
const KIND_TO_CATEGORY: Record<ScanKind, ScoreCategory> = {
  sast: 'code',
  dependencies: 'dependencies',
  secrets: 'secrets',
  container: 'infrastructure',
  iac: 'infrastructure',
  license: 'dependencies',
  sbom: 'dependencies',
  config: 'configuration',
  'ai-security': 'aiSafety',
};

export function categoryForKind(kind: ScanKind): ScoreCategory {
  return KIND_TO_CATEGORY[kind];
}

/**
 * Penalty applied per finding, before diminishing returns.
 *
 * The gap between `high` and `critical` is intentionally wide: one critical
 * should dominate the score in a way that ten mediums do not.
 */
const SEVERITY_PENALTY: Record<Severity, number> = {
  info: 0.4,
  low: 2,
  medium: 6,
  high: 16,
  critical: 34,
};

/**
 * Weight of each category in the overall score. Secrets and code weigh most:
 * a leaked live credential is an immediate incident, not a backlog item.
 */
const CATEGORY_WEIGHT: Record<ScoreCategory, number> = {
  code: 1.15,
  dependencies: 1,
  infrastructure: 0.95,
  secrets: 1.3,
  aiSafety: 1.05,
  configuration: 0.85,
};

/**
 * Findings of the same severity have decreasing marginal impact — the 40th
 * medium tells you much less than the first. Without this, a large legacy repo
 * scores 0 in every category and the score stops being actionable.
 */
function diminishingPenalty(count: number, unitPenalty: number): number {
  if (count <= 0) return 0;
  let total = 0;
  for (let i = 0; i < count; i += 1) {
    total += unitPenalty / (1 + i * 0.35);
  }
  return total;
}

export function gradeFor(score: number): Grade {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 65) return 'C';
  if (score >= 50) return 'D';
  return 'F';
}

export function riskLevelFor(score: number): HealthScores['riskLevel'] {
  if (score >= 90) return 'minimal';
  if (score >= 78) return 'low';
  if (score >= 60) return 'moderate';
  if (score >= 40) return 'elevated';
  return 'severe';
}

function describeCategory(counts: SeverityCounts, analyzed: boolean): string {
  if (!analyzed) return 'Not analyzed in this scan.';
  const parts: string[] = [];
  if (counts.critical) parts.push(`${counts.critical} critical`);
  if (counts.high) parts.push(`${counts.high} high`);
  if (counts.medium) parts.push(`${counts.medium} medium`);
  if (counts.low) parts.push(`${counts.low} low`);
  if (!parts.length) return 'No issues detected.';
  return `${parts.join(', ')} ${parts.length === 1 ? 'finding' : 'findings'} detected.`;
}

export interface ScoreInput {
  findings: readonly Finding[];
  /** Domains actually executed — lets us distinguish "clean" from "unchecked". */
  analyzedKinds: readonly ScanKind[];
}

/**
 * Compute per-category and overall health scores.
 *
 * Suppressed findings are excluded: accepting a risk is an explicit decision and
 * should not keep punishing the score forever.
 */
export function computeScores(input: ScoreInput): HealthScores {
  const active = input.findings.filter((f) => !f.suppressed && f.status !== 'false-positive');
  const analyzedCategories = new Set(input.analyzedKinds.map(categoryForKind));

  const categories: CategoryScore[] = SCORE_CATEGORIES.map((category) => {
    const relevant = active.filter((f) => categoryForKind(f.kind) === category);
    const counts = countBySeverity(relevant);
    const analyzed = analyzedCategories.has(category);

    let penalty = 0;
    for (const severity of Object.keys(SEVERITY_PENALTY) as Severity[]) {
      penalty += diminishingPenalty(counts[severity], SEVERITY_PENALTY[severity]);
    }

    const score = analyzed ? Math.max(0, Math.round(100 - penalty)) : 100;

    return {
      category,
      score,
      grade: gradeFor(score),
      findingCount: relevant.length,
      counts,
      analyzed,
      rationale: describeCategory(counts, analyzed),
    };
  });

  // Only analyzed categories contribute; an unscanned domain must not inflate
  // the overall score with a free 100.
  const scored = categories.filter((c) => c.analyzed);
  const overall = scored.length
    ? Math.round(
        scored.reduce((sum, c) => sum + c.score * CATEGORY_WEIGHT[c.category], 0) /
          scored.reduce((sum, c) => sum + CATEGORY_WEIGHT[c.category], 0),
      )
    : 100;

  return {
    overall,
    grade: gradeFor(overall),
    riskLevel: riskLevelFor(overall),
    categories,
    counts: active.length ? countBySeverity(active) : emptySeverityCounts(),
    totalFindings: active.length,
    computedAt: new Date().toISOString(),
  };
}

export function toHistoryPoint(
  scanId: string,
  scores: HealthScores,
  timestamp: string,
): ScoreHistoryPoint {
  const categories = Object.fromEntries(
    scores.categories.map((c) => [c.category, c.score]),
  ) as Record<ScoreCategory, number>;

  return { scanId, timestamp, overall: scores.overall, categories, counts: scores.counts };
}

export interface TrendSummary {
  direction: 'improving' | 'declining' | 'stable';
  delta: number;
  /** Percentage change relative to the earliest point. */
  changePercent: number;
  points: ScoreHistoryPoint[];
}

export function summarizeTrend(points: readonly ScoreHistoryPoint[]): TrendSummary {
  const ordered = [...points].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
  if (ordered.length < 2) {
    return { direction: 'stable', delta: 0, changePercent: 0, points: ordered };
  }

  const first = ordered[0]!;
  const last = ordered[ordered.length - 1]!;
  const delta = last.overall - first.overall;
  const changePercent = first.overall === 0 ? 0 : Math.round((delta / first.overall) * 1000) / 10;

  // A ±2 point wobble is noise, not a trend.
  const direction: TrendSummary['direction'] =
    Math.abs(delta) <= 2 ? 'stable' : delta > 0 ? 'improving' : 'declining';

  return { direction, delta, changePercent, points: ordered };
}

/** What changed between two scans of the same project. */
export function diffFindings(
  previous: readonly Finding[],
  current: readonly Finding[],
): { introduced: Finding[]; resolved: Finding[]; unchanged: Finding[] } {
  const previousMap = new Map(previous.map((f) => [f.fingerprint, f]));
  const currentMap = new Map(current.map((f) => [f.fingerprint, f]));

  return {
    introduced: current.filter((f) => !previousMap.has(f.fingerprint)),
    resolved: previous.filter((f) => !currentMap.has(f.fingerprint)),
    unchanged: current.filter((f) => previousMap.has(f.fingerprint)),
  };
}
