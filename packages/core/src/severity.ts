import { SEVERITIES, type Confidence, type Severity, type SeverityCounts } from './types.js';

const RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function severityRank(severity: Severity): number {
  return RANK[severity];
}

export function isAtLeast(severity: Severity, threshold: Severity): boolean {
  return RANK[severity] >= RANK[threshold];
}

export function maxSeverity(severities: readonly Severity[]): Severity | undefined {
  let best: Severity | undefined;
  for (const s of severities) {
    if (!best || RANK[s] > RANK[best]) best = s;
  }
  return best;
}

export function compareSeverityDesc(a: Severity, b: Severity): number {
  return RANK[b] - RANK[a];
}

export function emptySeverityCounts(): SeverityCounts {
  return { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
}

export function countBySeverity(items: readonly { severity: Severity }[]): SeverityCounts {
  const counts = emptySeverityCounts();
  for (const item of items) counts[item.severity] += 1;
  return counts;
}

/**
 * Map a CVSS v3.x base score onto our severity ladder, using the official
 * qualitative ratings from the CVSS v3.1 specification.
 */
export function severityFromCvss(score: number): Severity {
  if (!Number.isFinite(score) || score <= 0) return 'info';
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score >= 0.1) return 'low';
  return 'info';
}

/**
 * Normalize the many severity vocabularies third-party scanners use.
 * Unrecognized values fall back to `medium` rather than being dropped —
 * silently discarding a finding is worse than mis-ranking it.
 */
export function normalizeSeverity(raw: unknown, fallback: Severity = 'medium'): Severity {
  if (typeof raw === 'number') return severityFromCvss(raw);
  if (typeof raw !== 'string') return fallback;

  const value = raw.trim().toLowerCase();
  if ((SEVERITIES as readonly string[]).includes(value)) return value as Severity;

  switch (value) {
    case 'crit':
    case 'blocker':
    case 'fatal':
    case 'severe':
      return 'critical';
    case 'error':
    case 'major':
    case 'important':
      return 'high';
    case 'warning':
    case 'warn':
    case 'moderate':
    case 'minor':
      return 'medium';
    case 'note':
    case 'style':
    case 'informational':
    case 'unknown':
    case 'none':
    case 'negligible':
      return value === 'negligible' ? 'low' : 'info';
    default: {
      const numeric = Number.parseFloat(value);
      if (Number.isFinite(numeric)) return severityFromCvss(numeric);
      return fallback;
    }
  }
}

const CONFIDENCE_WEIGHT: Record<Confidence, number> = {
  low: 0.55,
  medium: 0.8,
  high: 1,
};

const SEVERITY_WEIGHT: Record<Severity, number> = {
  info: 5,
  low: 25,
  medium: 50,
  high: 78,
  critical: 96,
};

/**
 * Blend severity and confidence into a 0..100 risk score.
 *
 * Confidence attenuates rather than dominates: a low-confidence critical still
 * outranks a high-confidence low, which matches how triage actually works.
 */
export function computeRiskScore(severity: Severity, confidence: Confidence): number {
  const base = SEVERITY_WEIGHT[severity];
  const weight = CONFIDENCE_WEIGHT[confidence];
  // Retain 60% of the base regardless of confidence so ranking stays severity-first.
  const score = base * (0.6 + 0.4 * weight);
  return Math.round(Math.min(100, Math.max(0, score)));
}

export function normalizeConfidence(raw: unknown, fallback: Confidence = 'medium'): Confidence {
  if (typeof raw === 'number') {
    if (raw >= 0.8) return 'high';
    if (raw >= 0.5) return 'medium';
    return 'low';
  }
  if (typeof raw !== 'string') return fallback;
  const value = raw.trim().toLowerCase();
  if (value === 'high' || value === 'medium' || value === 'low') return value;
  return fallback;
}
