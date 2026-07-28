import { describe, expect, it } from 'vitest';
import {
  computeScores,
  diffFindings,
  gradeFor,
  summarizeTrend,
  toHistoryPoint,
} from './scoring.js';
import { normalizeFindings } from './normalize.js';
import type { Finding, RawFinding, ScanKind, ScoreHistoryPoint, Severity } from './types.js';

function makeFindings(
  specs: Array<{ severity: Severity; kind: ScanKind; rule?: string }>,
): Finding[] {
  const raw: RawFinding[] = specs.map((spec, i) => ({
    ruleId: spec.rule ?? `rule-${i}`,
    title: `Finding ${i}`,
    severity: spec.severity,
    kind: spec.kind,
    location: { path: `src/file-${i}.ts`, startLine: i + 1, snippet: `line ${i}` },
  }));
  return normalizeFindings(raw, { scanId: 'scan_1', scanner: 'test', scannerKind: 'native' });
}

describe('computeScores', () => {
  it('gives a clean repository a perfect score', () => {
    const scores = computeScores({ findings: [], analyzedKinds: ['sast', 'secrets'] });
    expect(scores.overall).toBe(100);
    expect(scores.grade).toBe('A');
    expect(scores.riskLevel).toBe('minimal');
  });

  it('penalizes critical findings far more than mediums', () => {
    const withCritical = computeScores({
      findings: makeFindings([{ severity: 'critical', kind: 'sast' }]),
      analyzedKinds: ['sast'],
    });
    const withMediums = computeScores({
      findings: makeFindings([
        { severity: 'medium', kind: 'sast' },
        { severity: 'medium', kind: 'sast' },
      ]),
      analyzedKinds: ['sast'],
    });
    expect(withCritical.overall).toBeLessThan(withMediums.overall);
  });

  it('applies diminishing returns so large repos stay above zero', () => {
    const many = makeFindings(
      Array.from({ length: 60 }, () => ({ severity: 'medium' as const, kind: 'sast' as const })),
    );
    const scores = computeScores({ findings: many, analyzedKinds: ['sast'] });
    expect(scores.overall).toBeGreaterThan(0);
    expect(scores.overall).toBeLessThan(60);
  });

  it('never lets an unscanned category inflate the overall score', () => {
    const findings = makeFindings([{ severity: 'critical', kind: 'sast' }]);
    const narrow = computeScores({ findings, analyzedKinds: ['sast'] });
    const wide = computeScores({ findings, analyzedKinds: ['sast', 'iac', 'config', 'secrets'] });
    // Adding clean categories should raise the score, but only because they were
    // genuinely analyzed — the SAST-only run must not be graded against 100s.
    expect(wide.overall).toBeGreaterThan(narrow.overall);
    expect(narrow.categories.find((c) => c.category === 'infrastructure')?.analyzed).toBe(false);
  });

  it('excludes suppressed findings from scoring', () => {
    const findings = makeFindings([{ severity: 'critical', kind: 'sast' }]).map((f) => ({
      ...f,
      suppressed: true,
    }));
    expect(computeScores({ findings, analyzedKinds: ['sast'] }).overall).toBe(100);
  });

  it('routes each kind into the right category', () => {
    const scores = computeScores({
      findings: makeFindings([{ severity: 'high', kind: 'ai-security' }]),
      analyzedKinds: ['ai-security'],
    });
    const ai = scores.categories.find((c) => c.category === 'aiSafety');
    expect(ai?.findingCount).toBe(1);
    expect(ai?.score).toBeLessThan(100);
  });
});

describe('gradeFor', () => {
  it('maps score bands to letters', () => {
    expect(gradeFor(95)).toBe('A');
    expect(gradeFor(85)).toBe('B');
    expect(gradeFor(70)).toBe('C');
    expect(gradeFor(55)).toBe('D');
    expect(gradeFor(10)).toBe('F');
  });
});

describe('summarizeTrend', () => {
  const point = (overall: number, timestamp: string): ScoreHistoryPoint => ({
    ...toHistoryPoint(
      `scan-${overall}`,
      computeScores({ findings: [], analyzedKinds: ['sast'] }),
      timestamp,
    ),
    overall,
  });

  it('is stable for a single point', () => {
    expect(summarizeTrend([point(80, '2026-01-01')]).direction).toBe('stable');
  });

  it('detects improvement and decline', () => {
    expect(summarizeTrend([point(60, '2026-01-01'), point(85, '2026-02-01')]).direction).toBe(
      'improving',
    );
    expect(summarizeTrend([point(85, '2026-01-01'), point(60, '2026-02-01')]).direction).toBe(
      'declining',
    );
  });

  it('treats small wobbles as noise', () => {
    expect(summarizeTrend([point(80, '2026-01-01'), point(81, '2026-02-01')]).direction).toBe(
      'stable',
    );
  });

  it('orders points chronologically regardless of input order', () => {
    const trend = summarizeTrend([point(90, '2026-03-01'), point(50, '2026-01-01')]);
    expect(trend.points[0]?.overall).toBe(50);
    expect(trend.delta).toBe(40);
  });
});

describe('diffFindings', () => {
  it('classifies introduced, resolved and unchanged by fingerprint', () => {
    const previous = makeFindings([
      { severity: 'high', kind: 'sast', rule: 'a' },
      { severity: 'low', kind: 'sast', rule: 'b' },
    ]);
    const current = [
      previous[0]!,
      ...makeFindings([{ severity: 'high', kind: 'sast', rule: 'c' }]),
    ];

    const diff = diffFindings(previous, current);
    expect(diff.resolved.map((f) => f.ruleId)).toEqual(['b']);
    expect(diff.unchanged).toHaveLength(1);
    expect(diff.introduced).toHaveLength(1);
  });
});
