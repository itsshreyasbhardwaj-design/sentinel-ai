import { describe, expect, it } from 'vitest';
import {
  computeRiskScore,
  countBySeverity,
  isAtLeast,
  maxSeverity,
  normalizeConfidence,
  normalizeSeverity,
  severityFromCvss,
} from './severity.js';

describe('normalizeSeverity', () => {
  it('passes through canonical values', () => {
    expect(normalizeSeverity('critical')).toBe('critical');
    expect(normalizeSeverity('LOW')).toBe('low');
    expect(normalizeSeverity('  High  ')).toBe('high');
  });

  it('maps third-party vocabularies', () => {
    expect(normalizeSeverity('BLOCKER')).toBe('critical');
    expect(normalizeSeverity('ERROR')).toBe('high');
    expect(normalizeSeverity('WARNING')).toBe('medium');
    expect(normalizeSeverity('note')).toBe('info');
    expect(normalizeSeverity('negligible')).toBe('low');
  });

  it('treats numeric input as a CVSS score', () => {
    expect(normalizeSeverity(9.8)).toBe('critical');
    expect(normalizeSeverity('7.5')).toBe('high');
    expect(normalizeSeverity(4.0)).toBe('medium');
  });

  it('falls back rather than dropping unknown values', () => {
    expect(normalizeSeverity('bananas')).toBe('medium');
    expect(normalizeSeverity(undefined, 'low')).toBe('low');
    expect(normalizeSeverity(null)).toBe('medium');
  });
});

describe('severityFromCvss', () => {
  it('follows the CVSS v3.1 qualitative ratings', () => {
    expect(severityFromCvss(0)).toBe('info');
    expect(severityFromCvss(0.1)).toBe('low');
    expect(severityFromCvss(3.9)).toBe('low');
    expect(severityFromCvss(4.0)).toBe('medium');
    expect(severityFromCvss(6.9)).toBe('medium');
    expect(severityFromCvss(7.0)).toBe('high');
    expect(severityFromCvss(8.9)).toBe('high');
    expect(severityFromCvss(9.0)).toBe('critical');
  });

  it('is defensive about garbage input', () => {
    expect(severityFromCvss(Number.NaN)).toBe('info');
    expect(severityFromCvss(-1)).toBe('info');
  });
});

describe('computeRiskScore', () => {
  it('keeps ranking severity-first even at low confidence', () => {
    expect(computeRiskScore('critical', 'low')).toBeGreaterThan(computeRiskScore('high', 'high'));
    expect(computeRiskScore('high', 'low')).toBeGreaterThan(computeRiskScore('medium', 'high'));
  });

  it('rewards higher confidence within a severity', () => {
    expect(computeRiskScore('high', 'high')).toBeGreaterThan(computeRiskScore('high', 'medium'));
    expect(computeRiskScore('high', 'medium')).toBeGreaterThan(computeRiskScore('high', 'low'));
  });

  it('stays inside 0..100', () => {
    for (const severity of ['info', 'low', 'medium', 'high', 'critical'] as const) {
      for (const confidence of ['low', 'medium', 'high'] as const) {
        const score = computeRiskScore(severity, confidence);
        expect(score).toBeGreaterThanOrEqual(0);
        expect(score).toBeLessThanOrEqual(100);
      }
    }
  });
});

describe('helpers', () => {
  it('isAtLeast respects the ladder', () => {
    expect(isAtLeast('critical', 'high')).toBe(true);
    expect(isAtLeast('high', 'high')).toBe(true);
    expect(isAtLeast('medium', 'high')).toBe(false);
  });

  it('maxSeverity returns undefined for an empty list', () => {
    expect(maxSeverity([])).toBeUndefined();
    expect(maxSeverity(['low', 'critical', 'medium'])).toBe('critical');
  });

  it('countBySeverity tallies every bucket', () => {
    const counts = countBySeverity([
      { severity: 'low' },
      { severity: 'low' },
      { severity: 'critical' },
    ]);
    expect(counts).toEqual({ info: 0, low: 2, medium: 0, high: 0, critical: 1 });
  });

  it('normalizeConfidence accepts numeric probabilities', () => {
    expect(normalizeConfidence(0.95)).toBe('high');
    expect(normalizeConfidence(0.6)).toBe('medium');
    expect(normalizeConfidence(0.2)).toBe('low');
  });
});
