import { describe, expect, it } from 'vitest';
import { normalizeFindings, type ScanResult } from '@sentinel/core';
import { toPdf } from './pdf.js';

/**
 * Regression tests for text handling in the PDF writer.
 *
 * The interesting failures here are silent: text that renders as garbage or as
 * two words welded together still produces a "valid" PDF, so these assertions
 * check the rendered content stream rather than just the file structure.
 */

function resultWith(text: string): ScanResult {
  const findings = normalizeFindings(
    [
      {
        ruleId: 'test-rule',
        title: 'Test finding',
        description: text,
        severity: 'high',
        kind: 'sast',
        location: { path: 'src/a.ts', startLine: 1 },
      },
    ],
    { scanId: 's', scanner: 'native', scannerKind: 'native' },
  );

  return {
    id: 'scan_1',
    projectId: 'p',
    status: 'completed',
    target: { type: 'local', path: '/repo' },
    options: {},
    repository: { name: 'demo', languages: [], fileCount: 1, totalBytes: 1, linesOfCode: 1 },
    findings,
    scannerRuns: [],
    scores: {
      overall: 70,
      grade: 'C',
      riskLevel: 'moderate',
      categories: [],
      counts: { info: 0, low: 0, medium: 0, high: 1, critical: 0 },
      totalFindings: 1,
      computedAt: new Date().toISOString(),
    },
    startedAt: '2026-07-28T10:00:00.000Z',
    completedAt: '2026-07-28T10:00:01.000Z',
    durationMs: 1000,
  };
}

describe('PDF text handling', () => {
  it('converts newlines to spaces instead of deleting them', () => {
    // Deleting the newline welds the words: "credential.In this case".
    const text = toPdf(resultWith('First sentence.\n\nSecond sentence.')).toString('latin1');
    expect(text).toContain('First sentence.');
    expect(text).not.toContain('sentence.Second');
  });

  it('escapes PDF string delimiters', () => {
    const text = toPdf(resultWith('Value (parenthesized) with \\ backslash')).toString('latin1');
    // Unescaped parentheses would terminate the string literal early and
    // corrupt every subsequent operator in the content stream.
    expect(text).toContain('\\(parenthesized\\)');
    expect(text).toContain('\\\\');
  });

  it('substitutes typographic characters rather than dropping them', () => {
    const text = toPdf(resultWith('Use “smart quotes” — and an ellipsis…')).toString('latin1');
    expect(text).toContain('"smart quotes"');
    expect(text).toContain('- and an ellipsis...');
  });

  it('drops characters with no Latin-1 representation without corrupting output', () => {
    const pdf = toPdf(resultWith('日本語 テキスト and 🎉 emoji'));
    const text = pdf.toString('latin1');
    expect(text).toContain('and');
    expect(text).toContain('emoji');
    expect(text.startsWith('%PDF-1.7')).toBe(true);
  });

  it('hard-splits a word longer than the line width', () => {
    const long = 'a'.repeat(500);
    const pdf = toPdf(resultWith(long));
    expect(pdf.length).toBeGreaterThan(1000);
    // Must not produce a single overflowing line.
    const lines = pdf.toString('latin1').match(/\(a+\) Tj/g) ?? [];
    expect(lines.length).toBeGreaterThan(1);
  });

  it('handles empty and whitespace-only text', () => {
    expect(() => toPdf(resultWith(''))).not.toThrow();
    expect(() => toPdf(resultWith('   \n\n   '))).not.toThrow();
  });
});
