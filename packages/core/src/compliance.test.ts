import { describe, expect, it } from 'vitest';
import {
  FRAMEWORKS,
  OWASP_LLM_TOP_10,
  OWASP_TOP_10_2021,
  assessCompliance,
  getFramework,
  taxonomyTags,
} from './compliance.js';
import { normalizeFindings } from './normalize.js';
import type { RawFinding } from './types.js';

const sqlInjection: RawFinding = {
  ruleId: 'ts-sql-injection',
  title: 'SQL injection via string concatenation',
  severity: 'critical',
  kind: 'sast',
  location: { path: 'src/db.ts', startLine: 4 },
  taxonomy: { cwe: ['CWE-89'], owaspTop10: ['A03:2021-Injection'] },
};

const promptInjection: RawFinding = {
  ruleId: 'ai-indirect-prompt-injection',
  title: 'Retrieved content is concatenated into the system prompt',
  severity: 'high',
  kind: 'ai-security',
  location: { path: 'src/agent.ts', startLine: 20 },
  taxonomy: { owaspLlmTop10: ['LLM01:2025-Prompt Injection'] },
};

const ctx = { scanId: 'scan_1', scanner: 'native', scannerKind: 'native' as const };

describe('taxonomyTags', () => {
  it('extracts CWE, OWASP and kind tags', () => {
    const [finding] = normalizeFindings([sqlInjection], ctx);
    const tags = taxonomyTags(finding!);
    expect(tags).toContain('CWE-89');
    expect(tags).toContain('A03:2021');
    expect(tags).toContain('kind:sast');
  });

  it('flags findings carrying a CVE', () => {
    const [finding] = normalizeFindings(
      [{ ...sqlInjection, taxonomy: { cve: ['CVE-2024-1234'] } }],
      ctx,
    );
    expect(taxonomyTags(finding!)).toContain('has:cve');
  });
});

describe('assessCompliance', () => {
  it('fails the control a finding maps to', () => {
    const findings = normalizeFindings([sqlInjection], ctx);
    const report = assessCompliance(OWASP_TOP_10_2021, findings, 'scan_1', ['sast']);
    const injection = report.assessments.find((a) => a.controlId === 'A03:2021');
    expect(injection?.status).toBe('fail');
    expect(injection?.worstSeverity).toBe('critical');
    expect(injection?.findingIds).toHaveLength(1);
  });

  it('never reports pass for a domain that was not scanned', () => {
    const report = assessCompliance(OWASP_TOP_10_2021, [], 'scan_1', ['sast']);
    const misconfig = report.assessments.find((a) => a.controlId === 'A05:2021');
    // A05 depends on iac/config/container analysis, none of which ran.
    expect(misconfig?.status).toBe('needs-review');
    expect(misconfig?.evidence).toMatch(/did not cover/i);
  });

  it('passes a control when the relevant domain ran clean', () => {
    const report = assessCompliance(OWASP_TOP_10_2021, [], 'scan_1', [
      'sast',
      'iac',
      'config',
      'container',
    ]);
    expect(report.assessments.find((a) => a.controlId === 'A05:2021')?.status).toBe('pass');
  });

  it('excludes suppressed findings from the assessment', () => {
    const findings = normalizeFindings([sqlInjection], {
      ...ctx,
      suppressions: [{ ruleId: 'ts-sql-injection', reason: 'accepted' }],
    });
    const report = assessCompliance(OWASP_TOP_10_2021, findings, 'scan_1', ['sast']);
    expect(report.assessments.find((a) => a.controlId === 'A03:2021')?.status).toBe('pass');
  });

  it('maps AI findings onto the OWASP LLM framework', () => {
    const findings = normalizeFindings([promptInjection], ctx);
    const report = assessCompliance(OWASP_LLM_TOP_10, findings, 'scan_1', ['ai-security']);
    expect(report.assessments.find((a) => a.controlId === 'LLM01:2025')?.status).toBe('fail');
    expect(report.failed).toBe(1);
  });

  it('computes coverage over applicable controls only', () => {
    const findings = normalizeFindings([sqlInjection], ctx);
    const report = assessCompliance(OWASP_TOP_10_2021, findings, 'scan_1', ['sast']);
    expect(report.coveragePercent).toBeGreaterThanOrEqual(0);
    expect(report.coveragePercent).toBeLessThanOrEqual(100);
    expect(report.passed + report.failed + report.needsReview + report.notApplicable).toBe(
      OWASP_TOP_10_2021.controls.length,
    );
  });
});

describe('framework catalog', () => {
  it('exposes unique, well-formed frameworks', () => {
    const ids = FRAMEWORKS.map((f) => f.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const framework of FRAMEWORKS) {
      expect(framework.controls.length).toBeGreaterThan(0);
      expect(getFramework(framework.id)).toBe(framework);
      for (const control of framework.controls) {
        expect(control.mappedTaxonomy.length).toBeGreaterThan(0);
      }
    }
  });

  it('returns undefined for an unknown framework', () => {
    expect(getFramework('does-not-exist')).toBeUndefined();
  });
});
