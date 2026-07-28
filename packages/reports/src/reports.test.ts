import { describe, expect, it } from 'vitest';
import { normalizeFindings, silentLogger, type Finding, type ScanResult } from '@sentinel/core';
import { KnowledgeBaseAnalyst, enrichScanResult } from '@sentinel/ai';
import { EXPORT_FORMATS, exportReport } from './index.js';
import { toSarif } from './sarif.js';
import { toMarkdown, toPullRequestComment } from './markdown.js';
import { toHtml } from './html.js';
import { csvEscape, toCsv, toJson, toStatistics } from './tabular.js';
import { toPdf } from './pdf.js';

function makeFindings(): Finding[] {
  return normalizeFindings(
    [
      {
        ruleId: 'js-sql-injection',
        title: 'SQL query built by string concatenation',
        description: 'A SQL statement is assembled from a template literal.',
        severity: 'critical',
        kind: 'sast',
        confidence: 'high',
        location: { path: 'src/api/users.ts', startLine: 12, snippet: 'db.query(`SELECT ${id}`)' },
        taxonomy: { cwe: ['CWE-89'], owaspTop10: ['A03:2021-Injection'] },
        remediationHint: 'Use parameterized queries.',
      },
      {
        ruleId: 'dependency-GHSA-p6mc-m468-83gg',
        title: 'lodash@4.17.15: Prototype pollution',
        description: 'Prototype pollution in lodash.',
        severity: 'high',
        kind: 'dependencies',
        confidence: 'high',
        location: { path: 'package.json', startLine: 1 },
        component: { name: 'lodash', version: '4.17.15', ecosystem: 'npm' },
        taxonomy: { cve: ['CVE-2020-8203'], cwe: ['CWE-1321'] },
        metadata: { fixedVersions: ['4.17.21'] },
      },
      {
        ruleId: 'ai-indirect-prompt-injection',
        title: 'Retrieved content placed into a prompt without isolation',
        severity: 'high',
        kind: 'ai-security',
        confidence: 'medium',
        location: { path: 'src/agent.py', startLine: 24 },
        taxonomy: { owaspLlmTop10: ['LLM01:2025-Prompt Injection'], cwe: ['CWE-1427'] },
      },
      {
        ruleId: 'js-insecure-cookie',
        title: 'Session cookie missing security attributes',
        severity: 'low',
        kind: 'sast',
        confidence: 'medium',
        location: { path: 'src/session.ts', startLine: 8 },
      },
    ],
    { scanId: 'scan_abc', scanner: 'native-sast', scannerKind: 'native' },
  );
}

function makeResult(findings: Finding[] = makeFindings()): ScanResult {
  return {
    id: 'scan_abc',
    projectId: 'proj_1',
    status: 'completed',
    target: { type: 'github', owner: 'acme', repo: 'web' },
    options: { allowNetwork: false },
    repository: {
      name: 'acme/web',
      url: 'https://github.com/acme/web',
      ref: 'main',
      commit: 'a1b2c3d4e5f6a7b8',
      languages: [
        { language: 'typescript', files: 40, bytes: 90_000, percent: 78.2 },
        { language: 'python', files: 8, bytes: 25_000, percent: 21.8 },
      ],
      fileCount: 48,
      totalBytes: 115_000,
      linesOfCode: 4200,
    },
    findings,
    scannerRuns: [
      {
        scanner: 'native-sast',
        kind: 'sast',
        scannerKind: 'native',
        status: 'ok',
        durationMs: 120,
        findingCount: 2,
      },
      {
        scanner: 'native-dependencies',
        kind: 'dependencies',
        scannerKind: 'native',
        status: 'ok',
        durationMs: 40,
        findingCount: 1,
      },
      {
        scanner: 'native-ai-security',
        kind: 'ai-security',
        scannerKind: 'native',
        status: 'ok',
        durationMs: 30,
        findingCount: 1,
      },
      {
        scanner: 'semgrep',
        kind: 'sast',
        scannerKind: 'external',
        status: 'skipped',
        durationMs: 0,
        findingCount: 0,
        reason: 'semgrep is not installed',
      },
      {
        scanner: 'trivy',
        kind: 'dependencies',
        scannerKind: 'external',
        status: 'failed',
        durationMs: 5,
        findingCount: 0,
        reason: 'database unavailable',
      },
    ],
    scores: {
      overall: 48,
      grade: 'F',
      riskLevel: 'elevated',
      categories: [
        {
          category: 'code',
          score: 52,
          grade: 'D',
          findingCount: 2,
          counts: { info: 0, low: 1, medium: 0, high: 0, critical: 1 },
          analyzed: true,
          rationale: '1 critical, 1 low findings detected.',
        },
        {
          category: 'dependencies',
          score: 64,
          grade: 'C',
          findingCount: 1,
          counts: { info: 0, low: 0, medium: 0, high: 1, critical: 0 },
          analyzed: true,
          rationale: '1 high finding detected.',
        },
        {
          category: 'aiSafety',
          score: 70,
          grade: 'C',
          findingCount: 1,
          counts: { info: 0, low: 0, medium: 0, high: 1, critical: 0 },
          analyzed: true,
          rationale: '1 high finding detected.',
        },
        {
          category: 'secrets',
          score: 100,
          grade: 'A',
          findingCount: 0,
          counts: { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
          analyzed: false,
          rationale: 'Not analyzed in this scan.',
        },
        {
          category: 'infrastructure',
          score: 100,
          grade: 'A',
          findingCount: 0,
          counts: { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
          analyzed: false,
          rationale: 'Not analyzed in this scan.',
        },
        {
          category: 'configuration',
          score: 100,
          grade: 'A',
          findingCount: 0,
          counts: { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
          analyzed: false,
          rationale: 'Not analyzed in this scan.',
        },
      ],
      counts: { info: 0, low: 1, medium: 0, high: 2, critical: 1 },
      totalFindings: 4,
      computedAt: new Date().toISOString(),
    },
    startedAt: '2026-07-28T10:00:00.000Z',
    completedAt: '2026-07-28T10:00:12.000Z',
    durationMs: 12_000,
  };
}

async function enriched() {
  return enrichScanResult(makeResult(), {
    analyst: new KnowledgeBaseAnalyst(),
    logger: silentLogger,
  });
}

describe('SARIF export', () => {
  it('produces a valid SARIF 2.1.0 document', () => {
    const sarif = toSarif(makeResult());
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toContain('sarif-schema-2.1.0.json');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0]?.tool.driver.name).toBe('Sentinel AI');
  });

  it('emits one rule per distinct ruleId with valid result indices', () => {
    const sarif = toSarif(makeResult());
    const run = sarif.runs[0]!;
    expect(run.tool.driver.rules).toHaveLength(4);

    for (const result of run.results) {
      expect(run.tool.driver.rules[result.ruleIndex]?.id).toBe(result.ruleId);
    }
  });

  it('maps severities onto SARIF levels and GitHub security-severity', () => {
    const run = toSarif(makeResult()).runs[0]!;
    const critical = run.results.find((r) => r.ruleId === 'js-sql-injection');
    const low = run.results.find((r) => r.ruleId === 'js-insecure-cookie');

    expect(critical?.level).toBe('error');
    expect(low?.level).toBe('note');

    const criticalRule = run.tool.driver.rules.find((r) => r.id === 'js-sql-injection');
    expect(criticalRule?.properties?.['security-severity']).toBe('9.5');
  });

  it('carries the stable fingerprint so alerts track across commits', () => {
    const run = toSarif(makeResult()).runs[0]!;
    for (const result of run.results) {
      expect(result.partialFingerprints['sentinelFingerprint']).toHaveLength(32);
    }
  });

  it('omits suppressed findings entirely', () => {
    const findings = makeFindings().map((f, i) => (i === 0 ? { ...f, suppressed: true } : f));
    const run = toSarif(makeResult(findings)).runs[0]!;
    expect(run.results.find((r) => r.ruleId === 'js-sql-injection')).toBeUndefined();
  });

  it('records failed scanners as tool notifications', () => {
    const run = toSarif(makeResult()).runs[0]!;
    const notifications = run.invocations[0]?.toolExecutionNotifications ?? [];
    expect(notifications.length).toBe(1);
    expect(notifications[0]?.message.text).toContain('trivy');
  });

  it('includes version control provenance', () => {
    const run = toSarif(makeResult()).runs[0]!;
    expect(run.versionControlProvenance?.[0]?.repositoryUri).toBe('https://github.com/acme/web');
    expect(run.versionControlProvenance?.[0]?.revisionId).toBe('a1b2c3d4e5f6a7b8');
  });

  it('round-trips through JSON', () => {
    expect(() => JSON.parse(JSON.stringify(toSarif(makeResult())))).not.toThrow();
  });
});

describe('Markdown export', () => {
  it('renders the header, scores and findings', async () => {
    const { result, summary, priorities } = await enriched();
    const markdown = toMarkdown(result, { summary, priorities });

    expect(markdown).toContain('# Security Report: acme/web');
    expect(markdown).toContain('Score 48/100');
    expect(markdown).toContain('SQL query built by string concatenation');
    expect(markdown).toContain('Business impact');
  });

  it('always includes the scanner coverage table', async () => {
    const { result, summary } = await enriched();
    const markdown = toMarkdown(result, { summary });
    expect(markdown).toContain('## Scanner coverage');
    expect(markdown).toContain('semgrep is not installed');
    expect(markdown).toContain('database unavailable');
  });

  it('surfaces caveats so coverage is never overstated', async () => {
    const { result, summary } = await enriched();
    const markdown = toMarkdown(result, { summary });
    expect(markdown).toContain('## Caveats');
    expect(markdown.toLowerCase()).toContain('network access was disabled');
  });

  it('escapes pipes so tables do not break', () => {
    const findings = makeFindings();
    findings[0]!.title = 'Injection | with | pipes';
    const markdown = toMarkdown(makeResult(findings), { compact: true });
    expect(markdown).toContain('Injection \\| with \\| pipes');
  });

  it('renders compliance sections when frameworks are requested', async () => {
    const { result, summary } = await enriched();
    const markdown = toMarkdown(result, { summary, frameworks: ['owasp-top-10-2021'] });
    expect(markdown).toContain('OWASP Top 10 2021');
    expect(markdown).toContain('A03:2021');
  });

  it('reports a failed scan without pretending it succeeded', () => {
    const failed: ScanResult = { ...makeResult([]), status: 'failed', error: 'Clone failed' };
    const markdown = toMarkdown(failed);
    expect(markdown).toContain('did not complete');
    expect(markdown).toContain('Clone failed');
    expect(markdown).not.toContain('## Findings');
  });

  it('states clearly when there are no findings', () => {
    expect(toMarkdown(makeResult([]))).toContain('No open findings');
  });

  it('keeps pull-request comments under the GitHub size limit', async () => {
    const many = Array.from({ length: 400 }, () => makeFindings()).flat();
    const comment = toPullRequestComment(makeResult(many));
    expect(comment.length).toBeLessThanOrEqual(65_000);
  });

  it('links to files when a repository base URL is supplied', () => {
    const markdown = toMarkdown(makeResult(), {
      compact: true,
      repoUrlBase: 'https://github.com/acme/web/blob/main',
    });
    expect(markdown).toContain('https://github.com/acme/web/blob/main/src/api/users.ts#L12');
  });
});

describe('HTML export', () => {
  it('produces a complete standalone document', async () => {
    const { result, summary, priorities } = await enriched();
    const html = toHtml(result, { summary, priorities });

    expect(html.startsWith('<!doctype html>')).toBe(true);
    expect(html).toContain('</html>');
    expect(html).toContain('acme/web');
    expect(html).toContain('<style>');
  });

  it('references no external resources', async () => {
    const { result, summary } = await enriched();
    const html = toHtml(result, { summary });

    // Everything must be inlined: no CDN, no fonts, no scripts, no images.
    expect(html).not.toMatch(/<script/i);
    expect(html).not.toMatch(/<link[^>]+href=["']https?:/i);
    expect(html).not.toMatch(/src=["']https?:/i);
    expect(html).not.toMatch(/@import\s+url\(/i);
  });

  it('escapes HTML in finding content', () => {
    const findings = makeFindings();
    findings[0]!.title = '<img src=x onerror=alert(1)>';
    findings[0]!.location = {
      path: 'src/x.ts',
      startLine: 1,
      snippet: '<script>alert(1)</script>',
    };

    const html = toHtml(makeResult(findings));
    expect(html).not.toContain('<img src=x onerror=');
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
  });

  it('renders compliance and coverage sections', async () => {
    const { result, summary } = await enriched();
    const html = toHtml(result, { summary, frameworks: ['owasp-llm-top-10-2025'] });
    expect(html).toContain('LLM01:2025');
    expect(html).toContain('Scanner coverage');
    expect(html).toContain('Caveats');
  });

  it('handles a failed scan', () => {
    const failed: ScanResult = { ...makeResult([]), status: 'failed', error: 'Clone failed' };
    const html = toHtml(failed);
    expect(html).toContain('Scan did not complete');
    expect(html).toContain('Clone failed');
  });
});

describe('CSV export', () => {
  it('emits a header and one row per finding', () => {
    const csv = toCsv(makeResult());
    const lines = csv.split('\n');
    expect(lines[0]).toContain('severity,riskScore');
    expect(lines).toHaveLength(5);
  });

  it('neutralizes spreadsheet formula injection', () => {
    // A finding title starting with '=' would execute on open in Excel/Sheets.
    expect(csvEscape('=cmd|/c calc')).toBe("'=cmd|/c calc");
    expect(csvEscape('+1234')).toBe("'+1234");
    expect(csvEscape('@SUM(A1)')).toBe("'@SUM(A1)");
    expect(csvEscape('-2+3')).toBe("'-2+3");
  });

  it('quotes fields containing separators and newlines', () => {
    expect(csvEscape('a,b')).toBe('"a,b"');
    expect(csvEscape('line1\nline2')).toBe('"line1\nline2"');
    expect(csvEscape('say "hi"')).toBe('"say ""hi"""');
  });

  it('joins array fields readably', () => {
    const csv = toCsv(makeResult());
    expect(csv).toContain('CWE-89');
  });
});

describe('JSON export', () => {
  it('is versioned and parseable', async () => {
    const { result, summary, priorities } = await enriched();
    const parsed = JSON.parse(toJson(result, { summary, priorities }));

    expect(parsed.schemaVersion).toBe('1.0');
    expect(parsed.generator.name).toBe('Sentinel AI');
    expect(parsed.findings).toHaveLength(4);
    expect(parsed.summary.headline).toBeTruthy();
    expect(parsed.priorities).toHaveLength(4);
  });

  it('supports a minimal shape for machine consumers', () => {
    const parsed = JSON.parse(toJson(makeResult(), { minimal: true }));
    expect(parsed.findings[0]).not.toHaveProperty('explanation');
    expect(parsed.findings[0]).toHaveProperty('fingerprint');
  });
});

describe('statistics', () => {
  it('aggregates by kind, scanner and file', () => {
    const stats = toStatistics(makeResult());
    expect(stats.totalFindings).toBe(4);
    expect(stats.byKind['sast']).toBe(2);
    expect(stats.byKind['ai-security']).toBe(1);
    expect(stats.topFiles[0]?.count).toBeGreaterThan(0);
    expect(stats.coverage.scannersFailed).toBe(1);
    expect(stats.coverage.scannersSkipped).toBe(1);
  });

  it('excludes suppressed findings', () => {
    const findings = makeFindings().map((f, i) => (i === 0 ? { ...f, suppressed: true } : f));
    const stats = toStatistics(makeResult(findings));
    expect(stats.totalFindings).toBe(3);
    expect(stats.suppressed).toBe(1);
  });
});

describe('PDF export', () => {
  it('produces a structurally valid PDF', async () => {
    const { result, summary, priorities } = await enriched();
    const pdf = toPdf(result, { summary, priorities });
    const text = pdf.toString('latin1');

    expect(pdf.length).toBeGreaterThan(2000);
    expect(text.startsWith('%PDF-1.7')).toBe(true);
    expect(text.trimEnd().endsWith('%%EOF')).toBe(true);
    expect(text).toContain('/Type /Catalog');
    expect(text).toContain('/Type /Pages');
    expect(text).toContain('/Type /Page');
    expect(text).toContain('xref');
    expect(text).toContain('trailer');
    expect(text).toContain('startxref');
  });

  it('declares an object count matching the xref table', () => {
    const text = toPdf(makeResult()).toString('latin1');
    const declaredSize = Number(/\/Size (\d+)/.exec(text)![1]);
    const xrefHeader = /xref\n0 (\d+)\n/.exec(text)![1];
    expect(Number(xrefHeader)).toBe(declaredSize);

    // Every object must have an xref entry (minus the free entry at index 0).
    const objectCount = (text.match(/^\d+ 0 obj$/gm) ?? []).length;
    expect(objectCount).toBe(declaredSize - 1);
  });

  it('records byte offsets that actually point at their objects', () => {
    const text = toPdf(makeResult()).toString('latin1');
    const entries = [...text.matchAll(/^(\d{10}) 00000 n $/gm)].map((m) => Number(m[1]));
    expect(entries.length).toBeGreaterThan(5);

    entries.forEach((offset, index) => {
      expect(text.slice(offset, offset + 20)).toMatch(new RegExp(`^${index + 1} 0 obj`));
    });
  });

  it('embeds the report content as selectable text', async () => {
    const { result, summary } = await enriched();
    const text = toPdf(result, { summary }).toString('latin1');
    expect(text).toContain('acme/web');
    expect(text).toContain('SQL query built by string concatenation');
    expect(text).toContain('Scanner coverage');
  });

  it('paginates long reports', () => {
    const many = Array.from({ length: 60 }, () => makeFindings()).flat();
    const text = toPdf(makeResult(many), { maxFindings: 60 }).toString('latin1');
    const pageCount = Number(/\/Count (\d+)/.exec(text)![1]);
    expect(pageCount).toBeGreaterThan(1);
    expect((text.match(/\/Type \/Page[^s]/g) ?? []).length).toBe(pageCount);
  });

  it('survives characters outside the font encoding', () => {
    const findings = makeFindings();
    findings[0]!.title = 'Ünïcödé — 中文 — 🔴 emoji';
    expect(() => toPdf(makeResult(findings))).not.toThrow();
  });

  it('handles a failed scan', () => {
    const failed: ScanResult = { ...makeResult([]), status: 'failed', error: 'Clone failed' };
    const text = toPdf(failed).toString('latin1');
    expect(text).toContain('Scan did not complete');
  });
});

describe('exportReport', () => {
  it('supports every advertised format', async () => {
    const { result, summary, priorities } = await enriched();

    for (const format of EXPORT_FORMATS) {
      const report = exportReport(result, format, { summary, priorities });
      expect(report.format, format).toBe(format);
      expect(report.contentType, format).toBeTruthy();
      expect(report.filename, format).toMatch(/^sentinel-acme-web-2026-07-28\./);
      expect(report.body.length, format).toBeGreaterThan(100);
    }
  });

  it('returns a Buffer for PDF and a string for the rest', async () => {
    const { result } = await enriched();
    expect(Buffer.isBuffer(exportReport(result, 'pdf').body)).toBe(true);
    expect(typeof exportReport(result, 'json').body).toBe('string');
  });

  it('sanitizes the filename', () => {
    const result = makeResult();
    result.repository.name = '../../etc/passwd';
    const report = exportReport(result, 'json');
    expect(report.filename).not.toContain('/');
    expect(report.filename).not.toContain('..');
  });

  it('rejects an unknown format', async () => {
    const { result } = await enriched();
    expect(() => exportReport(result, 'docx' as never)).toThrow(/Unsupported export format/);
  });
});
