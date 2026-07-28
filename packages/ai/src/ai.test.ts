import { describe, expect, it, vi } from 'vitest';
import { normalizeFindings, silentLogger, type Finding, type ScanResult } from '@sentinel/core';
import { KnowledgeBaseAnalyst } from './providers/knowledge-base.js';
import { OpenRouterAnalyst } from './providers/openrouter.js';
import { createAnalyst, enrichScanResult } from './index.js';
import { TOPICS, topicFor } from './knowledge/topics.js';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  const [finding] = normalizeFindings(
    [
      {
        ruleId: 'js-sql-injection',
        title: 'SQL query built by string concatenation',
        description: 'A SQL statement is assembled from a template literal.',
        severity: 'critical',
        kind: 'sast',
        location: { path: 'src/api/users.ts', startLine: 12, snippet: 'db.query(`SELECT ${id}`)' },
        taxonomy: { cwe: ['CWE-89'], owaspTop10: ['A03:2021-Injection'] },
      },
    ],
    { scanId: 'scan_1', scanner: 'native-sast', scannerKind: 'native' },
  );
  return { ...finding!, ...overrides };
}

function makeResult(findings: Finding[]): ScanResult {
  return {
    id: 'scan_1',
    projectId: 'project_1',
    status: 'completed',
    target: { type: 'local', path: '/repo' },
    options: { allowNetwork: false },
    repository: {
      name: 'demo-app',
      languages: [{ language: 'typescript', files: 10, bytes: 1000, percent: 100 }],
      fileCount: 10,
      totalBytes: 1000,
      linesOfCode: 500,
    },
    findings,
    scannerRuns: [
      {
        scanner: 'native-sast',
        kind: 'sast',
        scannerKind: 'native',
        status: 'ok',
        durationMs: 10,
        findingCount: findings.length,
      },
      {
        scanner: 'semgrep',
        kind: 'sast',
        scannerKind: 'external',
        status: 'skipped',
        durationMs: 0,
        findingCount: 0,
        reason: 'not installed',
      },
    ],
    scores: {
      overall: 42,
      grade: 'F',
      riskLevel: 'elevated',
      categories: [
        {
          category: 'code',
          score: 42,
          grade: 'F',
          findingCount: findings.length,
          counts: { info: 0, low: 0, medium: 0, high: 0, critical: findings.length },
          analyzed: true,
          rationale: 'Critical findings detected.',
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
      ],
      counts: { info: 0, low: 0, medium: 0, high: 0, critical: findings.length },
      totalFindings: findings.length,
      computedAt: new Date().toISOString(),
    },
    startedAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    durationMs: 100,
  };
}

describe('topicFor', () => {
  it('selects the specific topic for a rule id', () => {
    expect(topicFor(makeFinding()).id).toBe('sql-injection');
  });

  it('prefers a rule-id match over a CWE match', () => {
    const retrieval = makeFinding({
      ruleId: 'ai-vector-search-no-tenant-filter',
      taxonomy: { cwe: ['CWE-863'], owaspLlmTop10: ['LLM08:2025-Vector and Embedding Weaknesses'] },
    });
    expect(topicFor(retrieval).id).toBe('ai-retrieval');
  });

  it('falls back to CWE when the rule id is unrecognized', () => {
    const finding = makeFinding({ ruleId: 'some-vendor-rule-1234', taxonomy: { cwe: ['CWE-79'] } });
    expect(topicFor(finding).id).toBe('xss');
  });

  it('returns the generic topic for a completely unknown finding', () => {
    const finding = makeFinding({ ruleId: 'unknown-rule', taxonomy: {} });
    expect(topicFor(finding).id).toBe('generic');
  });

  it('gives every topic complete content', () => {
    for (const topic of TOPICS) {
      expect(topic.plainEnglish.length, topic.id).toBeGreaterThan(50);
      expect(topic.businessImpact.length, topic.id).toBeGreaterThan(50);
      expect(topic.technicalImpact.length, topic.id).toBeGreaterThan(30);
      expect(topic.howItHappens.length, topic.id).toBeGreaterThan(30);
      expect(topic.matches.length, topic.id).toBeGreaterThan(0);
      const fixes = topic.fixes(makeFinding());
      expect(fixes.length, topic.id).toBeGreaterThan(0);
      for (const fix of fixes) {
        expect(fix.title.length, `${topic.id}/${fix.title}`).toBeGreaterThan(5);
        expect(fix.description.length, `${topic.id}/${fix.title}`).toBeGreaterThan(20);
      }
    }
  });
});

describe('KnowledgeBaseAnalyst', () => {
  const analyst = new KnowledgeBaseAnalyst();

  it('reports itself as local', () => {
    expect(analyst.info.remote).toBe(false);
  });

  it('explains a finding with every field populated', async () => {
    const explanation = await analyst.explain({ finding: makeFinding() });
    expect(explanation.plainEnglish).toMatch(/database/i);
    expect(explanation.businessImpact.length).toBeGreaterThan(50);
    expect(explanation.technicalImpact.length).toBeGreaterThan(30);
    expect(explanation.howItHappens).toContain('src/api/users.ts:12');
    expect(explanation.suggestedFixes.length).toBeGreaterThan(0);
    expect(explanation.confidenceScore).toBeGreaterThan(0);
    expect(explanation.confidenceScore).toBeLessThanOrEqual(1);
    expect(explanation.provider).toBe('knowledge-base');
  });

  it('is deterministic apart from the timestamp', async () => {
    const a = await analyst.explain({ finding: makeFinding() });
    const b = await analyst.explain({ finding: makeFinding() });
    expect({ ...a, generatedAt: '' }).toEqual({ ...b, generatedAt: '' });
  });

  it('lowers confidence for low-confidence detections', async () => {
    const high = await analyst.explain({ finding: makeFinding({ confidence: 'high' }) });
    const low = await analyst.explain({ finding: makeFinding({ confidence: 'low' }) });
    expect(low.confidenceScore).toBeLessThan(high.confidenceScore);
  });

  it('provides a language-appropriate code example', async () => {
    const python = await analyst.explain({
      finding: makeFinding({
        ruleId: 'py-sql-injection',
        location: { path: 'app/db.py', startLine: 5 },
      }),
    });
    expect(python.suggestedFixes[0]?.code).toContain('cursor.execute');
  });

  describe('prioritize', () => {
    it('ranks secrets above an equally severe code finding', async () => {
      const secret = makeFinding({
        id: 'secret-1',
        ruleId: 'secret-github-token',
        kind: 'secrets',
        severity: 'critical',
      });
      const code = makeFinding({ id: 'code-1' });

      const [first] = await analyst.prioritize([code, secret]);
      expect(first?.findingId).toBe('secret-1');
      expect(first?.reasoning).toMatch(/rotat|credential/i);
    });

    it('demotes findings in test paths', async () => {
      const production = makeFinding({
        id: 'prod',
        location: { path: 'src/api/users.ts', startLine: 1 },
      });
      const test = makeFinding({
        id: 'test',
        location: { path: 'src/__tests__/users.test.ts', startLine: 1 },
      });

      const priorities = await analyst.prioritize([test, production]);
      const prodScore = priorities.find((p) => p.findingId === 'prod')!.priorityScore;
      const testScore = priorities.find((p) => p.findingId === 'test')!.priorityScore;
      expect(prodScore).toBeGreaterThan(testScore);
    });

    it('demotes development-only dependencies', async () => {
      const runtime = makeFinding({ id: 'runtime', kind: 'dependencies' });
      const dev = makeFinding({
        id: 'dev',
        kind: 'dependencies',
        metadata: { isDevelopmentDependency: true },
      });
      const priorities = await analyst.prioritize([runtime, dev]);
      expect(priorities.find((p) => p.findingId === 'runtime')!.priorityScore).toBeGreaterThan(
        priorities.find((p) => p.findingId === 'dev')!.priorityScore,
      );
    });

    it('assigns contiguous ranks and bounded scores', async () => {
      const findings = [
        makeFinding({ id: 'a' }),
        makeFinding({ id: 'b' }),
        makeFinding({ id: 'c' }),
      ];
      const priorities = await analyst.prioritize(findings);
      expect(priorities.map((p) => p.rank)).toEqual([1, 2, 3]);
      for (const priority of priorities) {
        expect(priority.priorityScore).toBeGreaterThanOrEqual(0);
        expect(priority.priorityScore).toBeLessThanOrEqual(100);
        expect(priority.factors.length).toBeGreaterThan(0);
      }
    });
  });

  describe('remediate', () => {
    it('produces ordered steps and verification guidance', async () => {
      const plan = await analyst.remediate(makeFinding());
      expect(plan.steps.map((s) => s.order)).toEqual(plan.steps.map((_, i) => i + 1));
      expect(plan.verification.length).toBeGreaterThan(0);
      expect(plan.verification[0]).toContain('js-sql-injection');
      expect(plan.exampleCode).toBeTruthy();
    });

    it('puts rotation first for a secret', async () => {
      const plan = await analyst.remediate(
        makeFinding({ ruleId: 'secret-github-token', kind: 'secrets' }),
      );
      expect(plan.verification[0]).toMatch(/rotat/i);
      expect(plan.steps[0]?.action).toMatch(/rotate/i);
    });

    it('flags upgrade risk for dependency findings', async () => {
      const plan = await analyst.remediate(
        makeFinding({ ruleId: 'dependency-GHSA-x', kind: 'dependencies' }),
      );
      expect(plan.risks.join(' ')).toMatch(/breaking/i);
    });
  });

  describe('summarize', () => {
    it('writes a headline naming the repository and score', async () => {
      const summary = await analyst.summarize(makeResult([makeFinding()]));
      expect(summary.headline).toContain('demo-app');
      expect(summary.headline).toContain('42');
      expect(summary.recommendedActions.length).toBeGreaterThan(0);
    });

    it('always states coverage caveats', async () => {
      const summary = await analyst.summarize(makeResult([makeFinding()]));
      const caveats = summary.caveats.join(' ');
      // Never imply coverage the scan did not have.
      expect(caveats).toMatch(/secrets/i);
      expect(caveats).toMatch(/network access was disabled/i);
      expect(caveats).toMatch(/reachability/i);
    });

    it('handles a clean scan without claiming false precision', async () => {
      const summary = await analyst.summarize(makeResult([]));
      expect(summary.headline).toMatch(/nothing critical/i);
      expect(summary.caveats.length).toBeGreaterThan(0);
    });
  });
});

describe('createAnalyst', () => {
  it('defaults to the knowledge base with no key', () => {
    const analyst = createAnalyst({ logger: silentLogger });
    expect(analyst.info.id).toBe('knowledge-base');
    expect(analyst.info.remote).toBe(false);
  });

  it('uses OpenRouter when a key is present', () => {
    const analyst = createAnalyst({
      logger: silentLogger,
      env: {
        AI_PROVIDER: 'auto',
        OPENROUTER_API_KEY: 'sk-or-v1-test',
        OPENROUTER_MODEL: 'anthropic/claude-3.5-sonnet',
        APP_URL: 'http://localhost:3000',
      },
    });
    expect(analyst.info.id).toBe('openrouter');
    expect(analyst.info.remote).toBe(true);
  });

  it('honours an explicit knowledge-base override even with a key present', () => {
    const analyst = createAnalyst({
      logger: silentLogger,
      env: {
        AI_PROVIDER: 'knowledge-base',
        OPENROUTER_API_KEY: 'sk-or-v1-test',
        OPENROUTER_MODEL: 'x',
        APP_URL: 'http://localhost:3000',
      },
    });
    expect(analyst.info.id).toBe('knowledge-base');
  });

  it('falls back rather than failing when openrouter is requested without a key', () => {
    const analyst = createAnalyst({
      logger: silentLogger,
      env: { AI_PROVIDER: 'openrouter', OPENROUTER_MODEL: 'x', APP_URL: 'http://localhost:3000' },
    });
    expect(analyst.info.id).toBe('knowledge-base');
  });
});

describe('OpenRouterAnalyst', () => {
  const jsonResponse = (content: unknown) =>
    ({
      ok: true,
      json: async () => ({ choices: [{ message: { content: JSON.stringify(content) } }] }),
      text: async () => '',
    }) as unknown as Response;

  it('uses the model response when it is well-formed', async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse({
        plainEnglish: 'Model-written explanation of the injection.',
        businessImpact: 'Model-written business impact.',
        technicalImpact: 'Model-written technical impact.',
        howItHappens: 'Model-written mechanism.',
        confidence: 0.91,
      }),
    );

    const analyst = new OpenRouterAnalyst({
      apiKey: 'sk-or-v1-test',
      logger: silentLogger,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    const explanation = await analyst.explain({ finding: makeFinding() });
    expect(explanation.plainEnglish).toBe('Model-written explanation of the injection.');
    expect(explanation.confidenceScore).toBe(0.91);
    expect(explanation.provider).toBe('openrouter');
    // Fixes always come from the reviewed knowledge base, never generated.
    expect(explanation.suggestedFixes.length).toBeGreaterThan(0);
    expect(explanation.suggestedFixes[0]?.code).toContain('SELECT');
  });

  it('parses JSON wrapped in a markdown fence', async () => {
    const fetchImpl = vi.fn(
      async () =>
        ({
          ok: true,
          json: async () => ({
            choices: [
              {
                message: {
                  content:
                    'Here is the analysis:\n```json\n{"plainEnglish":"Fenced response."}\n```\nHope that helps.',
                },
              },
            ],
          }),
          text: async () => '',
        }) as unknown as Response,
    );

    const analyst = new OpenRouterAnalyst({
      apiKey: 'k',
      logger: silentLogger,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    expect((await analyst.explain({ finding: makeFinding() })).plainEnglish).toBe(
      'Fenced response.',
    );
  });

  it('falls back to the knowledge base when the API errors', async () => {
    const fetchImpl = vi.fn(
      async () =>
        ({ ok: false, status: 401, text: async () => 'unauthorized' }) as unknown as Response,
    );

    const analyst = new OpenRouterAnalyst({
      apiKey: 'bad',
      logger: silentLogger,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    const explanation = await analyst.explain({ finding: makeFinding() });
    expect(explanation.provider).toBe('knowledge-base');
    expect(explanation.plainEnglish.length).toBeGreaterThan(50);
    // A 401 must not be retried.
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('falls back when the response is not JSON', async () => {
    const fetchImpl = vi.fn(
      async () =>
        ({
          ok: true,
          json: async () => ({ choices: [{ message: { content: 'I cannot help with that.' } }] }),
          text: async () => '',
        }) as unknown as Response,
    );

    const analyst = new OpenRouterAnalyst({
      apiKey: 'k',
      logger: silentLogger,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    expect((await analyst.explain({ finding: makeFinding() })).provider).toBe('knowledge-base');
  });

  it('never delegates prioritization to the model', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({}));
    const analyst = new OpenRouterAnalyst({
      apiKey: 'k',
      logger: silentLogger,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await analyst.prioritize([makeFinding()]);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('keeps computed caveats even when the model summarizes', async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse({
        headline: 'Model headline.',
        posture: 'Model posture.',
        topRisks: ['Model risk'],
        recommendedActions: ['Model action'],
        caveats: ['Everything is fine, nothing to worry about'],
      }),
    );

    const analyst = new OpenRouterAnalyst({
      apiKey: 'k',
      logger: silentLogger,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    const summary = await analyst.summarize(makeResult([makeFinding()]));
    expect(summary.headline).toBe('Model headline.');
    // The model must not be able to soften the honest coverage statement.
    expect(summary.caveats.join(' ')).not.toContain('nothing to worry about');
    expect(summary.caveats.join(' ')).toMatch(/reachability/i);
  });
});

describe('enrichScanResult', () => {
  it('attaches explanations, priorities and a summary', async () => {
    const findings = [makeFinding({ id: 'a' }), makeFinding({ id: 'b', severity: 'low' })];
    const enriched = await enrichScanResult(makeResult(findings), {
      analyst: new KnowledgeBaseAnalyst(),
      logger: silentLogger,
    });

    expect(enriched.explained).toBe(2);
    expect(enriched.priorities).toHaveLength(2);
    expect(enriched.summary.headline).toBeTruthy();
    expect(enriched.result.findings.every((f) => f.explanation)).toBe(true);
  });

  it('respects the explanation budget and explains the highest priority first', async () => {
    const findings = [
      makeFinding({ id: 'low', severity: 'low' }),
      makeFinding({ id: 'critical', severity: 'critical' }),
    ];
    const enriched = await enrichScanResult(makeResult(findings), {
      analyst: new KnowledgeBaseAnalyst(),
      logger: silentLogger,
      maxExplanations: 1,
    });

    expect(enriched.explained).toBe(1);
    expect(enriched.result.findings.find((f) => f.id === 'critical')?.explanation).toBeDefined();
    expect(enriched.result.findings.find((f) => f.id === 'low')?.explanation).toBeUndefined();
  });

  it('skips suppressed findings', async () => {
    const findings = [makeFinding({ id: 'a', suppressed: true })];
    const enriched = await enrichScanResult(makeResult(findings), {
      analyst: new KnowledgeBaseAnalyst(),
      logger: silentLogger,
    });
    expect(enriched.explained).toBe(0);
  });

  it('honours a minimum severity threshold', async () => {
    const findings = [
      makeFinding({ id: 'low', severity: 'low' }),
      makeFinding({ id: 'high', severity: 'high' }),
    ];
    const enriched = await enrichScanResult(makeResult(findings), {
      analyst: new KnowledgeBaseAnalyst(),
      logger: silentLogger,
      minSeverity: 'high',
    });
    expect(enriched.explained).toBe(1);
    expect(enriched.result.findings.find((f) => f.id === 'high')?.explanation).toBeDefined();
  });

  it('keeps the finding when its explanation fails', async () => {
    const failing = new KnowledgeBaseAnalyst();
    vi.spyOn(failing, 'explain').mockRejectedValue(new Error('provider exploded'));

    const enriched = await enrichScanResult(makeResult([makeFinding()]), {
      analyst: failing,
      logger: silentLogger,
    });

    expect(enriched.explained).toBe(0);
    expect(enriched.result.findings).toHaveLength(1);
    expect(enriched.summary.headline).toBeTruthy();
  });
});
