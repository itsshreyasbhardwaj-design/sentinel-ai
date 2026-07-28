import {
  errors,
  retry,
  type Finding,
  type FindingExplanation,
  type Logger,
  type ScanResult,
  type SuggestedFix,
} from '@sentinel/core';
import { KnowledgeBaseAnalyst } from './knowledge-base.js';
import type {
  AiAnalyst,
  AiProviderInfo,
  ExecutiveSummary,
  ExplainRequest,
  PrioritizedFinding,
  RemediationPlan,
} from '../types.js';

/**
 * OpenRouter-backed analyst.
 *
 * Wraps the knowledge-base analyst rather than replacing it. Every method falls
 * back to the deterministic implementation on any error, timeout or malformed
 * response, so enabling a model can improve output but can never take the
 * product down — and prioritization stays arithmetic, because ranking work
 * queues is a job that benefits from being reproducible.
 */

const OPENROUTER_URL = 'https://openrouter.ai/api/v1/chat/completions';

export interface OpenRouterOptions {
  apiKey: string;
  model?: string;
  logger: Logger;
  timeoutMs?: number;
  appUrl?: string;
  fetchImpl?: typeof fetch;
}

interface ChatResponse {
  choices?: { message?: { content?: string } }[];
  error?: { message?: string };
}

/** Models return JSON wrapped in prose or fences more often than not. */
function extractJson(text: string): unknown {
  const trimmed = text.trim();
  const fenced = /```(?:json)?\s*([\s\S]*?)```/.exec(trimmed);
  const candidate = fenced?.[1]?.trim() ?? trimmed;

  try {
    return JSON.parse(candidate);
  } catch {
    // Fall back to the outermost brace pair.
    const start = candidate.indexOf('{');
    const end = candidate.lastIndexOf('}');
    if (start === -1 || end <= start) return undefined;
    try {
      return JSON.parse(candidate.slice(start, end + 1));
    } catch {
      return undefined;
    }
  }
}

function asString(value: unknown, fallback: string): string {
  return typeof value === 'string' && value.trim() ? value.trim() : fallback;
}

function asStringArray(value: unknown, fallback: string[]): string[] {
  if (!Array.isArray(value)) return fallback;
  const out = value.filter((v): v is string => typeof v === 'string' && v.trim().length > 0);
  return out.length ? out : fallback;
}

export class OpenRouterAnalyst implements AiAnalyst {
  readonly info: AiProviderInfo;
  private readonly fallback = new KnowledgeBaseAnalyst();
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(private readonly options: OpenRouterOptions) {
    this.info = {
      id: 'openrouter',
      name: 'OpenRouter',
      remote: true,
      model: options.model ?? 'anthropic/claude-3.5-sonnet',
      rationale:
        'Model-generated analysis via OpenRouter, grounded in the scanner finding and falling back to the built-in knowledge base if the request fails.',
    };
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.timeoutMs = options.timeoutMs ?? 60_000;
  }

  private async complete(system: string, user: string): Promise<string> {
    const response = await retry(
      async () => {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.timeoutMs);

        try {
          const res = await this.fetchImpl(OPENROUTER_URL, {
            method: 'POST',
            headers: {
              authorization: `Bearer ${this.options.apiKey}`,
              'content-type': 'application/json',
              // OpenRouter uses these for attribution on its dashboard.
              'http-referer': this.options.appUrl ?? 'https://github.com/sentinel-ai',
              'x-title': 'Sentinel AI',
            },
            body: JSON.stringify({
              model: this.info.model,
              messages: [
                { role: 'system', content: system },
                { role: 'user', content: user },
              ],
              temperature: 0.2,
              max_tokens: 2000,
              response_format: { type: 'json_object' },
            }),
            signal: controller.signal,
          });

          if (!res.ok) {
            const body = await res.text().catch(() => '');
            throw errors.aiProvider(`OpenRouter returned ${res.status}: ${body.slice(0, 200)}`);
          }
          return (await res.json()) as ChatResponse;
        } finally {
          clearTimeout(timer);
        }
      },
      {
        attempts: 2,
        baseDelayMs: 1000,
        // Auth and quota errors will not resolve on retry.
        shouldRetry: (error) => !/40[13]|429/.test(String(error)),
      },
    );

    if (response.error?.message) throw errors.aiProvider(response.error.message);
    const content = response.choices?.[0]?.message?.content;
    if (!content) throw errors.aiProvider('OpenRouter returned an empty response');
    return content;
  }

  async explain(request: ExplainRequest): Promise<FindingExplanation> {
    // Always compute the deterministic answer: it is both the fallback and the
    // floor on quality.
    const baseline = await this.fallback.explain(request);
    const { finding } = request;

    const system = [
      'You are a principal application security engineer reviewing a static analysis finding.',
      'Explain it precisely and without alarmism, for the engineer who has to fix it.',
      'Ground every statement in the code and metadata provided. Do not invent file paths, function names, CVEs or behaviour.',
      'If the evidence does not support a claim, say what is uncertain instead of guessing.',
      'Respond with a single JSON object and no other text, using exactly these keys:',
      '{"plainEnglish": string, "businessImpact": string, "technicalImpact": string, "howItHappens": string, "confidence": number between 0 and 1}',
    ].join('\n');

    const user = JSON.stringify(
      {
        rule: finding.ruleId,
        title: finding.title,
        description: finding.description,
        severity: finding.severity,
        detectorConfidence: finding.confidence,
        cwe: finding.taxonomy?.cwe,
        owasp: [
          ...(finding.taxonomy?.owaspTop10 ?? []),
          ...(finding.taxonomy?.owaspLlmTop10 ?? []),
        ],
        file: finding.location?.path,
        line: finding.location?.startLine,
        code: request.codeContext?.slice(0, 3000) ?? finding.location?.snippet,
        component: finding.component,
        repositoryLanguages: request.languages,
      },
      null,
      2,
    );

    try {
      const parsed = extractJson(await this.complete(system, user)) as
        Record<string, unknown> | undefined;
      if (!parsed) throw errors.aiProvider('Response was not valid JSON');

      const confidence =
        typeof parsed['confidence'] === 'number' ? parsed['confidence'] : undefined;

      return {
        plainEnglish: asString(parsed['plainEnglish'], baseline.plainEnglish),
        businessImpact: asString(parsed['businessImpact'], baseline.businessImpact),
        technicalImpact: asString(parsed['technicalImpact'], baseline.technicalImpact),
        howItHappens: asString(parsed['howItHappens'], baseline.howItHappens),
        // Fixes stay from the knowledge base: they are reviewed, tested and
        // safe to paste, which is not something we can assert about generated code.
        suggestedFixes: baseline.suggestedFixes,
        confidenceScore:
          confidence !== undefined
            ? Math.max(0, Math.min(1, confidence))
            : baseline.confidenceScore,
        provider: this.info.id,
        ...(this.info.model ? { model: this.info.model } : {}),
        generatedAt: new Date().toISOString(),
      };
    } catch (error) {
      this.options.logger.warn('OpenRouter explanation failed; using the knowledge base', {
        finding: finding.id,
        error: String(error),
      });
      return baseline;
    }
  }

  /**
   * Prioritization is intentionally not delegated to the model. Ranking a work
   * queue must be reproducible and auditable — the same scan should produce the
   * same order twice, and a user asking "why is this first" deserves an
   * arithmetic answer.
   */
  prioritize(findings: readonly Finding[]): Promise<PrioritizedFinding[]> {
    return this.fallback.prioritize(findings);
  }

  async remediate(finding: Finding, codeContext?: string): Promise<RemediationPlan> {
    const baseline = await this.fallback.remediate(finding, codeContext);
    if (!codeContext) return baseline;

    const system = [
      'You are a principal engineer writing a remediation for a security finding.',
      'Produce a fix that is minimal, idiomatic for the language shown, and preserves existing behaviour.',
      'Only reference symbols that appear in the provided code. Never invent APIs.',
      'Respond with a single JSON object and no other text:',
      '{"summary": string, "exampleCode": string, "risks": string[], "verification": string[]}',
    ].join('\n');

    const user = JSON.stringify({
      rule: finding.ruleId,
      title: finding.title,
      severity: finding.severity,
      file: finding.location?.path,
      line: finding.location?.startLine,
      code: codeContext.slice(0, 4000),
      knownGoodApproach: baseline.summary,
    });

    try {
      const parsed = extractJson(await this.complete(system, user)) as
        Record<string, unknown> | undefined;
      if (!parsed) throw errors.aiProvider('Response was not valid JSON');

      return {
        ...baseline,
        summary: asString(parsed['summary'], baseline.summary),
        exampleCode: asString(parsed['exampleCode'], baseline.exampleCode ?? ''),
        risks: asStringArray(parsed['risks'], baseline.risks),
        verification: asStringArray(parsed['verification'], baseline.verification),
      };
    } catch (error) {
      this.options.logger.warn('OpenRouter remediation failed; using the knowledge base', {
        finding: finding.id,
        error: String(error),
      });
      return baseline;
    }
  }

  async summarize(result: ScanResult): Promise<ExecutiveSummary> {
    const baseline = await this.fallback.summarize(result);

    const system = [
      'You are a CISO writing the executive summary of an application security report.',
      'Be direct and specific. No hedging, no filler, no security-vendor language.',
      'Use only the data provided. Never overstate coverage or certainty.',
      'Respond with a single JSON object and no other text:',
      '{"headline": string, "posture": string, "topRisks": string[], "recommendedActions": string[]}',
    ].join('\n');

    const user = JSON.stringify({
      repository: result.repository.name,
      languages: result.repository.languages.map((l) => l.language),
      scores: result.scores,
      counts: result.scores.counts,
      topFindings: result.findings.slice(0, 15).map((f) => ({
        title: f.title,
        severity: f.severity,
        kind: f.kind,
        path: f.location?.path,
      })),
      scannerCoverage: result.scannerRuns.map((r) => ({ scanner: r.scanner, status: r.status })),
    });

    try {
      const parsed = extractJson(await this.complete(system, user)) as
        Record<string, unknown> | undefined;
      if (!parsed) throw errors.aiProvider('Response was not valid JSON');

      return {
        headline: asString(parsed['headline'], baseline.headline),
        posture: asString(parsed['posture'], baseline.posture),
        topRisks: asStringArray(parsed['topRisks'], baseline.topRisks),
        recommendedActions: asStringArray(
          parsed['recommendedActions'],
          baseline.recommendedActions,
        ),
        // Caveats are computed from what actually ran, never generated — this is
        // the one field a model must not be allowed to soften.
        caveats: baseline.caveats,
      };
    } catch (error) {
      this.options.logger.warn('OpenRouter summary failed; using the knowledge base', {
        error: String(error),
      });
      return baseline;
    }
  }
}

/** Exposed for tests and for the remediation UI. */
export function mergeFixes(baseline: SuggestedFix[], extra: SuggestedFix[]): SuggestedFix[] {
  const seen = new Set(baseline.map((f) => f.title.toLowerCase()));
  return [...baseline, ...extra.filter((f) => !seen.has(f.title.toLowerCase()))];
}
