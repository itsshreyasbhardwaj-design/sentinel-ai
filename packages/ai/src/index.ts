import {
  mapLimit,
  isAtLeast,
  type Env,
  type Finding,
  type Logger,
  type ScanResult,
} from '@sentinel/core';
import { KnowledgeBaseAnalyst } from './providers/knowledge-base.js';
import { OpenRouterAnalyst } from './providers/openrouter.js';
import type { AiAnalyst, ExecutiveSummary, PrioritizedFinding } from './types.js';

export * from './types.js';
export { KnowledgeBaseAnalyst, shouldExplain } from './providers/knowledge-base.js';
export { OpenRouterAnalyst } from './providers/openrouter.js';
export { TOPICS, topicFor, type KnowledgeTopic } from './knowledge/topics.js';

export interface CreateAnalystOptions {
  logger: Logger;
  env?: Pick<Env, 'AI_PROVIDER' | 'OPENROUTER_API_KEY' | 'OPENROUTER_MODEL' | 'APP_URL'>;
  fetchImpl?: typeof fetch;
}

/**
 * Choose an analyst.
 *
 * `auto` — the default — uses OpenRouter when a key is present and the
 * knowledge base otherwise. There is deliberately no configuration in which the
 * platform has *no* analyst: explanations are part of the product, not an
 * add-on that degrades to empty fields when unconfigured.
 */
export function createAnalyst(options: CreateAnalystOptions): AiAnalyst {
  const env = options.env;
  const provider = env?.AI_PROVIDER ?? 'auto';

  if (provider === 'knowledge-base') {
    return new KnowledgeBaseAnalyst();
  }

  if (env?.OPENROUTER_API_KEY) {
    options.logger.info('Using OpenRouter for AI analysis', { model: env.OPENROUTER_MODEL });
    return new OpenRouterAnalyst({
      apiKey: env.OPENROUTER_API_KEY,
      ...(env.OPENROUTER_MODEL ? { model: env.OPENROUTER_MODEL } : {}),
      logger: options.logger,
      ...(env.APP_URL ? { appUrl: env.APP_URL } : {}),
      ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
    });
  }

  if (provider === 'openrouter') {
    options.logger.warn(
      'AI_PROVIDER is set to openrouter but OPENROUTER_API_KEY is missing; falling back to the built-in knowledge base',
    );
  }

  return new KnowledgeBaseAnalyst();
}

export interface EnrichOptions {
  analyst: AiAnalyst;
  logger: Logger;
  /** Ceiling on explained findings, to bound latency and spend. */
  maxExplanations?: number;
  minSeverity?: Finding['severity'];
  concurrency?: number;
  /** Reads the source around a finding so explanations can cite real code. */
  readContext?: (finding: Finding) => Promise<string | undefined>;
  signal?: AbortSignal;
}

export interface EnrichedScan {
  result: ScanResult;
  priorities: PrioritizedFinding[];
  summary: ExecutiveSummary;
  /** How many findings received an explanation, and why the rest did not. */
  explained: number;
  skipped: number;
}

/**
 * Attach explanations, priorities and an executive summary to a scan result.
 *
 * Explanations are budgeted: the highest-priority findings are explained first
 * and the rest are left with their scanner description. Spending forty model
 * calls on informational findings while the criticals wait is the wrong trade.
 */
export async function enrichScanResult(
  result: ScanResult,
  options: EnrichOptions,
): Promise<EnrichedScan> {
  const started = Date.now();
  const maxExplanations = options.maxExplanations ?? 50;

  const priorities = await options.analyst.prioritize(result.findings);
  const priorityByFinding = new Map(priorities.map((p) => [p.findingId, p]));

  const eligible = result.findings
    .filter((finding) => !finding.suppressed)
    .filter((finding) => !options.minSeverity || isAtLeast(finding.severity, options.minSeverity))
    .sort(
      (a, b) =>
        (priorityByFinding.get(b.id)?.priorityScore ?? 0) -
        (priorityByFinding.get(a.id)?.priorityScore ?? 0),
    );

  const toExplain = eligible.slice(0, maxExplanations);
  const languages = result.repository.languages.map((l) => l.language);

  const explanations = await mapLimit(toExplain, options.concurrency ?? 4, async (finding) => {
    if (options.signal?.aborted) return undefined;
    try {
      const codeContext = await options.readContext?.(finding);
      return await options.analyst.explain({
        finding,
        ...(codeContext ? { codeContext } : {}),
        languages,
        repositoryName: result.repository.name,
      });
    } catch (error) {
      // A failed explanation must never lose the finding itself.
      options.logger.warn('Failed to explain finding', {
        finding: finding.id,
        error: String(error),
      });
      return undefined;
    }
  });

  const explainedById = new Map(
    toExplain
      .map((finding, index) => [finding.id, explanations[index]] as const)
      .filter((entry): entry is [string, NonNullable<(typeof explanations)[number]>] =>
        Boolean(entry[1]),
      ),
  );

  const enrichedResult: ScanResult = {
    ...result,
    findings: result.findings.map((finding) => {
      const explanation = explainedById.get(finding.id);
      return explanation ? { ...finding, explanation } : finding;
    }),
  };

  const summary = await options.analyst.summarize(enrichedResult);

  options.logger.info('AI enrichment complete', {
    provider: options.analyst.info.id,
    explained: explainedById.size,
    durationMs: Date.now() - started,
  });

  return {
    result: enrichedResult,
    priorities,
    summary,
    explained: explainedById.size,
    skipped: Math.max(0, eligible.length - explainedById.size),
  };
}
