import type { Finding, FindingExplanation, Logger, ScanResult, Severity } from '@sentinel/core';

/**
 * The AI layer's contract.
 *
 * Sentinel treats "AI" as a *pluggable enrichment step*, never as a dependency.
 * Every method here has a deterministic offline implementation, so the platform
 * produces complete, useful output with no API key and no network — and a
 * hosted model, when configured, improves the prose rather than unlocking the
 * feature.
 */

export interface ExplainRequest {
  finding: Finding;
  /** Source lines around the finding, when available. */
  codeContext?: string;
  /** Repository language mix, so advice can be idiomatic. */
  languages?: string[];
  repositoryName?: string;
}

export interface PrioritizedFinding {
  findingId: string;
  /** 0..100. Higher means "fix this sooner". */
  priorityScore: number;
  rank: number;
  /** Why this ranks where it does, in one sentence. */
  reasoning: string;
  /** Rough effort estimate to remediate. */
  effort: 'trivial' | 'small' | 'medium' | 'large';
  /** Signals that pushed the score up or down. */
  factors: PriorityFactor[];
}

export interface PriorityFactor {
  name: string;
  /** Positive raises priority, negative lowers it. */
  weight: number;
  detail: string;
}

export interface RemediationPlan {
  findingId: string;
  summary: string;
  steps: RemediationStep[];
  /** A unified diff when the fix is mechanically derivable. */
  patch?: string;
  /** Safer implementation to copy. */
  exampleCode?: string;
  language?: string;
  /** Anything that could break when applying this. */
  risks: string[];
  verification: string[];
}

export interface RemediationStep {
  order: number;
  action: string;
  detail: string;
  automated: boolean;
}

export interface ExecutiveSummary {
  /** Two or three sentences a non-engineer can act on. */
  headline: string;
  posture: string;
  topRisks: string[];
  recommendedActions: string[];
  /** What the numbers do *not* tell you — coverage gaps and caveats. */
  caveats: string[];
}

export interface AiProviderInfo {
  id: string;
  name: string;
  /** True when the provider calls an external service. */
  remote: boolean;
  model?: string;
  /** Explains why this provider was chosen, shown in the UI. */
  rationale: string;
}

export interface AiAnalyst {
  readonly info: AiProviderInfo;
  explain(request: ExplainRequest): Promise<FindingExplanation>;
  prioritize(findings: readonly Finding[]): Promise<PrioritizedFinding[]>;
  remediate(finding: Finding, codeContext?: string): Promise<RemediationPlan>;
  summarize(result: ScanResult): Promise<ExecutiveSummary>;
}

export interface AnalystOptions {
  logger: Logger;
  /** Cap on findings explained per scan, to bound latency and cost. */
  maxExplanations?: number;
  /** Only explain findings at or above this severity. */
  minSeverity?: Severity;
  signal?: AbortSignal;
}
