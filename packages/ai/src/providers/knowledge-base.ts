import {
  isAtLeast,
  severityRank,
  type Finding,
  type FindingExplanation,
  type ScanResult,
} from '@sentinel/core';
import { GENERIC_TOPIC, topicFor } from '../knowledge/topics.js';
import type {
  AiAnalyst,
  AiProviderInfo,
  ExecutiveSummary,
  ExplainRequest,
  PriorityFactor,
  PrioritizedFinding,
  RemediationPlan,
} from '../types.js';

/**
 * Deterministic, offline analyst.
 *
 * This is the default provider and the reason Sentinel works with no API key,
 * no network and no spend. It composes explanations from the curated knowledge
 * base and computes prioritization arithmetically, so its output is stable
 * across runs — which also makes it the only provider that can be meaningfully
 * snapshot-tested.
 */

const INFO: AiProviderInfo = {
  id: 'knowledge-base',
  name: 'Sentinel Knowledge Base',
  remote: false,
  rationale:
    "Deterministic analysis from Sentinel's curated vulnerability knowledge base. Runs offline with no API key and no per-scan cost.",
};

/* ------------------------------------------------------------------ */
/* Prioritization                                                      */
/* ------------------------------------------------------------------ */

/**
 * Signals that move a finding up or down the queue, beyond raw severity.
 *
 * Severity answers "how bad if exploited". Priority has to answer "what should
 * I do first", which is a different question — a medium-severity leaked key in
 * production code outranks a critical in a test fixture.
 */
function priorityFactors(finding: Finding): PriorityFactor[] {
  const factors: PriorityFactor[] = [];
  const path = finding.location?.path ?? '';

  factors.push({
    name: 'Severity',
    weight: severityRank(finding.severity) * 12,
    detail: `Rated ${finding.severity}.`,
  });

  if (finding.confidence === 'high') {
    factors.push({
      name: 'High confidence',
      weight: 8,
      detail: 'Detection is unlikely to be a false positive.',
    });
  } else if (finding.confidence === 'low') {
    factors.push({
      name: 'Low confidence',
      weight: -10,
      detail: 'Needs manual confirmation before work starts.',
    });
  }

  if (Array.isArray(finding.metadata?.['corroboratedBy'])) {
    factors.push({
      name: 'Corroborated',
      weight: 10,
      detail: 'Reported independently by more than one scanner.',
    });
  }

  // A live credential is the only finding class where the clock is already running.
  if (finding.kind === 'secrets') {
    factors.push({
      name: 'Active credential exposure',
      weight: 22,
      detail:
        'A committed secret is exploitable right now and must be rotated before anything else.',
    });
  }

  if (finding.taxonomy?.cve?.length) {
    factors.push({
      name: 'Published CVE',
      weight: 12,
      detail: 'A public advisory exists, so exploitation requires no original research.',
    });
  }

  if (finding.metadata?.['isDevelopmentDependency'] === true) {
    factors.push({
      name: 'Development-only dependency',
      weight: -14,
      detail: 'Not present in the production artifact.',
    });
  }

  if (/(?:^|\/)(?:tests?|spec|__tests__|fixtures?|examples?|docs?)(?:\/|$)/i.test(path)) {
    factors.push({
      name: 'Non-production path',
      weight: -18,
      detail: 'Located in test, fixture or documentation code.',
    });
  }

  if (
    /(?:^|\/)(?:api|routes?|controllers?|handlers?|middleware|auth|admin|payment|billing)(?:\/|$)/i.test(
      path,
    )
  ) {
    factors.push({
      name: 'Sensitive code path',
      weight: 12,
      detail:
        'Located in request-handling, authentication or payment code, so it is likely reachable from untrusted input.',
    });
  }

  if (finding.kind === 'ai-security') {
    factors.push({
      name: 'AI attack surface',
      weight: 8,
      detail:
        'AI features are actively targeted and their failure modes are poorly covered by existing controls.',
    });
  }

  // An issue that has survived many scans is either accepted or genuinely stuck.
  const ageDays = (Date.now() - new Date(finding.firstSeenAt).getTime()) / 86_400_000;
  if (ageDays > 30) {
    factors.push({
      name: 'Long-standing',
      weight: 6,
      detail: `First detected ${Math.round(ageDays)} days ago and still open.`,
    });
  }

  return factors;
}

function effortFor(finding: Finding): PrioritizedFinding['effort'] {
  if (finding.kind === 'dependencies' && finding.metadata?.['fixedVersions']) return 'trivial';
  if (finding.kind === 'secrets') return 'small';
  if (finding.kind === 'ai-security') return 'medium';
  if (finding.kind === 'iac' || finding.kind === 'config') return 'small';
  return 'medium';
}

/* ------------------------------------------------------------------ */
/* Provider                                                            */
/* ------------------------------------------------------------------ */

export class KnowledgeBaseAnalyst implements AiAnalyst {
  readonly info = INFO;

  async explain(request: ExplainRequest): Promise<FindingExplanation> {
    const { finding } = request;
    const topic = topicFor(finding);

    // Weave the scanner's own description in so rule-specific detail is not
    // lost behind the generic topic text.
    const specific = finding.description?.trim();
    const plainEnglish =
      specific && specific.length > 40 && topic.id === GENERIC_TOPIC.id
        ? specific
        : specific
          ? `${topic.plainEnglish}\n\nIn this case: ${specific}`
          : topic.plainEnglish;

    const location = finding.location
      ? `${finding.location.path}:${finding.location.startLine}`
      : finding.component
        ? `${finding.component.name}@${finding.component.version}`
        : 'the repository';

    return {
      plainEnglish,
      businessImpact: topic.businessImpact,
      technicalImpact: topic.technicalImpact,
      howItHappens: `${topic.howItHappens}\n\nDetected at ${location} by ${finding.scanner}.`,
      suggestedFixes: topic.fixes(finding),
      // Blend the topic's baseline with the detector's own confidence, so a
      // low-confidence match never claims certainty.
      confidenceScore:
        Math.round(
          topic.confidence *
            (finding.confidence === 'high' ? 1 : finding.confidence === 'medium' ? 0.85 : 0.6) *
            100,
        ) / 100,
      provider: INFO.id,
      generatedAt: new Date().toISOString(),
    };
  }

  async prioritize(findings: readonly Finding[]): Promise<PrioritizedFinding[]> {
    const scored = findings.map((finding) => {
      const factors = priorityFactors(finding);
      const raw = factors.reduce((sum, factor) => sum + factor.weight, 0);
      const priorityScore = Math.max(0, Math.min(100, Math.round(raw)));

      const positives = factors.filter((f) => f.weight > 0).sort((a, b) => b.weight - a.weight);
      const negatives = factors.filter((f) => f.weight < 0);
      const reasoning = [
        positives[0]?.detail ?? `Rated ${finding.severity}.`,
        ...(positives[1] ? [positives[1].detail] : []),
        ...(negatives[0] ? [`Lowered: ${negatives[0].detail.toLowerCase()}`] : []),
      ].join(' ');

      return { finding, priorityScore, factors, reasoning };
    });

    return scored
      .sort((a, b) => b.priorityScore - a.priorityScore)
      .map((entry, index) => ({
        findingId: entry.finding.id,
        priorityScore: entry.priorityScore,
        rank: index + 1,
        reasoning: entry.reasoning,
        effort: effortFor(entry.finding),
        factors: entry.factors,
      }));
  }

  async remediate(finding: Finding, codeContext?: string): Promise<RemediationPlan> {
    const topic = topicFor(finding);
    const fixes = topic.fixes(finding);
    const primary = fixes[0];

    const steps = fixes.map((suggestion, index) => ({
      order: index + 1,
      action: suggestion.title,
      detail: suggestion.description,
      automated: suggestion.autoApplicable,
    }));

    // Verification is deliberately concrete: "did you re-run the scan" is the
    // step most remediation advice omits and most teams forget.
    const verification = [
      `Re-run the scan and confirm ${finding.ruleId} no longer reports at ${finding.location?.path ?? 'this location'}.`,
      'Run the existing test suite to confirm the change did not alter behaviour.',
    ];

    if (finding.kind === 'secrets') {
      verification.unshift(
        'Confirm the old credential is rejected by the provider — rotation is the fix, not the file edit.',
      );
    }
    if (finding.kind === 'dependencies') {
      verification.push(
        'Check the lockfile diff to confirm the resolved version is outside the vulnerable range.',
      );
    }

    const risks: string[] = [];
    if (finding.kind === 'dependencies') {
      risks.push('A major-version upgrade may include breaking API changes; review the changelog.');
    }
    if (topic.id === 'sql-injection' || topic.id === 'nosql-injection') {
      risks.push(
        'Parameterization cannot be applied to identifiers such as table or column names; those need an allowlist instead.',
      );
    }
    if (topic.id === 'ai-excessive-agency') {
      risks.push(
        'Narrowing tool permissions may break flows that silently relied on the broader access.',
      );
    }
    if (codeContext && codeContext.length > 4000) {
      risks.push(
        'The surrounding function is large; review the whole call path rather than the single line.',
      );
    }

    return {
      findingId: finding.id,
      summary: primary
        ? `${primary.title}. ${primary.description.split('.')[0]}.`
        : 'Review the finding against the linked standard.',
      steps,
      ...(primary?.code ? { exampleCode: primary.code } : {}),
      ...(primary?.language ? { language: primary.language } : {}),
      risks,
      verification,
    };
  }

  async summarize(result: ScanResult): Promise<ExecutiveSummary> {
    const active = result.findings.filter((f) => !f.suppressed);
    const critical = active.filter((f) => f.severity === 'critical');
    const high = active.filter((f) => f.severity === 'high');
    const secrets = active.filter((f) => f.kind === 'secrets');
    const aiFindings = active.filter((f) => f.kind === 'ai-security');

    const headline =
      critical.length > 0
        ? `${result.repository.name} has ${critical.length} critical ${critical.length === 1 ? 'issue' : 'issues'} requiring immediate attention, and scores ${result.scores.overall}/100 overall (grade ${result.scores.grade}).`
        : high.length > 0
          ? `${result.repository.name} has no critical issues but ${high.length} high-severity ${high.length === 1 ? 'finding' : 'findings'} to address, scoring ${result.scores.overall}/100 (grade ${result.scores.grade}).`
          : `${result.repository.name} scores ${result.scores.overall}/100 (grade ${result.scores.grade}) with ${active.length} open ${active.length === 1 ? 'finding' : 'findings'} and nothing critical outstanding.`;

    const weakest = [...result.scores.categories]
      .filter((c) => c.analyzed)
      .sort((a, b) => a.score - b.score)[0];

    const posture = weakest
      ? `The weakest area is ${weakest.category} at ${weakest.score}/100 — ${weakest.rationale.toLowerCase()} Overall risk level is ${result.scores.riskLevel}.`
      : `Overall risk level is ${result.scores.riskLevel}.`;

    const topRisks = [...critical, ...high]
      .slice(0, 5)
      .map((f) => `${f.title}${f.location ? ` (${f.location.path}:${f.location.startLine})` : ''}`);

    const recommendedActions: string[] = [];
    if (secrets.length) {
      recommendedActions.push(
        `Rotate ${secrets.length} exposed ${secrets.length === 1 ? 'credential' : 'credentials'} immediately — assume each is already compromised.`,
      );
    }
    if (critical.length) {
      recommendedActions.push(
        `Remediate ${critical.length} critical ${critical.length === 1 ? 'finding' : 'findings'} before the next release.`,
      );
    }
    const upgradable = active.filter(
      (f) => f.kind === 'dependencies' && f.metadata?.['fixedVersions'],
    );
    if (upgradable.length) {
      recommendedActions.push(
        `Upgrade ${upgradable.length} vulnerable ${upgradable.length === 1 ? 'dependency' : 'dependencies'} that already have published fixes — the cheapest risk reduction available.`,
      );
    }
    if (aiFindings.length) {
      recommendedActions.push(
        `Review ${aiFindings.length} AI-specific ${aiFindings.length === 1 ? 'finding' : 'findings'}; prioritize anywhere model output reaches an execution sink.`,
      );
    }
    if (!recommendedActions.length) {
      recommendedActions.push(
        'Maintain the current posture and keep dependency updates flowing automatically.',
      );
    }

    // The caveats matter as much as the findings: a report that implies
    // complete coverage it did not have is actively misleading.
    const caveats: string[] = [];
    const failed = result.scannerRuns.filter((r) => r.status === 'failed');
    const skipped = result.scannerRuns.filter((r) => r.status === 'skipped');
    const unanalyzed = result.scores.categories.filter((c) => !c.analyzed);

    if (failed.length) {
      caveats.push(
        `${failed.length} scanner(s) failed, so coverage is incomplete: ${failed.map((f) => f.scanner).join(', ')}.`,
      );
    }
    if (unanalyzed.length) {
      caveats.push(`Not assessed in this scan: ${unanalyzed.map((c) => c.category).join(', ')}.`);
    }
    if (!result.options.allowNetwork) {
      caveats.push(
        'Network access was disabled, so dependency analysis used the bundled advisory snapshot rather than live advisory data.',
      );
    }
    if (skipped.length) {
      caveats.push(
        `${skipped.length} scanner(s) were skipped or superseded; see the scanner coverage table for details.`,
      );
    }
    caveats.push(
      'Static analysis cannot prove reachability. Confirm each finding against how the code is actually invoked.',
    );

    return { headline, posture, topRisks, recommendedActions, caveats };
  }
}

/** Should this finding be explained, given the configured limits? */
export function shouldExplain(
  finding: Finding,
  minSeverity: Finding['severity'] | undefined,
): boolean {
  if (finding.suppressed) return false;
  if (!minSeverity) return true;
  return isAtLeast(finding.severity, minSeverity);
}
