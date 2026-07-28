import type { Finding, ScanResult, Severity } from '@sentinel/core';

/**
 * SARIF 2.1.0 export.
 *
 * SARIF is the format GitHub code scanning, Azure DevOps and most IDEs consume,
 * so this is the export that puts findings in front of developers where they
 * already work rather than in yet another dashboard.
 *
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

export interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: SarifRun[];
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
    extensions?: { name: string; version?: string }[];
  };
  results: SarifResult[];
  invocations: {
    executionSuccessful: boolean;
    startTimeUtc: string;
    endTimeUtc?: string;
    toolExecutionNotifications?: { level: string; message: { text: string } }[];
  }[];
  automationDetails?: { id: string };
  versionControlProvenance?: { repositoryUri: string; revisionId?: string; branch?: string }[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription?: { text: string };
  help?: { text: string; markdown?: string };
  helpUri?: string;
  defaultConfiguration: { level: SarifLevel };
  properties?: {
    tags?: string[];
    precision?: string;
    'security-severity'?: string;
    problem?: { severity: string };
  };
}

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: SarifLevel;
  message: { text: string };
  locations: {
    physicalLocation: {
      artifactLocation: { uri: string };
      region?: {
        startLine: number;
        endLine?: number;
        startColumn?: number;
        endColumn?: number;
        snippet?: { text: string };
      };
    };
  }[];
  partialFingerprints: Record<string, string>;
  properties?: Record<string, unknown>;
  fixes?: { description: { text: string } }[];
}

type SarifLevel = 'none' | 'note' | 'warning' | 'error';

/** SARIF has four levels; map our five-point ladder onto them. */
const LEVEL: Record<Severity, SarifLevel> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'none',
};

/**
 * GitHub uses `security-severity` (a CVSS-like number) to decide which findings
 * block a pull request, so the mapping has to be deliberate rather than
 * incidental.
 */
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: '9.5',
  high: '7.5',
  medium: '5.0',
  low: '3.0',
  info: '0.0',
};

const PRECISION: Record<Finding['confidence'], string> = {
  high: 'high',
  medium: 'medium',
  low: 'low',
};

function ruleTags(finding: Finding): string[] {
  return [
    'security',
    finding.kind,
    ...(finding.taxonomy?.cwe ?? []),
    ...(finding.taxonomy?.owaspTop10 ?? []).map((o) => `OWASP-${o.split('-')[0]}`),
    ...(finding.taxonomy?.owaspLlmTop10 ?? []).map((o) => `OWASP-LLM-${o.split(':')[0]}`),
  ].filter(Boolean);
}

function helpMarkdown(finding: Finding): string {
  const parts: string[] = [];
  if (finding.explanation) {
    parts.push(finding.explanation.plainEnglish);
    parts.push(`\n**Business impact:** ${finding.explanation.businessImpact}`);
    if (finding.explanation.suggestedFixes.length) {
      parts.push('\n**How to fix:**');
      for (const fix of finding.explanation.suggestedFixes) {
        parts.push(`- **${fix.title}** — ${fix.description}`);
        if (fix.code) parts.push(`\n\`\`\`${fix.language ?? ''}\n${fix.code}\n\`\`\``);
      }
    }
  } else {
    parts.push(finding.description ?? finding.title);
    if (finding.remediationHint) parts.push(`\n**Remediation:** ${finding.remediationHint}`);
  }

  const references = finding.taxonomy?.references ?? [];
  if (references.length) {
    parts.push('\n**References:**');
    for (const ref of references.slice(0, 5)) parts.push(`- [${ref.title}](${ref.url})`);
  }

  return parts.join('\n');
}

export function toSarif(result: ScanResult): SarifLog {
  // One rule entry per distinct ruleId; results reference it by index.
  const ruleIndex = new Map<string, number>();
  const rules: SarifRule[] = [];

  for (const finding of result.findings) {
    if (ruleIndex.has(finding.ruleId)) continue;
    ruleIndex.set(finding.ruleId, rules.length);

    const helpUri = finding.taxonomy?.references?.[0]?.url;
    rules.push({
      id: finding.ruleId,
      name: finding.ruleId.replace(/[^a-zA-Z0-9]+/g, ''),
      shortDescription: { text: finding.title.slice(0, 200) },
      ...(finding.description ? { fullDescription: { text: finding.description } } : {}),
      help: {
        text: finding.remediationHint ?? finding.description ?? finding.title,
        markdown: helpMarkdown(finding),
      },
      ...(helpUri ? { helpUri } : {}),
      defaultConfiguration: { level: LEVEL[finding.severity] },
      properties: {
        tags: ruleTags(finding),
        precision: PRECISION[finding.confidence],
        'security-severity': SECURITY_SEVERITY[finding.severity],
        problem: { severity: finding.severity },
      },
    });
  }

  const results: SarifResult[] = result.findings
    // Suppressed findings are omitted rather than emitted as suppressed: GitHub
    // renders the latter as open alerts, which defeats the suppression.
    .filter((finding) => !finding.suppressed)
    .map((finding) => ({
      ruleId: finding.ruleId,
      ruleIndex: ruleIndex.get(finding.ruleId) ?? 0,
      level: LEVEL[finding.severity],
      message: { text: finding.explanation?.plainEnglish ?? finding.description ?? finding.title },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: finding.location?.path ?? 'unknown' },
            ...(finding.location
              ? {
                  region: {
                    startLine: Math.max(1, finding.location.startLine),
                    ...(finding.location.endLine ? { endLine: finding.location.endLine } : {}),
                    ...(finding.location.startColumn
                      ? { startColumn: finding.location.startColumn }
                      : {}),
                    ...(finding.location.endColumn
                      ? { endColumn: finding.location.endColumn }
                      : {}),
                    ...(finding.location.snippet
                      ? { snippet: { text: finding.location.snippet } }
                      : {}),
                  },
                }
              : {}),
          },
        },
      ],
      // GitHub uses these to track an alert across commits; the fingerprint is
      // exactly the stable identity we already compute.
      partialFingerprints: {
        sentinelFingerprint: finding.fingerprint,
        primaryLocationLineHash: finding.fingerprint.slice(0, 16),
      },
      properties: {
        scanner: finding.scanner,
        kind: finding.kind,
        riskScore: finding.riskScore,
        confidence: finding.confidence,
        ...(finding.component
          ? { component: `${finding.component.name}@${finding.component.version}` }
          : {}),
        ...(finding.taxonomy?.cve?.length ? { cve: finding.taxonomy.cve } : {}),
      },
      ...(finding.explanation?.suggestedFixes.length
        ? {
            fixes: finding.explanation.suggestedFixes.map((fix) => ({
              description: { text: `${fix.title}: ${fix.description}` },
            })),
          }
        : {}),
    }));

  const failedScanners = result.scannerRuns.filter((run) => run.status === 'failed');

  return {
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Sentinel AI',
            version: '0.1.0',
            informationUri: 'https://github.com/sentinel-ai/sentinel-ai',
            rules,
          },
          // Record which third-party engines contributed, for provenance.
          extensions: result.scannerRuns
            .filter((run) => run.scannerKind === 'external' && run.status === 'ok')
            .map((run) => ({
              name: run.scanner,
              ...(run.version ? { version: run.version } : {}),
            })),
        },
        results,
        invocations: [
          {
            executionSuccessful: result.status === 'completed',
            startTimeUtc: result.startedAt,
            ...(result.completedAt ? { endTimeUtc: result.completedAt } : {}),
            ...(failedScanners.length
              ? {
                  toolExecutionNotifications: failedScanners.map((run) => ({
                    level: 'error',
                    message: {
                      text: `Scanner ${run.scanner} failed: ${run.reason ?? 'unknown error'}`,
                    },
                  })),
                }
              : {}),
          },
        ],
        automationDetails: { id: `sentinel/${result.projectId}/${result.id}` },
        ...(result.repository.url
          ? {
              versionControlProvenance: [
                {
                  repositoryUri: result.repository.url,
                  ...(result.repository.commit ? { revisionId: result.repository.commit } : {}),
                  ...(result.repository.ref ? { branch: result.repository.ref } : {}),
                },
              ],
            }
          : {}),
      },
    ],
  };
}
