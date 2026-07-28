import { normalizeSeverity, severityFromCvss, type RawFinding } from '@sentinel/core';
import { probeBinary, run, tryParseJson } from '../exec.js';
import type { Scanner } from '../types.js';

/**
 * Trivy adapter.
 *
 * Trivy is the broadest open-source scanner available: it covers dependency
 * vulnerabilities across every ecosystem, IaC misconfiguration, container
 * images and licences from one binary with a continuously updated database.
 * When present it supersedes both our dependency and IaC scanners.
 */

interface TrivyVulnerability {
  VulnerabilityID: string;
  PkgName: string;
  PkgPath?: string;
  InstalledVersion: string;
  FixedVersion?: string;
  Title?: string;
  Description?: string;
  Severity: string;
  CweIDs?: string[];
  References?: string[];
  CVSS?: Record<string, { V3Score?: number; V2Score?: number }>;
  PrimaryURL?: string;
}

interface TrivyMisconfiguration {
  ID: string;
  AVDID?: string;
  Type: string;
  Title: string;
  Description: string;
  Message: string;
  Resolution?: string;
  Severity: string;
  PrimaryURL?: string;
  CauseMetadata?: {
    StartLine?: number;
    EndLine?: number;
    Code?: { Lines?: { Content?: string }[] };
  };
}

interface TrivySecret {
  RuleID: string;
  Category: string;
  Severity: string;
  Title: string;
  StartLine: number;
  EndLine: number;
  Match: string;
}

interface TrivyResult {
  Target: string;
  Class?: string;
  Type?: string;
  Vulnerabilities?: TrivyVulnerability[];
  Misconfigurations?: TrivyMisconfiguration[];
  Secrets?: TrivySecret[];
  Licenses?: { PkgName: string; Name: string; Severity: string; Category?: string }[];
}

interface TrivyOutput {
  Results?: TrivyResult[];
}

/** Prefer the highest CVSS v3 score any source assigned. */
function bestCvss(cvss: TrivyVulnerability['CVSS']): number | undefined {
  if (!cvss) return undefined;
  const scores = Object.values(cvss)
    .map((entry) => entry.V3Score)
    .filter((score): score is number => typeof score === 'number');
  return scores.length ? Math.max(...scores) : undefined;
}

export const trivyScanner: Scanner = {
  id: 'trivy',
  name: 'Trivy',
  kind: 'dependencies',
  origin: 'external',
  description:
    'Aqua Security Trivy: dependency vulnerabilities, IaC misconfiguration, licences and secrets from a continuously updated database.',
  supersedes: ['native-dependencies', 'native-iac'],

  async isAvailable() {
    const probe = await probeBinary('trivy', ['--version']);
    return probe.available
      ? { available: true, ...(probe.version ? { version: probe.version } : {}) }
      : { available: false, reason: 'trivy is not installed (brew install trivy)' };
  },

  async scan(ctx) {
    const args = [
      'filesystem',
      '--format',
      'json',
      '--quiet',
      '--scanners',
      'vuln,misconfig,secret,license',
      '--severity',
      'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL',
    ];

    // Without network access Trivy cannot refresh its database; tell it not to
    // try rather than letting it fail the whole scan on a timeout.
    if (!ctx.options.allowNetwork) args.push('--skip-db-update', '--offline-scan');
    args.push(ctx.root);

    const result = await run('trivy', args, {
      timeoutMs: ctx.options.timeoutMs ?? 600_000,
      okExitCodes: [0, 1],
      maxBuffer: 128 * 1024 * 1024,
      ...(ctx.signal ? { signal: ctx.signal } : {}),
    });

    const output = tryParseJson<TrivyOutput>(result.stdout);
    if (!output?.Results) {
      ctx.logger.warn('Trivy produced no parseable output', {
        stderr: result.stderr.slice(0, 300),
      });
      return [];
    }

    const findings: RawFinding[] = [];
    const relativize = (target: string) =>
      target.replace(`${ctx.root}/`, '').replace(ctx.root, '.');

    for (const group of output.Results) {
      const path = relativize(group.Target);

      for (const vuln of group.Vulnerabilities ?? []) {
        const cvss = bestCvss(vuln.CVSS);
        findings.push({
          ruleId: `trivy-${vuln.VulnerabilityID}`,
          title: `${vuln.PkgName}@${vuln.InstalledVersion}: ${vuln.Title ?? vuln.VulnerabilityID}`,
          description: vuln.Description ?? vuln.Title ?? 'No description provided.',
          severity: cvss !== undefined ? severityFromCvss(cvss) : normalizeSeverity(vuln.Severity),
          kind: 'dependencies',
          confidence: 'high',
          location: { path: vuln.PkgPath ?? path, startLine: 1 },
          component: {
            name: vuln.PkgName,
            version: vuln.InstalledVersion,
            ecosystem: group.Type ?? 'unknown',
            path: vuln.PkgPath ?? path,
          },
          taxonomy: {
            cve: [vuln.VulnerabilityID],
            cwe: vuln.CweIDs,
            owaspTop10: ['A06:2021-Vulnerable and Outdated Components'],
            references: [
              ...(vuln.PrimaryURL ? [{ title: 'Advisory', url: vuln.PrimaryURL }] : []),
              ...(vuln.References ?? []).slice(0, 4).map((url) => ({ title: 'Reference', url })),
            ],
          },
          metadata: { cvss, fixedVersion: vuln.FixedVersion, advisorySource: 'trivy' },
          remediationHint: vuln.FixedVersion
            ? `Upgrade ${vuln.PkgName} to ${vuln.FixedVersion} or later.`
            : 'No fixed version is available yet; assess reachability and consider an alternative package.',
        });
      }

      for (const misconfig of group.Misconfigurations ?? []) {
        findings.push({
          ruleId: `trivy-${misconfig.ID}`,
          title: misconfig.Title,
          description: `${misconfig.Description}\n\n${misconfig.Message}`,
          severity: normalizeSeverity(misconfig.Severity),
          kind: misconfig.Type?.toLowerCase().includes('docker') ? 'container' : 'iac',
          confidence: 'high',
          location: {
            path,
            startLine: misconfig.CauseMetadata?.StartLine ?? 1,
            ...(misconfig.CauseMetadata?.EndLine
              ? { endLine: misconfig.CauseMetadata.EndLine }
              : {}),
            snippet: misconfig.CauseMetadata?.Code?.Lines?.map((l) => l.Content ?? '')
              .join('\n')
              .trim(),
          },
          taxonomy: {
            owaspTop10: ['A05:2021-Security Misconfiguration'],
            references: misconfig.PrimaryURL
              ? [{ title: 'Details', url: misconfig.PrimaryURL }]
              : [],
          },
          metadata: { avdId: misconfig.AVDID, configType: misconfig.Type },
          ...(misconfig.Resolution ? { remediationHint: misconfig.Resolution } : {}),
        });
      }

      for (const secret of group.Secrets ?? []) {
        findings.push({
          ruleId: `trivy-secret-${secret.RuleID}`,
          title: secret.Title,
          description: `Trivy detected a ${secret.Category} credential in this file.`,
          severity: normalizeSeverity(secret.Severity, 'critical'),
          kind: 'secrets',
          confidence: 'high',
          location: { path, startLine: secret.StartLine, endLine: secret.EndLine },
          taxonomy: { cwe: ['CWE-798'] },
          metadata: { category: secret.Category },
          remediationHint: 'Rotate the credential and remove it from source control.',
        });
      }
    }

    return findings;
  },
};
