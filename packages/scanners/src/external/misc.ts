import { normalizeSeverity, severityFromCvss, type RawFinding } from '@sentinel/core';
import { parseJsonLines, probeBinary, run, tryParseJson } from '../exec.js';
import type { Scanner } from '../types.js';

/**
 * Additional external tool adapters.
 *
 * Each follows the same contract: probe for the binary, run it with JSON
 * output, translate into `RawFinding`. Adding another tool means adding one
 * object here and registering it — no other part of the platform changes.
 */

/* ------------------------------------------------------------------ */
/* osv-scanner — Google's OSS-Vulnerability scanner                    */
/* ------------------------------------------------------------------ */

interface OsvScannerOutput {
  results?: {
    source?: { path?: string; type?: string };
    packages?: {
      package?: { name?: string; version?: string; ecosystem?: string };
      vulnerabilities?: {
        id: string;
        summary?: string;
        details?: string;
        aliases?: string[];
        severity?: { type?: string; score?: string }[];
        database_specific?: { severity?: string; cwe_ids?: string[] };
      }[];
      groups?: { ids?: string[]; max_severity?: string }[];
    }[];
  }[];
}

export const osvScannerScanner: Scanner = {
  id: 'osv-scanner',
  name: 'OSV-Scanner',
  kind: 'dependencies',
  origin: 'external',
  description:
    "Google's OSV-Scanner, matching lockfiles against the OSV.dev vulnerability database across every supported ecosystem.",
  supersedes: ['native-dependencies'],

  async isAvailable() {
    const probe = await probeBinary('osv-scanner', ['--version']);
    return probe.available
      ? { available: true, ...(probe.version ? { version: probe.version } : {}) }
      : { available: false, reason: 'osv-scanner is not installed (brew install osv-scanner)' };
  },

  async scan(ctx) {
    const result = await run('osv-scanner', ['--format', 'json', '--recursive', ctx.root], {
      timeoutMs: ctx.options.timeoutMs ?? 300_000,
      // 1 means vulnerabilities were found; 128 means nothing scannable.
      okExitCodes: [0, 1, 128],
      ...(ctx.signal ? { signal: ctx.signal } : {}),
    });

    const output = tryParseJson<OsvScannerOutput>(result.stdout);
    if (!output?.results) return [];

    const findings: RawFinding[] = [];

    for (const group of output.results) {
      const path = (group.source?.path ?? '').replace(`${ctx.root}/`, '');

      for (const pkg of group.packages ?? []) {
        const maxSeverityLabel = pkg.groups?.[0]?.max_severity;

        for (const vuln of pkg.vulnerabilities ?? []) {
          const cvssEntry = vuln.severity?.find((s) => s.type?.startsWith('CVSS'));
          const cvss = cvssEntry?.score ? Number.parseFloat(cvssEntry.score) : undefined;

          findings.push({
            ruleId: `osv-${vuln.id}`,
            title: `${pkg.package?.name}@${pkg.package?.version}: ${vuln.summary ?? vuln.id}`,
            description:
              vuln.details?.slice(0, 2000) ?? vuln.summary ?? 'No description available.',
            severity:
              cvss !== undefined && Number.isFinite(cvss)
                ? severityFromCvss(cvss)
                : normalizeSeverity(vuln.database_specific?.severity ?? maxSeverityLabel),
            kind: 'dependencies',
            confidence: 'high',
            location: { path: path || 'unknown', startLine: 1 },
            component: {
              name: pkg.package?.name ?? 'unknown',
              version: pkg.package?.version ?? 'unknown',
              ecosystem: pkg.package?.ecosystem ?? 'unknown',
              path,
            },
            taxonomy: {
              cve: vuln.aliases?.filter((a) => a.startsWith('CVE-')) ?? [vuln.id],
              cwe: vuln.database_specific?.cwe_ids,
              owaspTop10: ['A06:2021-Vulnerable and Outdated Components'],
              references: [
                { title: 'OSV advisory', url: `https://osv.dev/vulnerability/${vuln.id}` },
              ],
            },
            metadata: { advisorySource: 'osv-scanner', cvss },
            remediationHint: `Upgrade ${pkg.package?.name} to a version outside the affected range.`,
          });
        }
      }
    }

    return findings;
  },
};

/* ------------------------------------------------------------------ */
/* Checkov — IaC policy scanning                                       */
/* ------------------------------------------------------------------ */

interface CheckovOutput {
  results?: {
    failed_checks?: {
      check_id: string;
      bc_check_id?: string;
      check_name: string;
      file_path: string;
      file_line_range?: [number, number];
      resource?: string;
      guideline?: string;
      severity?: string;
    }[];
  };
  summary?: { failed?: number };
}

export const checkovScanner: Scanner = {
  id: 'checkov',
  name: 'Checkov',
  kind: 'iac',
  origin: 'external',
  description:
    'Bridgecrew Checkov policy-as-code scanning for Terraform, CloudFormation, Kubernetes, Helm, ARM and Serverless definitions.',
  supersedes: ['native-iac'],

  async isAvailable() {
    const probe = await probeBinary('checkov', ['--version']);
    return probe.available
      ? { available: true, ...(probe.version ? { version: probe.version } : {}) }
      : { available: false, reason: 'checkov is not installed (pip install checkov)' };
  },

  async scan(ctx) {
    const result = await run(
      'checkov',
      ['--directory', ctx.root, '--output', 'json', '--compact', '--quiet', '--skip-download'],
      {
        timeoutMs: ctx.options.timeoutMs ?? 600_000,
        okExitCodes: [0, 1],
        maxBuffer: 128 * 1024 * 1024,
        ...(ctx.signal ? { signal: ctx.signal } : {}),
      },
    );

    // Checkov emits either a single object or an array of framework results.
    const parsed = tryParseJson<CheckovOutput | CheckovOutput[]>(result.stdout);
    if (!parsed) return [];
    const groups = Array.isArray(parsed) ? parsed : [parsed];

    return groups.flatMap((group) =>
      (group.results?.failed_checks ?? []).map((check): RawFinding => ({
        ruleId: `checkov-${check.check_id}`,
        title: check.check_name,
        description: `Checkov policy ${check.check_id} failed${check.resource ? ` for resource \`${check.resource}\`` : ''}.`,
        severity: normalizeSeverity(check.severity, 'medium'),
        kind: 'iac',
        confidence: 'high',
        location: {
          path: check.file_path.replace(/^\//, ''),
          startLine: check.file_line_range?.[0] ?? 1,
          ...(check.file_line_range?.[1] ? { endLine: check.file_line_range[1] } : {}),
        },
        taxonomy: {
          owaspTop10: ['A05:2021-Security Misconfiguration'],
          references: check.guideline ? [{ title: 'Checkov guideline', url: check.guideline }] : [],
        },
        metadata: { resource: check.resource, bcCheckId: check.bc_check_id },
        remediationHint: check.guideline
          ? `See the Checkov guideline for remediation: ${check.guideline}`
          : 'Update the resource definition to satisfy the policy.',
      })),
    );
  },
};

/* ------------------------------------------------------------------ */
/* Hadolint — Dockerfile linting                                       */
/* ------------------------------------------------------------------ */

interface HadolintFinding {
  file: string;
  line: number;
  column: number;
  level: string;
  code: string;
  message: string;
}

export const hadolintScanner: Scanner = {
  id: 'hadolint',
  name: 'Hadolint',
  kind: 'container',
  origin: 'external',
  description: 'Dockerfile linter enforcing image build best practices and security rules.',
  supersedes: ['native-container'],

  async isAvailable() {
    const probe = await probeBinary('hadolint', ['--version']);
    return probe.available
      ? { available: true, ...(probe.version ? { version: probe.version } : {}) }
      : { available: false, reason: 'hadolint is not installed (brew install hadolint)' };
  },

  async scan(ctx) {
    const dockerfiles = ctx.files.filter((file) =>
      /(?:^|\/)(?:Dockerfile|Containerfile)/i.test(file.path),
    );
    if (!dockerfiles.length) return [];

    const result = await run(
      'hadolint',
      ['--format', 'json', '--no-fail', ...dockerfiles.map((f) => f.absolutePath)],
      {
        timeoutMs: 120_000,
        okExitCodes: [0, 1],
        ...(ctx.signal ? { signal: ctx.signal } : {}),
      },
    );

    const findings =
      tryParseJson<HadolintFinding[]>(result.stdout) ??
      parseJsonLines<HadolintFinding>(result.stdout);

    return findings.map((item): RawFinding => ({
      ruleId: `hadolint-${item.code}`,
      title: item.message,
      description: `Hadolint rule ${item.code}: ${item.message}`,
      severity: normalizeSeverity(item.level, 'low'),
      kind: 'container',
      confidence: 'high',
      location: {
        path: item.file.replace(`${ctx.root}/`, ''),
        startLine: item.line,
        startColumn: item.column,
      },
      taxonomy: {
        owaspTop10: ['A05:2021-Security Misconfiguration'],
        references: [
          { title: 'Hadolint rule', url: `https://github.com/hadolint/hadolint/wiki/${item.code}` },
        ],
      },
      remediationHint: `See the Hadolint wiki entry for ${item.code}.`,
    }));
  },
};

/* ------------------------------------------------------------------ */
/* Syft — SBOM generation                                              */
/* ------------------------------------------------------------------ */

export const syftScanner: Scanner = {
  id: 'syft',
  name: 'Syft',
  kind: 'sbom',
  origin: 'external',
  description:
    'Anchore Syft, generating a high-fidelity CycloneDX SBOM with deep package resolution.',
  supersedes: ['native-sbom'],

  async isAvailable() {
    const probe = await probeBinary('syft', ['version']);
    return probe.available
      ? { available: true, ...(probe.version ? { version: probe.version } : {}) }
      : { available: false, reason: 'syft is not installed (brew install syft)' };
  },

  async scan(ctx) {
    const result = await run('syft', ['scan', `dir:${ctx.root}`, '-o', 'cyclonedx-json', '-q'], {
      timeoutMs: ctx.options.timeoutMs ?? 300_000,
      maxBuffer: 128 * 1024 * 1024,
      ...(ctx.signal ? { signal: ctx.signal } : {}),
    });

    const sbom = tryParseJson<{ components?: unknown[] }>(result.stdout);
    const count = sbom?.components?.length ?? 0;

    return [
      {
        ruleId: 'sbom-generated',
        title: `Software bill of materials generated for ${count} components`,
        description:
          'Syft produced a CycloneDX SBOM with deep package resolution across the repository.',
        severity: 'info',
        kind: 'sbom',
        confidence: 'high',
        metadata: {
          componentCount: count,
          generator: 'syft',
          sbom: result.stdout.slice(0, 2_000_000),
        },
        remediationHint: 'Export the SBOM and attach it to your release artifacts.',
      },
    ];
  },
};
