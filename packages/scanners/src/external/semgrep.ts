import { normalizeSeverity, type RawFinding } from '@sentinel/core';
import { probeBinary, run, tryParseJson } from '../exec.js';
import type { Scanner } from '../types.js';

/**
 * Semgrep adapter.
 *
 * Semgrep is the best-in-class open-source SAST engine, with a far larger and
 * better-maintained rule corpus than anything we would write ourselves. When it
 * is installed we defer to it and our native SAST scanner stands down.
 */

interface SemgrepResult {
  check_id: string;
  path: string;
  start: { line: number; col: number };
  end: { line: number; col: number };
  extra: {
    message: string;
    severity: string;
    lines?: string;
    metadata?: {
      cwe?: string | string[];
      owasp?: string | string[];
      references?: string[];
      confidence?: string;
      category?: string;
      technology?: string[];
      impact?: string;
      likelihood?: string;
    };
    fix?: string;
  };
}

interface SemgrepOutput {
  results?: SemgrepResult[];
  errors?: { message?: string }[];
}

function asArray(value: string | string[] | undefined): string[] {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

/** Semgrep writes CWEs as `CWE-79: Cross-site Scripting`; keep just the id. */
function extractCweIds(values: string[]): string[] {
  return values
    .map((value) => /CWE-\d+/i.exec(value)?.[0]?.toUpperCase())
    .filter((id): id is string => Boolean(id));
}

export const semgrepScanner: Scanner = {
  id: 'semgrep',
  name: 'Semgrep',
  kind: 'sast',
  origin: 'external',
  description:
    'Semantic static analysis using the Semgrep registry rulesets (p/security-audit, p/secrets, p/owasp-top-ten).',
  supersedes: ['native-sast'],

  async isAvailable() {
    const probe = await probeBinary('semgrep', ['--version']);
    return probe.available
      ? { available: true, ...(probe.version ? { version: probe.version } : {}) }
      : { available: false, reason: 'semgrep is not installed (pip install semgrep)' };
  },

  async scan(ctx) {
    const args = [
      '--json',
      '--quiet',
      '--no-git-ignore',
      '--metrics=off',
      '--disable-version-check',
      '--timeout',
      '30',
      '--max-target-bytes',
      String(ctx.options.maxFileSizeBytes),
      '--config',
      'p/security-audit',
      '--config',
      'p/owasp-top-ten',
      '.',
    ];

    // Semgrep exits 1 when it finds something, which is success for our purposes.
    const result = await run('semgrep', args, {
      cwd: ctx.root,
      timeoutMs: ctx.options.timeoutMs ?? 600_000,
      okExitCodes: [0, 1],
      ...(ctx.signal ? { signal: ctx.signal } : {}),
    });

    const output = tryParseJson<SemgrepOutput>(result.stdout);
    if (!output?.results) {
      ctx.logger.warn('Semgrep produced no parseable output', {
        stderr: result.stderr.slice(0, 300),
      });
      return [];
    }

    if (output.errors?.length) {
      ctx.logger.warn('Semgrep reported errors on some files', { count: output.errors.length });
    }

    return output.results.map((item): RawFinding => {
      const metadata = item.extra.metadata ?? {};
      const cwe = extractCweIds(asArray(metadata.cwe));
      const owasp = asArray(metadata.owasp);

      return {
        ruleId: item.check_id,
        title: item.extra.message.split('\n')[0]!.slice(0, 200),
        description: item.extra.message,
        severity: normalizeSeverity(item.extra.severity),
        kind: 'sast',
        confidence:
          metadata.confidence === 'HIGH'
            ? 'high'
            : metadata.confidence === 'LOW'
              ? 'low'
              : 'medium',
        location: {
          path: item.path,
          startLine: item.start.line,
          endLine: item.end.line,
          startColumn: item.start.col,
          endColumn: item.end.col,
          snippet: item.extra.lines?.trim(),
        },
        taxonomy: {
          ...(cwe.length ? { cwe } : {}),
          ...(owasp.length ? { owaspTop10: owasp } : {}),
          references: (metadata.references ?? [])
            .slice(0, 5)
            .map((url) => ({ title: 'Reference', url })),
        },
        metadata: {
          category: metadata.category,
          technology: metadata.technology,
          impact: metadata.impact,
          likelihood: metadata.likelihood,
        },
        ...(item.extra.fix ? { remediationHint: `Semgrep suggests: ${item.extra.fix}` } : {}),
      };
    });
  },
};
