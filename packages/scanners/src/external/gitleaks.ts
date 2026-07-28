import { join } from 'node:path';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import type { RawFinding } from '@sentinel/core';
import { maskSecret } from '../rules/secrets.js';
import { probeBinary, run, tryParseJson } from '../exec.js';
import type { Scanner } from '../types.js';

/**
 * Gitleaks adapter.
 *
 * Gitleaks scans git *history*, not just the working tree — which matters,
 * because deleting a secret in a later commit does not remove it from the
 * repository. That is the capability our native scanner cannot replicate
 * without reimplementing git object traversal.
 */

interface GitleaksFinding {
  RuleID: string;
  Description: string;
  File: string;
  StartLine: number;
  EndLine: number;
  StartColumn?: number;
  Secret: string;
  Match: string;
  Entropy?: number;
  Commit?: string;
  Author?: string;
  Date?: string;
  Message?: string;
}

export const gitleaksScanner: Scanner = {
  id: 'gitleaks',
  name: 'Gitleaks',
  kind: 'secrets',
  origin: 'external',
  description:
    'Scans the working tree and full git history for committed credentials using the Gitleaks rule corpus.',
  // Deliberately does *not* supersede the native scanner: the two use different
  // rule sets and corroborating hits raise confidence.

  async isAvailable() {
    const probe = await probeBinary('gitleaks', ['version']);
    return probe.available
      ? { available: true, ...(probe.version ? { version: probe.version } : {}) }
      : { available: false, reason: 'gitleaks is not installed (brew install gitleaks)' };
  },

  async scan(ctx) {
    const workDir = await mkdtemp(join(tmpdir(), 'sentinel-gitleaks-'));
    const reportPath = join(workDir, 'report.json');

    try {
      await run(
        'gitleaks',
        [
          'detect',
          '--source',
          ctx.root,
          '--report-format',
          'json',
          '--report-path',
          reportPath,
          '--no-banner',
          '--exit-code',
          '0',
        ],
        {
          timeoutMs: ctx.options.timeoutMs ?? 300_000,
          okExitCodes: [0, 1],
          ...(ctx.signal ? { signal: ctx.signal } : {}),
        },
      );

      const raw = await readFile(reportPath, 'utf8').catch(() => '[]');
      const findings = tryParseJson<GitleaksFinding[]>(raw) ?? [];

      return findings.map((item): RawFinding => {
        const inHistory = Boolean(item.Commit);

        return {
          ruleId: `gitleaks-${item.RuleID}`,
          title: `${item.Description} found in ${inHistory ? 'git history' : 'the working tree'}`,
          description: inHistory
            ? `${item.Description}. This secret is present in commit ${item.Commit?.slice(0, 8)} and remains recoverable from git history even if the file has since been changed.`
            : item.Description,
          severity: 'critical',
          kind: 'secrets',
          confidence: 'high',
          location: {
            path: item.File,
            startLine: item.StartLine,
            endLine: item.EndLine,
            ...(item.StartColumn ? { startColumn: item.StartColumn } : {}),
            // Never propagate the raw secret out of the adapter.
            snippet: item.Match
              ? item.Match.replace(item.Secret, maskSecret(item.Secret)).slice(0, 200)
              : undefined,
          },
          taxonomy: {
            cwe: ['CWE-798', 'CWE-540'],
            owaspTop10: ['A05:2021-Security Misconfiguration'],
          },
          metadata: {
            gitleaksRule: item.RuleID,
            entropy: item.Entropy,
            masked: maskSecret(item.Secret),
            ...(inHistory
              ? { commit: item.Commit, author: item.Author, date: item.Date, inGitHistory: true }
              : {}),
          },
          remediationHint: inHistory
            ? 'Rotate the credential first — it is already exposed. Then purge it from history with git-filter-repo or the BFG, and force-push after coordinating with every collaborator.'
            : 'Rotate the credential and move it into a secret manager or environment variable.',
        };
      });
    } finally {
      await rm(workDir, { recursive: true, force: true }).catch(() => {});
    }
  },
};
