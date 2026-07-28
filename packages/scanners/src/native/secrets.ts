import { mapLimit, type RawFinding } from '@sentinel/core';
import {
  GENERIC_SECRET_ASSIGNMENT,
  SECRET_PATTERNS,
  assessGenericSecret,
  maskSecret,
  shannonEntropy,
} from '../rules/secrets.js';
import type { FileEntry, Scanner } from '../types.js';

/**
 * Bundled secret detection.
 *
 * Findings never include the raw credential: the snippet is masked before it
 * leaves this module. A scanner that copies live secrets into a database, a
 * report and a Slack notification has multiplied the exposure it was hired to
 * reduce.
 */

const SUPPRESSION =
  /(?:sentinel-disable-next-line|gitleaks:allow|nosecret|pragma:\s*allowlist\s+secret)/i;

/**
 * Files that exist specifically to hold fake credentials.
 *
 * `.env.example` is the canonical case: its whole purpose is to show the shape
 * of each variable. Flagging it teaches people that the secret scanner is wrong,
 * which is how a scanner gets switched off.
 */
const TEMPLATE_FILE =
  /(?:^|\/)(?:\.env\.(?:example|sample|template|dist)|.*\.(?:example|sample|template|dist)(?:\.[a-z]+)?)$/i;

/**
 * A commented-out line in a config file is documentation, not a live credential.
 * Matches `#`, `//` and `;` comment styles at the start of the line.
 */
const COMMENTED_OUT = /^\s*(?:#|\/\/|;|--)/;

function maskLine(line: string, secret: string): string {
  return line.replace(secret, maskSecret(secret)).trim().slice(0, 200);
}

function scanFileForSecrets(file: FileEntry, content: string): RawFinding[] {
  const findings: RawFinding[] = [];
  const lines = content.split('\n');
  // Same credential on ten lines is one leak to revoke, not ten findings.
  const seenSecrets = new Set<string>();

  // Template files hold placeholder values by definition. Skipping the whole
  // file is correct and much clearer than filtering value by value.
  if (TEMPLATE_FILE.test(file.path)) return findings;

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i]!;
    if (!line.trim() || line.length > 4000) continue;
    if (SUPPRESSION.test(line)) continue;
    if (i > 0 && SUPPRESSION.test(lines[i - 1]!)) continue;
    // A commented-out connection string in a config file is an example of the
    // format, not a leaked credential.
    if (COMMENTED_OUT.test(line)) continue;

    /* --- Provider-specific patterns: high confidence --- */
    for (const pattern of SECRET_PATTERNS) {
      pattern.pattern.lastIndex = 0;
      let match: RegExpExecArray | null;

      while ((match = pattern.pattern.exec(line))) {
        const secret = match[1] ?? match[0];
        if (!secret) break;

        if (pattern.minEntropy && shannonEntropy(secret) < pattern.minEntropy) continue;

        const key = `${pattern.id}:${secret}`;
        if (seenSecrets.has(key)) continue;
        seenSecrets.add(key);

        findings.push({
          ruleId: `secret-${pattern.id}`,
          title: `${pattern.title} committed to the repository`,
          description: `A ${pattern.provider} credential was found in source. Assume it is compromised: anyone with repository access — including forks, clones and CI logs — can read it.`,
          severity: pattern.severity,
          kind: 'secrets',
          confidence: 'high',
          location: {
            path: file.path,
            startLine: i + 1,
            snippet: maskLine(line, secret),
            contextBefore: lines.slice(Math.max(0, i - 2), i).map((l) => l.trimEnd().slice(0, 200)),
            contextAfter: lines.slice(i + 1, i + 3).map((l) => l.trimEnd().slice(0, 200)),
          },
          taxonomy: {
            cwe: ['CWE-798', 'CWE-540'],
            owaspTop10: [
              'A05:2021-Security Misconfiguration',
              'A07:2021-Identification and Authentication Failures',
            ],
            references: [
              {
                title: 'CWE-798: Use of Hard-coded Credentials',
                url: 'https://cwe.mitre.org/data/definitions/798.html',
              },
            ],
          },
          metadata: {
            provider: pattern.provider,
            masked: maskSecret(secret),
            entropy: Math.round(shannonEntropy(secret) * 100) / 100,
            detector: 'pattern',
          },
          remediationHint: pattern.revocation,
        });
        break;
      }
    }

    /* --- Entropy analysis: the long tail of custom tokens --- */
    GENERIC_SECRET_ASSIGNMENT.lastIndex = 0;
    let generic: RegExpExecArray | null;

    while ((generic = GENERIC_SECRET_ASSIGNMENT.exec(line))) {
      const variableName = generic[1]!;
      const value = generic[2]!;

      const assessment = assessGenericSecret(variableName, value, file.path);
      if (!assessment.isSecret) continue;

      const key = `generic:${value}`;
      if (seenSecrets.has(key)) continue;
      seenSecrets.add(key);

      findings.push({
        ruleId: 'secret-generic-high-entropy',
        title: `Possible credential assigned to "${variableName}"`,
        description: `A high-entropy value (${assessment.entropy.toFixed(2)} bits/char) is assigned to a variable whose name suggests a credential. ${assessment.reason}.`,
        severity: assessment.confidence === 'high' ? 'high' : 'medium',
        kind: 'secrets',
        confidence: assessment.confidence,
        location: {
          path: file.path,
          startLine: i + 1,
          snippet: maskLine(line, value),
        },
        taxonomy: {
          cwe: ['CWE-798'],
          owaspTop10: ['A05:2021-Security Misconfiguration'],
          references: [
            {
              title: 'CWE-798: Use of Hard-coded Credentials',
              url: 'https://cwe.mitre.org/data/definitions/798.html',
            },
          ],
        },
        metadata: {
          variableName,
          masked: maskSecret(value),
          entropy: Math.round(assessment.entropy * 100) / 100,
          detector: 'entropy',
        },
        remediationHint:
          'Move the value into an environment variable or secret manager, then rotate it — a committed secret stays in git history even after the file is changed.',
      });
    }
  }

  return findings;
}

export const nativeSecretsScanner: Scanner = {
  id: 'native-secrets',
  name: 'Sentinel Secret Scanner',
  kind: 'secrets',
  origin: 'native',
  description:
    'Detects committed credentials using provider signatures for 20+ services plus Shannon entropy analysis, with placeholder filtering to suppress false positives.',

  async isAvailable() {
    return { available: true };
  },

  async scan(ctx) {
    // Secrets hide in config and lockfiles as often as in source, so this
    // scanner deliberately looks at every file the walker kept.
    const results = await mapLimit(ctx.files, ctx.options.concurrency, async (file) => {
      if (ctx.signal?.aborted) return [];
      try {
        return scanFileForSecrets(file, await ctx.readFile(file));
      } catch (error) {
        ctx.logger.debug('Skipped file during secret scan', {
          path: file.path,
          error: String(error),
        });
        return [];
      }
    });

    return results.flat();
  },
};
