import { matchesAnyGlob, type RawFinding } from '@sentinel/core';
import type { FileEntry, Rule, RuleMatch } from '../types.js';

/**
 * Inline suppression markers. Sentinel's own marker is honoured, and so are the
 * two most widespread ecosystem markers — a team that already annotated a false
 * positive for Semgrep or Bandit should not have to do it twice.
 */
const SUPPRESSION_PATTERNS = [
  /sentinel-disable-next-line(?:\s+(?<rules>[\w,\s-]+))?/i,
  /nosemgrep(?::\s*(?<rules>[\w,\s.-]+))?/i,
  /#\s*nosec\b(?<rules>[\w,\s]*)/i,
  /eslint-disable-next-line\s+security\//i,
];

/** Number of surrounding lines captured for UI context. */
const CONTEXT_LINES = 3;

/** Match on the same line (trailing comment) or the line above. */
function isSuppressed(lines: readonly string[], lineIndex: number, ruleId: string): boolean {
  for (const offset of [0, -1]) {
    const line = lines[lineIndex + offset];
    if (!line) continue;
    for (const pattern of SUPPRESSION_PATTERNS) {
      const match = pattern.exec(line);
      if (!match) continue;
      const scoped = match.groups?.['rules']?.trim();
      // A bare marker suppresses everything on that line; a scoped one only its
      // listed rules.
      if (!scoped) return true;
      const ids = scoped.split(/[,\s]+/).filter(Boolean);
      if (ids.some((id) => id === ruleId || ruleId.includes(id))) return true;
    }
  }
  return false;
}

function buildLocation(
  lines: readonly string[],
  lineNumber: number,
  column: number,
  matchLength: number,
) {
  const index = lineNumber - 1;
  return {
    path: '',
    startLine: lineNumber,
    endLine: lineNumber,
    startColumn: column + 1,
    endColumn: column + matchLength + 1,
    snippet: lines[index]?.trim() ?? '',
    contextBefore: lines.slice(Math.max(0, index - CONTEXT_LINES), index).map((l) => l.trimEnd()),
    contextAfter: lines.slice(index + 1, index + 1 + CONTEXT_LINES).map((l) => l.trimEnd()),
  };
}

export function ruleAppliesTo(rule: Rule, file: FileEntry): boolean {
  if (rule.languages?.length && !rule.languages.includes(file.language)) return false;
  if (rule.pathPatterns?.length && !matchesAnyGlob(file.path, rule.pathPatterns)) return false;
  return true;
}

/**
 * Apply a rule pack to one file.
 *
 * Deliberately line-oriented rather than AST-based: it works uniformly across
 * eight languages with no per-language parser, degrades gracefully on files it
 * does not fully understand, and cannot be defeated by a syntax error. Rules
 * that need more precision supply a `validate` callback with whole-file access.
 */
export function runRules(rules: readonly Rule[], file: FileEntry, content: string): RawFinding[] {
  const lines = content.split('\n');
  const findings: RawFinding[] = [];
  // One finding per rule per line — a regex that matches three times on one
  // line describes a single defect.
  const seen = new Set<string>();

  for (const rule of rules) {
    if (!ruleAppliesTo(rule, file)) continue;

    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i]!;
      if (!line.trim()) continue;
      // Skip absurdly long lines: they are minified output, and regex
      // backtracking over them is where scanners hang.
      if (line.length > 2000) continue;

      for (const pattern of rule.patterns) {
        // Patterns are shared across files, so reset any lastIndex state.
        pattern.lastIndex = 0;
        const match = pattern.exec(line);
        if (!match) continue;

        const key = `${rule.id}:${i}`;
        if (seen.has(key)) break;

        if (
          rule.excludePatterns?.some((exclude) => {
            exclude.lastIndex = 0;
            return exclude.test(line);
          })
        ) {
          break;
        }

        if (isSuppressed(lines, i, rule.id)) break;

        const ruleMatch: RuleMatch = {
          rule,
          file,
          line,
          lineNumber: i + 1,
          column: match.index,
          matchText: match[0],
          lines,
        };

        if (rule.validate && !rule.validate(ruleMatch)) break;

        seen.add(key);
        findings.push({
          ruleId: rule.id,
          title: rule.title,
          description: rule.description,
          severity: rule.severity,
          kind: rule.kind,
          confidence: rule.confidence ?? 'medium',
          location: {
            ...buildLocation(lines, i + 1, match.index, match[0].length),
            path: file.path,
          },
          taxonomy: rule.taxonomy,
          remediationHint: rule.remediationHint,
          metadata: { language: file.language },
        });
        break;
      }
    }
  }

  return findings;
}

/* ------------------------------------------------------------------ */
/* Shared validators                                                   */
/* ------------------------------------------------------------------ */

/** Lines that are pure comments rarely represent live code paths. */
export function notInComment(match: RuleMatch): boolean {
  const before = match.line.slice(0, match.column);
  if (/(^|\s)(\/\/|#)/.test(before)) return false;
  if (/^\s*\*/.test(match.line)) return false;
  if (/^\s*(\/\*|<!--)/.test(match.line)) return false;
  return true;
}

const TEST_PATH =
  /(^|\/)(tests?|spec|__tests__|__mocks__|e2e|fixtures?|examples?|samples?|docs?)(\/|$)/i;
const TEST_FILE = /\.(test|spec)\.[a-z]+$/i;

export function isTestPath(path: string): boolean {
  return TEST_PATH.test(path) || TEST_FILE.test(path);
}

/** Findings in test and fixture code are usually intentional. */
export function notInTests(match: RuleMatch): boolean {
  return !isTestPath(match.file.path);
}

export function all(...validators: ((match: RuleMatch) => boolean)[]) {
  return (match: RuleMatch) => validators.every((validate) => validate(match));
}

/**
 * The matched line plus its neighbours, lowercased.
 *
 * Needed because the signal that makes a match interesting is often one line
 * away: `Math.random()` is only a finding because the enclosing function is
 * called `createResetToken`, and that name is on the line above.
 */
export function nearbyContext(match: RuleMatch, radius = 4): string {
  const index = match.lineNumber - 1;
  return match.lines
    .slice(Math.max(0, index - radius), index + radius + 1)
    .join(' ')
    .toLowerCase();
}

/** Builds a validator that requires `pattern` to appear near the match. */
export function contextMatches(pattern: RegExp, radius = 4) {
  return (match: RuleMatch) => pattern.test(nearbyContext(match, radius));
}

/**
 * True when the matched expression mixes a literal with something dynamic —
 * the signal that separates `query("SELECT 1")` from `query("SELECT " + id)`.
 */
export function hasDynamicInterpolation(text: string): boolean {
  if (/\$\{[^}]+\}/.test(text)) return true;
  if (/["'`]\s*\+\s*(?!["'`])/.test(text)) return true;
  if (/\+\s*["'`]/.test(text) && /[a-zA-Z_$][\w$]*\s*\+/.test(text)) return true;
  if (/%\s*[\w(]/.test(text)) return true;
  if (/\.format\s*\(/.test(text)) return true;
  if (/f["']/.test(text)) return true;
  return false;
}
