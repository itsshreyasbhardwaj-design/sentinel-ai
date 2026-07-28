import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { matchesAnyGlob, type Logger } from '@sentinel/core';

/**
 * `.sentinelignore` support.
 *
 * Every repository has code that *should* look insecure: test fixtures,
 * documentation examples, sample payloads, and — for a security tool — the rule
 * definitions themselves. Without a way to exclude them the report fills with
 * findings the developer already knows about, and a noisy report gets ignored
 * entirely.
 *
 * The syntax is a deliberate subset of `.gitignore`, because that is the one
 * every developer already knows:
 *
 *   node_modules/          directory
 *   *.generated.ts         extension
 *   fixtures/**            subtree
 *   !fixtures/keep.ts      negation, re-including a path
 *   # comment
 */

export interface IgnoreRules {
  /** Patterns that exclude a path. */
  exclude: string[];
  /** Patterns that re-include an otherwise-excluded path. */
  include: string[];
}

export const SENTINELIGNORE_FILENAME = '.sentinelignore';

/**
 * Translate one `.gitignore`-style line into the glob syntax the walker uses.
 * Returns undefined for blank lines and comments.
 */
export function parseIgnoreLine(raw: string): { pattern: string; negated: boolean } | undefined {
  const line = raw.trim();
  if (!line || line.startsWith('#')) return undefined;

  const negated = line.startsWith('!');
  let pattern = negated ? line.slice(1).trim() : line;
  if (!pattern) return undefined;

  // A leading slash anchors to the repository root; everything else may match at
  // any depth, which is what `.gitignore` does and what users expect.
  const anchored = pattern.startsWith('/');
  if (anchored) pattern = pattern.slice(1);

  // A trailing slash means "directory and everything under it".
  if (pattern.endsWith('/')) pattern = `${pattern}**`;

  // A bare name with no glob syntax should match the whole subtree, so
  // `fixtures` behaves like `fixtures/**` rather than only the directory entry.
  if (!pattern.includes('*') && !pattern.includes('.')) pattern = `${pattern}/**`;

  return { pattern: anchored ? pattern : `**/${pattern}`, negated };
}

export function parseIgnoreFile(content: string): IgnoreRules {
  const exclude: string[] = [];
  const include: string[] = [];

  for (const line of content.split('\n')) {
    const parsed = parseIgnoreLine(line);
    if (!parsed) continue;
    (parsed.negated ? include : exclude).push(parsed.pattern);
  }

  return { exclude, include };
}

/** Read `.sentinelignore` from the repository root, if present. */
export async function loadIgnoreRules(root: string, logger?: Logger): Promise<IgnoreRules> {
  try {
    const content = await readFile(join(root, SENTINELIGNORE_FILENAME), 'utf8');
    const rules = parseIgnoreFile(content);
    logger?.debug('Loaded .sentinelignore', {
      exclude: rules.exclude.length,
      include: rules.include.length,
    });
    return rules;
  } catch {
    // Absent is the common case and not worth a log line.
    return { exclude: [], include: [] };
  }
}

/**
 * Apply ignore rules to a path.
 *
 * Negations win, matching `.gitignore` semantics: `!fixtures/real-code.ts`
 * re-includes a file that a broader `fixtures/**` rule excluded.
 */
export function isIgnored(path: string, rules: IgnoreRules): boolean {
  if (!rules.exclude.length) return false;
  if (!matchesAnyGlob(path, rules.exclude)) return false;
  return !matchesAnyGlob(path, rules.include);
}

/**
 * May the walker skip descending into this directory entirely?
 *
 * Pruning is a large speedup — not walking `fixtures/` at all beats walking it
 * and discarding every result. But pruning a directory makes every file inside
 * unreachable, so a negation like `!fixtures/keep.ts` could never take effect.
 *
 * Git accepts that limitation and documents it ("it is not possible to
 * re-include a file if a parent directory is excluded"). Sentinel does not:
 * silently ignoring a rule the user wrote is worse than walking a few extra
 * directories. When negations exist we descend and filter per file instead.
 */
export function canPruneDirectory(path: string, rules: IgnoreRules): boolean {
  if (!isIgnored(path, rules)) return false;
  return rules.include.length === 0;
}
