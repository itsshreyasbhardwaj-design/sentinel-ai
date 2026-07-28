import { mapLimit, type RawFinding } from '@sentinel/core';
import { runRules } from '../rules/engine.js';
import { SAST_RULES } from '../rules/sast.js';
import type { Scanner } from '../types.js';

/**
 * Bundled static analysis.
 *
 * Always available — no binary, no download, no network. When Semgrep is
 * installed the registry prefers it and this scanner steps aside, but the
 * platform is never left with zero SAST coverage.
 */
export const nativeSastScanner: Scanner = {
  id: 'native-sast',
  name: 'Sentinel SAST',
  kind: 'sast',
  origin: 'native',
  description:
    'Pattern-based static analysis across TypeScript, JavaScript, Python, Java, Go, Rust, C# and PHP with CWE and OWASP mappings.',
  languages: ['typescript', 'javascript', 'python', 'java', 'go', 'rust', 'csharp', 'php'],

  async isAvailable() {
    return { available: true };
  },

  async scan(ctx) {
    const candidates = ctx.files.filter(
      (file) =>
        file.language !== 'other' || file.path.endsWith('.vue') || file.path.endsWith('.svelte'),
    );

    ctx.logger.debug('Running native SAST', {
      files: candidates.length,
      rules: SAST_RULES.length,
    });

    const results = await mapLimit(candidates, ctx.options.concurrency, async (file) => {
      if (ctx.signal?.aborted) return [];
      try {
        const content = await ctx.readFile(file);
        return runRules(SAST_RULES, file, content);
      } catch (error) {
        // One unreadable file must not abort analysis of the other 20 000.
        ctx.logger.debug('Skipped file during SAST', { path: file.path, error: String(error) });
        return [];
      }
    });

    return results.flat() satisfies RawFinding[];
  },
};
