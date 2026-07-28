import { mapLimit, matchesAnyGlob, type RawFinding } from '@sentinel/core';
import { runRules } from '../rules/engine.js';
import { CONFIG_RULES, CONTAINER_RULES, IAC_RULES } from '../rules/infrastructure.js';
import type { Rule, ScanContext, Scanner } from '../types.js';

/**
 * Container, infrastructure-as-code and application-configuration scanners.
 *
 * All three share one implementation because they differ only in which rule
 * pack and which file shapes they care about. Keeping them as three registered
 * scanners rather than one keeps the scoring categories and the "what did we
 * actually analyze" reporting honest.
 */

async function runPack(
  ctx: ScanContext,
  rules: Rule[],
  filePatterns: string[],
): Promise<RawFinding[]> {
  const targets = ctx.files.filter((file) => matchesAnyGlob(file.path, filePatterns));
  if (!targets.length) return [];

  const results = await mapLimit(targets, ctx.options.concurrency, async (file) => {
    if (ctx.signal?.aborted) return [];
    try {
      return runRules(rules, file, await ctx.readFile(file));
    } catch (error) {
      ctx.logger.debug('Skipped file', { path: file.path, error: String(error) });
      return [];
    }
  });

  return results.flat();
}

const CONTAINER_FILES = [
  '**/Dockerfile',
  '**/Dockerfile.*',
  '**/*.dockerfile',
  '**/Containerfile',
  '**/docker-compose*.y*ml',
  '**/compose*.y*ml',
  '**/*.sh',
];

const IAC_FILES = [
  '**/*.tf',
  '**/*.tfvars',
  '**/*.tf.json',
  '**/*.hcl',
  '**/*.yaml',
  '**/*.yml',
  '**/*.json',
];

const CONFIG_FILES = [
  '**/.env',
  '**/.env.*',
  '**/.npmrc',
  '**/next.config.*',
  '**/nuxt.config.*',
  '**/vite.config.*',
  '**/.github/workflows/*.y*ml',
  '**/.github/actions/**/*.y*ml',
  '**/*.config.*',
  '**/middleware.*',
  '**/server.*',
  '**/app.*',
];

export const nativeContainerScanner: Scanner = {
  id: 'native-container',
  name: 'Sentinel Container Scanner',
  kind: 'container',
  origin: 'native',
  description:
    'Reviews Dockerfiles and Compose files for privilege, provenance and secret-handling problems.',

  async isAvailable() {
    return { available: true };
  },

  scan: (ctx) => runPack(ctx, CONTAINER_RULES, CONTAINER_FILES),
};

export const nativeIacScanner: Scanner = {
  id: 'native-iac',
  name: 'Sentinel IaC Scanner',
  kind: 'iac',
  origin: 'native',
  description:
    'Checks Terraform and Kubernetes definitions for public exposure, missing encryption, over-broad IAM and unsafe pod security context.',

  async isAvailable() {
    return { available: true };
  },

  scan: (ctx) => runPack(ctx, IAC_RULES, IAC_FILES),
};

export const nativeConfigScanner: Scanner = {
  id: 'native-config',
  name: 'Sentinel Configuration Scanner',
  kind: 'config',
  origin: 'native',
  description:
    'Audits application and CI configuration: committed environment files, unpinned GitHub Actions, workflow script injection and permissive CSP.',

  async isAvailable() {
    return { available: true };
  },

  scan: (ctx) => runPack(ctx, CONFIG_RULES, CONFIG_FILES),
};
