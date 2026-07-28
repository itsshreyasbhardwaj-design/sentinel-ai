import { preferLockfiles, parserForPath, type ParsedDependency } from '../manifests/index.js';
import type { ScanContext } from '../types.js';

/**
 * Dependency inventory, built once and shared.
 *
 * Three scanners need the same package list (SCA, license analysis, SBOM).
 * Parsing every manifest three times would triple the IO for no benefit, so the
 * result is memoized per scan context.
 */

const cache = new WeakMap<ScanContext, Promise<ParsedDependency[]>>();

async function build(ctx: ScanContext): Promise<ParsedDependency[]> {
  const manifests = ctx.files.filter((file) => parserForPath(file.path));
  const dependencies: ParsedDependency[] = [];

  for (const file of manifests) {
    const parser = parserForPath(file.path);
    if (!parser) continue;

    try {
      const content = await ctx.readFile(file);
      dependencies.push(...parser.parse(content, file.path));
    } catch (error) {
      ctx.logger.warn('Failed to parse dependency manifest', {
        path: file.path,
        error: String(error),
      });
    }
  }

  const resolved = preferLockfiles(dependencies);
  ctx.logger.debug('Dependency inventory built', {
    manifests: manifests.length,
    raw: dependencies.length,
    resolved: resolved.length,
  });

  return resolved;
}

export function getDependencyInventory(ctx: ScanContext): Promise<ParsedDependency[]> {
  let pending = cache.get(ctx);
  if (!pending) {
    pending = build(ctx);
    cache.set(ctx, pending);
  }
  return pending;
}
