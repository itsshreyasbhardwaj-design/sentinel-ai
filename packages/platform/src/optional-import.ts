import { createRequire } from 'node:module';
import { errors } from '@sentinel/core';

/**
 * Load an optional dependency at runtime.
 *
 * The Postgres, Redis and Clerk adapters exist so Sentinel *can* use those
 * services, not so every install has to carry them. A plain
 * `import('postgres')` would make the specifier statically resolvable, which
 * means TypeScript demands the types and bundlers try to include the module —
 * defeating the point. Routing through a variable specifier keeps them
 * genuinely optional.
 *
 * Node built-ins need a different escape hatch again. Bundlers rewrite both
 * `import()` and `require()` calls they can see, so `node:sqlite` — which is
 * newer than the built-in module lists Vite and webpack ship with — gets
 * replaced with an empty stub. `process.getBuiltinModule` exists precisely for
 * this case: it is not a module request, so nothing rewrites it.
 */

const requireFromHere = createRequire(import.meta.url);

/** `process.getBuiltinModule` is Node 22.3+; older runtimes fall back to require. */
function loadBuiltin<T>(specifier: string): T {
  const getBuiltinModule = (
    process as NodeJS.Process & { getBuiltinModule?: (id: string) => unknown }
  ).getBuiltinModule;

  if (typeof getBuiltinModule === 'function') {
    const module = getBuiltinModule(specifier);
    if (module) return module as T;
  }

  return requireFromHere(specifier) as T;
}

export async function optionalImport<T>(specifier: string, purpose: string): Promise<T> {
  try {
    if (specifier.startsWith('node:')) return loadBuiltin<T>(specifier);

    // `@vite-ignore` must come first — Vite only inspects the leading comment.
    return (await import(/* @vite-ignore */ /* webpackIgnore: true */ specifier)) as T;
  } catch (error) {
    const isBuiltin = specifier.startsWith('node:');
    throw errors.storage(
      isBuiltin
        ? `"${specifier}" is required for ${purpose} but is unavailable in this runtime. Node 22.5 or newer is required; this process reports ${process.version}.`
        : `The optional dependency "${specifier}" is required for ${purpose} but is not installed. Run \`pnpm add ${specifier}\`, or remove the configuration that selects it.`,
      error,
    );
  }
}
