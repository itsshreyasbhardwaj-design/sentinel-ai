import type { ComponentRef } from '@sentinel/core';

/**
 * Dependency manifest parsing.
 *
 * Lockfiles are preferred over manifests wherever both exist: a manifest says
 * `^4.17.0`, a lockfile says exactly what is installed, and only the second one
 * can be matched against an advisory range with any confidence.
 */

export interface ParsedDependency extends ComponentRef {
  name: string;
  version: string;
  ecosystem: string;
  scope: 'direct' | 'transitive';
  dependencyType: 'runtime' | 'development' | 'optional' | 'peer';
  path: string;
}

export interface ManifestParser {
  ecosystem: string;
  /** Filenames this parser handles, most authoritative first. */
  filenames: string[];
  parse(content: string, path: string): ParsedDependency[];
}

function purl(ecosystem: string, name: string, version: string): string {
  const type = ecosystem.toLowerCase();
  // Scoped npm names carry a `/` that must survive, but the rest is encoded.
  const encodedName = name
    .split('/')
    .map((part) => encodeURIComponent(part))
    .join('/');
  return `pkg:${type}/${encodedName}@${encodeURIComponent(version)}`;
}

function makeDependency(
  ecosystem: string,
  name: string,
  version: string,
  path: string,
  scope: ParsedDependency['scope'],
  dependencyType: ParsedDependency['dependencyType'],
  licenses?: string[],
): ParsedDependency {
  const cleanVersion = normalizeVersion(version);
  return {
    name,
    version: cleanVersion,
    ecosystem,
    purl: purl(ecosystem, name, cleanVersion),
    scope,
    dependencyType,
    path,
    ...(licenses?.length ? { licenses } : {}),
  };
}

/** Strip range operators so the result can be compared against advisory ranges. */
export function normalizeVersion(version: string): string {
  return version
    .trim()
    .replace(/^[\^~>=<v\s]+/, '')
    .replace(/\s.*$/, '')
    .replace(/^([0-9.]+).*$/, '$1')
    .trim();
}

/* ------------------------------------------------------------------ */
/* npm                                                                 */
/* ------------------------------------------------------------------ */

interface PackageJson {
  name?: string;
  version?: string;
  license?: string | { type?: string };
  licenses?: ({ type?: string } | string)[];
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

export const npmManifest: ManifestParser = {
  ecosystem: 'npm',
  filenames: ['package.json'],
  parse(content, path) {
    const pkg = safeJson<PackageJson>(content);
    if (!pkg) return [];

    const out: ParsedDependency[] = [];
    const groups: [Record<string, string> | undefined, ParsedDependency['dependencyType']][] = [
      [pkg.dependencies, 'runtime'],
      [pkg.devDependencies, 'development'],
      [pkg.optionalDependencies, 'optional'],
      [pkg.peerDependencies, 'peer'],
    ];

    for (const [group, dependencyType] of groups) {
      for (const [name, range] of Object.entries(group ?? {})) {
        // Workspace and file protocols point at local code, not a registry package.
        if (/^(?:workspace|file|link|portal):/.test(range)) continue;
        out.push(makeDependency('npm', name, range, path, 'direct', dependencyType));
      }
    }
    return out;
  },
};

interface PackageLock {
  lockfileVersion?: number;
  packages?: Record<
    string,
    {
      version?: string;
      dev?: boolean;
      optional?: boolean;
      peer?: boolean;
      license?: string;
      link?: boolean;
    }
  >;
  dependencies?: Record<string, { version?: string; dev?: boolean; requires?: unknown }>;
}

export const npmLock: ManifestParser = {
  ecosystem: 'npm',
  filenames: ['package-lock.json', 'npm-shrinkwrap.json'],
  parse(content, path) {
    const lock = safeJson<PackageLock>(content);
    if (!lock) return [];
    const out: ParsedDependency[] = [];

    // lockfileVersion >= 2 uses the `packages` map keyed by install path.
    for (const [key, entry] of Object.entries(lock.packages ?? {})) {
      if (!key || key === '' || entry.link) continue;
      const name = key.replace(/^.*?node_modules\//, '');
      if (!name || !entry.version) continue;
      out.push(
        makeDependency(
          'npm',
          name,
          entry.version,
          path,
          // A package directly under the root node_modules is a direct dependency.
          key.split('node_modules/').length === 2 ? 'direct' : 'transitive',
          entry.dev ? 'development' : entry.optional ? 'optional' : entry.peer ? 'peer' : 'runtime',
          entry.license ? [entry.license] : undefined,
        ),
      );
    }

    // v1 lockfiles nest under `dependencies`.
    if (!out.length) {
      for (const [name, entry] of Object.entries(lock.dependencies ?? {})) {
        if (!entry.version) continue;
        out.push(
          makeDependency(
            'npm',
            name,
            entry.version,
            path,
            'direct',
            entry.dev ? 'development' : 'runtime',
          ),
        );
      }
    }

    return out;
  },
};

export const pnpmLock: ManifestParser = {
  ecosystem: 'npm',
  filenames: ['pnpm-lock.yaml'],
  parse(content, path) {
    const out: ParsedDependency[] = [];
    const seen = new Set<string>();

    // pnpm keys look like `/lodash@4.17.21` or `/@scope/pkg@1.0.0(peer@2)`.
    const entryPattern = /^\s{2}(?:\/)?((?:@[^/\s]+\/)?[^@\s/][^@\s]*)@([^\s(:]+)/gm;
    let match: RegExpExecArray | null;

    while ((match = entryPattern.exec(content))) {
      const name = match[1]!;
      const version = match[2]!;
      if (!/^\d/.test(version)) continue;
      const key = `${name}@${version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(makeDependency('npm', name, version, path, 'transitive', 'runtime'));
    }

    return out;
  },
};

export const yarnLock: ManifestParser = {
  ecosystem: 'npm',
  filenames: ['yarn.lock'],
  parse(content, path) {
    const out: ParsedDependency[] = [];
    const seen = new Set<string>();
    const blocks = content.split(/\n(?=[^\s#])/);

    for (const block of blocks) {
      const header = block.split('\n')[0] ?? '';
      const versionMatch = /^\s+version:?\s+"?([^"\s]+)"?/m.exec(block);
      if (!versionMatch) continue;

      const nameMatch = /^"?((?:@[^/@\s]+\/)?[^@\s"]+)@/.exec(header.trim());
      if (!nameMatch) continue;

      const name = nameMatch[1]!;
      const version = versionMatch[1]!;
      const key = `${name}@${version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(makeDependency('npm', name, version, path, 'transitive', 'runtime'));
    }

    return out;
  },
};

/* ------------------------------------------------------------------ */
/* Python                                                              */
/* ------------------------------------------------------------------ */

export const requirementsTxt: ManifestParser = {
  ecosystem: 'pypi',
  filenames: [
    'requirements.txt',
    'requirements-dev.txt',
    'requirements_dev.txt',
    'dev-requirements.txt',
  ],
  parse(content, path) {
    const out: ParsedDependency[] = [];
    const isDev = /dev/i.test(path);

    for (const rawLine of content.split('\n')) {
      const line = rawLine.split('#')[0]!.trim();
      if (!line || line.startsWith('-')) continue;

      // `package[extra]==1.2.3 ; python_version < "3.9"`
      const match = /^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(?:([=<>!~]=?)\s*([^\s;,]+))?/.exec(
        line,
      );
      if (!match) continue;
      const name = match[1]!;
      const version = match[3] ?? 'unknown';
      out.push(
        makeDependency('pypi', name, version, path, 'direct', isDev ? 'development' : 'runtime'),
      );
    }
    return out;
  },
};

export const pyprojectToml: ManifestParser = {
  ecosystem: 'pypi',
  filenames: ['pyproject.toml'],
  parse(content, path) {
    const out: ParsedDependency[] = [];

    // PEP 621 `dependencies = ["fastapi>=0.100", ...]`
    const pep621 = /^\s*dependencies\s*=\s*\[([\s\S]*?)\]/m.exec(content);
    if (pep621?.[1]) {
      for (const entry of pep621[1].split(',')) {
        const cleaned = entry.replace(/["'\s]/g, '');
        if (!cleaned) continue;
        const match = /^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?(?:[=<>!~]=?([0-9][^\s,;]*))?/.exec(
          cleaned,
        );
        if (!match) continue;
        out.push(
          makeDependency('pypi', match[1]!, match[2] ?? 'unknown', path, 'direct', 'runtime'),
        );
      }
    }

    // Poetry `[tool.poetry.dependencies]`
    const poetrySection = /\[tool\.poetry\.dependencies\]([\s\S]*?)(?:\n\[|$)/.exec(content);
    if (poetrySection?.[1]) {
      for (const line of poetrySection[1].split('\n')) {
        const match = /^\s*([A-Za-z0-9._-]+)\s*=\s*["']?\^?~?([0-9][^\s"',}]*)/.exec(line);
        if (!match || match[1]?.toLowerCase() === 'python') continue;
        out.push(makeDependency('pypi', match[1]!, match[2]!, path, 'direct', 'runtime'));
      }
    }

    return out;
  },
};

export const pipfileLock: ManifestParser = {
  ecosystem: 'pypi',
  filenames: ['Pipfile.lock'],
  parse(content, path) {
    const lock = safeJson<Record<string, Record<string, { version?: string }>>>(content);
    if (!lock) return [];
    const out: ParsedDependency[] = [];

    for (const [section, type] of [
      ['default', 'runtime'],
      ['develop', 'development'],
    ] as const) {
      for (const [name, entry] of Object.entries(lock[section] ?? {})) {
        if (!entry.version) continue;
        out.push(makeDependency('pypi', name, entry.version, path, 'direct', type));
      }
    }
    return out;
  },
};

/* ------------------------------------------------------------------ */
/* Go, Rust, Java, PHP, .NET                                           */
/* ------------------------------------------------------------------ */

export const goMod: ManifestParser = {
  ecosystem: 'golang',
  filenames: ['go.mod'],
  parse(content, path) {
    const out: ParsedDependency[] = [];
    let inRequireBlock = false;

    for (const rawLine of content.split('\n')) {
      const line = rawLine.trim();
      if (line.startsWith('require (')) {
        inRequireBlock = true;
        continue;
      }
      if (inRequireBlock && line === ')') {
        inRequireBlock = false;
        continue;
      }

      const single = /^require\s+(\S+)\s+(v\S+)/.exec(line);
      const inBlock = inRequireBlock ? /^(\S+)\s+(v\S+)/.exec(line) : null;
      const match = single ?? inBlock;
      if (!match) continue;

      out.push(
        makeDependency(
          'golang',
          match[1]!,
          match[2]!.replace(/^v/, ''),
          path,
          'direct',
          line.includes('// indirect') ? 'runtime' : 'runtime',
        ),
      );
    }
    return out;
  },
};

export const cargoToml: ManifestParser = {
  ecosystem: 'cargo',
  filenames: ['Cargo.toml'],
  parse(content, path) {
    const out: ParsedDependency[] = [];

    for (const [heading, type] of [
      ['dependencies', 'runtime'],
      ['dev-dependencies', 'development'],
      ['build-dependencies', 'development'],
    ] as const) {
      const section = new RegExp(`\\[${heading}\\]([\\s\\S]*?)(?:\\n\\[|$)`).exec(content);
      if (!section?.[1]) continue;

      for (const line of section[1].split('\n')) {
        // `serde = "1.0"` or `serde = { version = "1.0", features = [...] }`
        const simple = /^\s*([A-Za-z0-9_-]+)\s*=\s*["']([^"']+)["']/.exec(line);
        const table = /^\s*([A-Za-z0-9_-]+)\s*=\s*\{[^}]*version\s*=\s*["']([^"']+)["']/.exec(line);
        const match = simple ?? table;
        if (!match) continue;
        out.push(makeDependency('cargo', match[1]!, match[2]!, path, 'direct', type));
      }
    }
    return out;
  },
};

export const cargoLock: ManifestParser = {
  ecosystem: 'cargo',
  filenames: ['Cargo.lock'],
  parse(content, path) {
    const out: ParsedDependency[] = [];
    const packagePattern = /\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"/g;
    let match: RegExpExecArray | null;
    while ((match = packagePattern.exec(content))) {
      out.push(makeDependency('cargo', match[1]!, match[2]!, path, 'transitive', 'runtime'));
    }
    return out;
  },
};

export const pomXml: ManifestParser = {
  ecosystem: 'maven',
  filenames: ['pom.xml'],
  parse(content, path) {
    const out: ParsedDependency[] = [];
    const dependencyPattern = /<dependency>([\s\S]*?)<\/dependency>/g;
    let match: RegExpExecArray | null;

    while ((match = dependencyPattern.exec(content))) {
      const block = match[1]!;
      const groupId = /<groupId>([^<]+)<\/groupId>/.exec(block)?.[1]?.trim();
      const artifactId = /<artifactId>([^<]+)<\/artifactId>/.exec(block)?.[1]?.trim();
      const version = /<version>([^<]+)<\/version>/.exec(block)?.[1]?.trim();
      const scope = /<scope>([^<]+)<\/scope>/.exec(block)?.[1]?.trim();
      if (!groupId || !artifactId) continue;

      out.push(
        makeDependency(
          'maven',
          `${groupId}:${artifactId}`,
          // Unresolved `${property}` placeholders are honest as "unknown".
          version && !version.startsWith('${') ? version : 'unknown',
          path,
          'direct',
          scope === 'test' ? 'development' : scope === 'provided' ? 'optional' : 'runtime',
        ),
      );
    }
    return out;
  },
};

export const gradleBuild: ManifestParser = {
  ecosystem: 'maven',
  filenames: ['build.gradle', 'build.gradle.kts'],
  parse(content, path) {
    const out: ParsedDependency[] = [];
    const pattern =
      /(implementation|api|compileOnly|runtimeOnly|testImplementation|testCompileOnly)\s*\(?\s*["']([^:"']+):([^:"']+):([^"']+)["']/g;
    let match: RegExpExecArray | null;

    while ((match = pattern.exec(content))) {
      out.push(
        makeDependency(
          'maven',
          `${match[2]}:${match[3]}`,
          match[4]!,
          path,
          'direct',
          match[1]!.startsWith('test') ? 'development' : 'runtime',
        ),
      );
    }
    return out;
  },
};

export const composerJson: ManifestParser = {
  ecosystem: 'composer',
  filenames: ['composer.json'],
  parse(content, path) {
    const pkg = safeJson<{
      require?: Record<string, string>;
      'require-dev'?: Record<string, string>;
    }>(content);
    if (!pkg) return [];
    const out: ParsedDependency[] = [];

    for (const [group, type] of [
      [pkg.require, 'runtime'],
      [pkg['require-dev'], 'development'],
    ] as const) {
      for (const [name, range] of Object.entries(group ?? {})) {
        // `php` and `ext-*` are platform requirements, not packages.
        if (name === 'php' || name.startsWith('ext-') || name.startsWith('lib-')) continue;
        out.push(makeDependency('composer', name, range, path, 'direct', type));
      }
    }
    return out;
  },
};

export const composerLock: ManifestParser = {
  ecosystem: 'composer',
  filenames: ['composer.lock'],
  parse(content, path) {
    const lock = safeJson<{
      packages?: { name: string; version: string; license?: string[] }[];
      'packages-dev'?: { name: string; version: string; license?: string[] }[];
    }>(content);
    if (!lock) return [];

    const out: ParsedDependency[] = [];
    for (const [group, type] of [
      [lock.packages, 'runtime'],
      [lock['packages-dev'], 'development'],
    ] as const) {
      for (const entry of group ?? []) {
        out.push(
          makeDependency(
            'composer',
            entry.name,
            entry.version,
            path,
            'direct',
            type,
            entry.license,
          ),
        );
      }
    }
    return out;
  },
};

export const csproj: ManifestParser = {
  ecosystem: 'nuget',
  filenames: [],
  parse(content, path) {
    const out: ParsedDependency[] = [];
    const pattern = /<PackageReference\s+Include\s*=\s*"([^"]+)"(?:[^>]*Version\s*=\s*"([^"]+)")?/g;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content))) {
      out.push(
        makeDependency('nuget', match[1]!, match[2] ?? 'unknown', path, 'direct', 'runtime'),
      );
    }
    return out;
  },
};

export const gemfileLock: ManifestParser = {
  ecosystem: 'rubygems',
  filenames: ['Gemfile.lock'],
  parse(content, path) {
    const out: ParsedDependency[] = [];
    const pattern = /^\s{4}([a-zA-Z0-9._-]+)\s\(([^)]+)\)/gm;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content))) {
      out.push(makeDependency('rubygems', match[1]!, match[2]!, path, 'transitive', 'runtime'));
    }
    return out;
  },
};

/* ------------------------------------------------------------------ */
/* Registry                                                            */
/* ------------------------------------------------------------------ */

function safeJson<T>(content: string): T | undefined {
  try {
    return JSON.parse(content) as T;
  } catch {
    return undefined;
  }
}

export const MANIFEST_PARSERS: ManifestParser[] = [
  npmLock,
  pnpmLock,
  yarnLock,
  npmManifest,
  pipfileLock,
  requirementsTxt,
  pyprojectToml,
  goMod,
  cargoLock,
  cargoToml,
  pomXml,
  gradleBuild,
  composerLock,
  composerJson,
  gemfileLock,
];

/** Find the parser responsible for a given file, if any. */
export function parserForPath(path: string): ManifestParser | undefined {
  const basename = path.split('/').pop() ?? '';
  if (/\.(?:cs|fs|vb)proj$/i.test(basename)) return csproj;
  if (/^requirements.*\.txt$/i.test(basename)) return requirementsTxt;
  return MANIFEST_PARSERS.find((parser) => parser.filenames.includes(basename));
}

/**
 * Lockfiles supersede manifests for the same ecosystem: keep the exact resolved
 * version and drop the range-only duplicate, otherwise every package is
 * reported twice with different "versions".
 */
export function preferLockfiles(dependencies: readonly ParsedDependency[]): ParsedDependency[] {
  const lockedEcosystems = new Set(
    dependencies
      .filter((d) => /lock|\.lock$/i.test(d.path.split('/').pop() ?? ''))
      .map((d) => d.ecosystem),
  );

  const filtered = dependencies.filter((d) => {
    const basename = d.path.split('/').pop() ?? '';
    const isLock = /lock/i.test(basename);
    return isLock || !lockedEcosystems.has(d.ecosystem);
  });

  // Collapse duplicates, preferring an entry with a concrete version.
  const byKey = new Map<string, ParsedDependency>();
  for (const dependency of filtered) {
    const key = `${dependency.ecosystem}:${dependency.name}`;
    const existing = byKey.get(key);
    if (!existing || (existing.version === 'unknown' && dependency.version !== 'unknown')) {
      byKey.set(key, dependency);
    }
  }

  return [...byKey.values()].sort((a, b) => a.name.localeCompare(b.name));
}
