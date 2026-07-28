import { isAbsolute, relative, resolve, sep } from 'node:path';
import { errors } from './errors.js';
import type { Language } from './types.js';

/**
 * Path containment check used everywhere untrusted paths are joined — archive
 * extraction, repository walking, report output. This is the control that stops
 * "zip slip" and `../../etc/passwd` traversal, so it is deliberately strict:
 * it resolves both sides and rejects anything that escapes, including via
 * symlink-shaped `..` segments.
 */
export function isInside(parent: string, child: string): boolean {
  const parentResolved = resolve(parent);
  const childResolved = resolve(child);
  if (parentResolved === childResolved) return true;
  const rel = relative(parentResolved, childResolved);
  return rel !== '' && !rel.startsWith('..') && !isAbsolute(rel);
}

/** Resolve `candidate` under `root`, throwing if it escapes. */
export function safeResolve(root: string, candidate: string): string {
  const target = resolve(root, candidate);
  if (!isInside(root, target)) {
    throw errors.validation(`Path "${candidate}" escapes the allowed root directory`);
  }
  return target;
}

/** Reject archive entry names that are absolute, traversing, or device paths. */
export function isSafeArchiveEntry(name: string): boolean {
  if (!name || name.length > 4096) return false;
  const normalized = name.replace(/\\/g, '/');
  if (normalized.startsWith('/')) return false;
  if (/^[a-zA-Z]:/.test(normalized)) return false;
  if (normalized.split('/').some((segment) => segment === '..')) return false;
  // Null bytes truncate paths in some syscalls — never allow them through.
  if (normalized.includes('\0')) return false;
  return true;
}

export function toPosix(path: string): string {
  return path.split(sep).join('/');
}

/* ------------------------------------------------------------------ */
/* Minimal glob matching                                               */
/* ------------------------------------------------------------------ */

/**
 * Supports the subset of glob syntax scanners actually need: `*`, `**`, `?`,
 * and brace alternation. Written by hand rather than pulled from npm because
 * ignore-pattern handling is security-relevant and a tiny, auditable
 * implementation beats a transitive dependency tree here.
 */
export function globToRegExp(pattern: string): RegExp {
  let out = '';
  let i = 0;
  const normalized = pattern.replace(/\\/g, '/');

  while (i < normalized.length) {
    const char = normalized[i]!;

    if (char === '*') {
      if (normalized[i + 1] === '*') {
        // `**/` matches zero or more path segments.
        if (normalized[i + 2] === '/') {
          out += '(?:.*/)?';
          i += 3;
        } else {
          out += '.*';
          i += 2;
        }
      } else {
        out += '[^/]*';
        i += 1;
      }
      continue;
    }

    if (char === '?') {
      out += '[^/]';
      i += 1;
      continue;
    }

    if (char === '{') {
      const close = normalized.indexOf('}', i);
      if (close !== -1) {
        const options = normalized.slice(i + 1, close).split(',');
        out += `(?:${options.map((o) => o.replace(/[.+^${}()|[\]\\]/g, '\\$&')).join('|')})`;
        i = close + 1;
        continue;
      }
    }

    out += char.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    i += 1;
  }

  return new RegExp(`^${out}$`);
}

const globCache = new Map<string, RegExp>();

export function matchesGlob(path: string, pattern: string): boolean {
  let regex = globCache.get(pattern);
  if (!regex) {
    regex = globToRegExp(pattern);
    globCache.set(pattern, regex);
  }
  const normalized = toPosix(path).replace(/^\.\//, '');
  if (regex.test(normalized)) return true;
  // A bare directory pattern like `node_modules` should match everything under it.
  if (!pattern.includes('/') && !pattern.includes('*')) {
    return normalized.split('/').includes(pattern);
  }
  return false;
}

export function matchesAnyGlob(path: string, patterns: readonly string[]): boolean {
  return patterns.some((pattern) => matchesGlob(path, pattern));
}

/** Directories and files that are never worth analyzing. */
export const DEFAULT_EXCLUDES: readonly string[] = [
  '**/node_modules/**',
  '**/.git/**',
  '**/dist/**',
  '**/build/**',
  '**/out/**',
  '**/.next/**',
  '**/.nuxt/**',
  '**/coverage/**',
  '**/vendor/**',
  '**/target/**',
  '**/bin/**',
  '**/obj/**',
  '**/.venv/**',
  '**/venv/**',
  '**/__pycache__/**',
  '**/.pytest_cache/**',
  '**/.mypy_cache/**',
  '**/.gradle/**',
  '**/.idea/**',
  '**/.vscode/**',
  '**/*.min.js',
  '**/*.min.css',
  '**/*.map',
  '**/*.lock',
  '**/.DS_Store',
  '**/*.woff',
  '**/*.woff2',
  '**/*.ttf',
  '**/*.eot',
  '**/*.png',
  '**/*.jpg',
  '**/*.jpeg',
  '**/*.gif',
  '**/*.webp',
  '**/*.avif',
  '**/*.ico',
  '**/*.svg',
  '**/*.pdf',
  '**/*.zip',
  '**/*.gz',
  '**/*.tar',
  '**/*.mp4',
  '**/*.mp3',
  '**/*.wasm',
];

/* ------------------------------------------------------------------ */
/* Language detection                                                  */
/* ------------------------------------------------------------------ */

const EXTENSION_LANGUAGE: Record<string, Language> = {
  ts: 'typescript',
  tsx: 'typescript',
  mts: 'typescript',
  cts: 'typescript',
  js: 'javascript',
  jsx: 'javascript',
  mjs: 'javascript',
  cjs: 'javascript',
  py: 'python',
  pyi: 'python',
  java: 'java',
  go: 'go',
  rs: 'rust',
  cs: 'csharp',
  php: 'php',
  rb: 'ruby',
};

export function extensionOf(path: string): string {
  const base = path.slice(path.lastIndexOf('/') + 1);
  const dot = base.lastIndexOf('.');
  return dot <= 0 ? '' : base.slice(dot + 1).toLowerCase();
}

export function languageOf(path: string): Language {
  return EXTENSION_LANGUAGE[extensionOf(path)] ?? 'other';
}

/** File types worth reading as text during analysis. */
const ANALYZABLE_EXTENSIONS = new Set([
  ...Object.keys(EXTENSION_LANGUAGE),
  'json',
  'yaml',
  'yml',
  'toml',
  'xml',
  'ini',
  'cfg',
  'conf',
  'env',
  'properties',
  'tf',
  'tfvars',
  'hcl',
  'sh',
  'bash',
  'zsh',
  'ps1',
  'sql',
  'graphql',
  'gql',
  'md',
  'mdx',
  'txt',
  'html',
  'htm',
  'vue',
  'svelte',
  'astro',
  'gradle',
  'kt',
  'kts',
  'swift',
  'c',
  'h',
  'cpp',
  'hpp',
  'cc',
  'ex',
  'exs',
  'erl',
  'scala',
  'clj',
  'pl',
  'lua',
  'r',
  'dart',
  'proto',
  'csproj',
  'fsproj',
  'vbproj',
  'sln',
  'razor',
  'cshtml',
  'jinja',
  'j2',
  'tpl',
  'template',
]);

/** Filenames without a useful extension that we still want to analyze. */
const ANALYZABLE_BASENAMES = new Set([
  'dockerfile',
  'containerfile',
  'makefile',
  'jenkinsfile',
  'procfile',
  'gemfile',
  'rakefile',
  'pipfile',
  'go.mod',
  'go.sum',
  'cargo.toml',
  'requirements.txt',
  'package.json',
  'composer.json',
  'pom.xml',
  'build.gradle',
  '.env',
  '.npmrc',
  '.dockerignore',
  '.gitignore',
]);

export function isAnalyzableFile(path: string): boolean {
  const base = toPosix(path).split('/').pop()?.toLowerCase() ?? '';
  if (ANALYZABLE_BASENAMES.has(base)) return true;
  if (base.startsWith('dockerfile')) return true;
  if (base.startsWith('.env')) return true;
  return ANALYZABLE_EXTENSIONS.has(extensionOf(path));
}
