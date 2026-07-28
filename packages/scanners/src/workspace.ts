import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import {
  DEFAULT_EXCLUDES,
  errors,
  isAnalyzableFile,
  languageOf,
  matchesAnyGlob,
  toPosix,
  type LanguageBreakdown,
  type Logger,
  type RepositoryInfo,
  type ScanTarget,
} from '@sentinel/core';
import { minimalEnv, run } from './exec.js';
import { detectSingleRoot, extractZip, readZipEntries } from './zip.js';
import { canPruneDirectory, isIgnored, loadIgnoreRules, type IgnoreRules } from './ignore.js';
import type { FileEntry } from './types.js';

export interface Workspace {
  /** Absolute path to the analyzable repository root. */
  root: string;
  repository: RepositoryInfo;
  files: FileEntry[];
  /** Removes any temporary directory this workspace created. */
  cleanup(): Promise<void>;
}

export interface MaterializeOptions {
  logger: Logger;
  maxFiles: number;
  maxFileSizeBytes: number;
  exclude?: string[];
  include?: string[];
  /** Restrict `local` targets to paths under these roots. Empty allows any. */
  allowedLocalRoots?: string[];
  signal?: AbortSignal;
}

/* ------------------------------------------------------------------ */
/* File walking                                                        */
/* ------------------------------------------------------------------ */

/** Directories skipped without descending — the single biggest walk speedup. */
const HARD_SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  '.next',
  '.nuxt',
  '.svelte-kit',
  'dist',
  'build',
  'out',
  'coverage',
  'target',
  'vendor',
  '__pycache__',
  '.venv',
  'venv',
  '.pytest_cache',
  '.mypy_cache',
  '.gradle',
  '.turbo',
  '.cache',
  '.terraform',
]);

async function digestFile(absolutePath: string, size: number): Promise<string> {
  // Hashing every byte of a large repo is wasteful; size + head is enough to
  // detect change for incremental caching purposes.
  const handle = await readFile(absolutePath).catch(() => Buffer.alloc(0));
  return createHash('sha256')
    .update(String(size))
    .update(handle.subarray(0, 64 * 1024))
    .digest('hex')
    .slice(0, 16);
}

export async function walkFiles(
  root: string,
  options: {
    maxFiles: number;
    maxFileSizeBytes: number;
    exclude?: string[];
    include?: string[];
    /** Parsed `.sentinelignore` rules, applied on top of `exclude`. */
    ignoreRules?: IgnoreRules;
    logger?: Logger;
    signal?: AbortSignal;
  },
): Promise<{ files: FileEntry[]; truncated: boolean; totalBytes: number }> {
  const exclude = [...DEFAULT_EXCLUDES, ...(options.exclude ?? [])];
  const ignoreRules = options.ignoreRules ?? { exclude: [], include: [] };
  const include = options.include ?? [];
  const files: FileEntry[] = [];
  const queue: string[] = [root];
  let truncated = false;
  let totalBytes = 0;

  while (queue.length) {
    if (options.signal?.aborted) throw errors.timeout('Repository walk', 0);

    const dir = queue.pop()!;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch (error) {
      options.logger?.debug('Skipping unreadable directory', { dir, error: String(error) });
      continue;
    }

    for (const entry of entries) {
      const absolutePath = join(dir, entry.name);
      const relPath = toPosix(relative(root, absolutePath));

      // Symlinks are never followed: a link to `/` would walk the whole disk,
      // and a link out of the repo is an exfiltration primitive.
      if (entry.isSymbolicLink()) continue;

      if (entry.isDirectory()) {
        if (HARD_SKIP_DIRS.has(entry.name)) continue;
        if (matchesAnyGlob(`${relPath}/`, exclude)) continue;
        // Pruning an ignored directory avoids walking its whole subtree, but
        // only when no negation could re-include something inside it.
        if (canPruneDirectory(`${relPath}/`, ignoreRules)) continue;
        queue.push(absolutePath);
        continue;
      }

      if (!entry.isFile()) continue;
      if (matchesAnyGlob(relPath, exclude)) continue;
      if (isIgnored(relPath, ignoreRules)) continue;
      if (include.length && !matchesAnyGlob(relPath, include)) continue;
      if (!isAnalyzableFile(relPath)) continue;

      if (files.length >= options.maxFiles) {
        truncated = true;
        continue;
      }

      let size: number;
      try {
        size = (await stat(absolutePath)).size;
      } catch {
        continue;
      }
      totalBytes += size;
      if (size > options.maxFileSizeBytes || size === 0) continue;

      files.push({
        path: relPath,
        absolutePath,
        size,
        language: languageOf(relPath),
        digest: await digestFile(absolutePath, size),
      });
    }
  }

  files.sort((a, b) => a.path.localeCompare(b.path));
  return { files, truncated, totalBytes };
}

/* ------------------------------------------------------------------ */
/* Repository metadata                                                 */
/* ------------------------------------------------------------------ */

export function summarizeLanguages(files: readonly FileEntry[]): LanguageBreakdown[] {
  const byLanguage = new Map<string, { files: number; bytes: number }>();
  let totalBytes = 0;

  for (const file of files) {
    if (file.language === 'other') continue;
    const current = byLanguage.get(file.language) ?? { files: 0, bytes: 0 };
    current.files += 1;
    current.bytes += file.size;
    byLanguage.set(file.language, current);
    totalBytes += file.size;
  }

  return [...byLanguage.entries()]
    .map(([language, stats]) => ({
      language: language as LanguageBreakdown['language'],
      files: stats.files,
      bytes: stats.bytes,
      percent: totalBytes ? Math.round((stats.bytes / totalBytes) * 1000) / 10 : 0,
    }))
    .sort((a, b) => b.bytes - a.bytes);
}

async function countLines(files: readonly FileEntry[]): Promise<number> {
  let total = 0;
  // Sample rather than read every file: exact LOC is not worth the IO on a
  // 25 000-file repository, and the number is only ever shown as context.
  const sample = files.length > 2000 ? files.filter((_, i) => i % 5 === 0) : files;
  for (const file of sample) {
    try {
      const content = await readFile(file.absolutePath, 'utf8');
      total += content.split('\n').length;
    } catch {
      // Unreadable file contributes nothing.
    }
  }
  return sample.length === files.length
    ? total
    : Math.round(total * (files.length / sample.length));
}

async function readGitMetadata(
  root: string,
  logger: Logger,
): Promise<{ commit?: string; ref?: string; url?: string; defaultBranch?: string }> {
  try {
    const [commit, ref, url] = await Promise.all([
      run('git', ['rev-parse', 'HEAD'], { cwd: root, timeoutMs: 5_000 }).catch(() => null),
      run('git', ['rev-parse', '--abbrev-ref', 'HEAD'], { cwd: root, timeoutMs: 5_000 }).catch(
        () => null,
      ),
      run('git', ['config', '--get', 'remote.origin.url'], { cwd: root, timeoutMs: 5_000 }).catch(
        () => null,
      ),
    ]);

    return {
      commit: commit?.stdout.trim() || undefined,
      ref: ref?.stdout.trim() || undefined,
      // Strip embedded credentials before this value is ever stored or shown.
      url: url?.stdout.trim().replace(/\/\/[^@/]+@/, '//') || undefined,
    };
  } catch (error) {
    logger.debug('No git metadata available', { error: String(error) });
    return {};
  }
}

/* ------------------------------------------------------------------ */
/* Target materialization                                              */
/* ------------------------------------------------------------------ */

async function materializeGithub(
  target: Extract<ScanTarget, { type: 'github' }>,
  options: MaterializeOptions,
): Promise<{ root: string; temp: string }> {
  const temp = await mkdtemp(join(tmpdir(), 'sentinel-gh-'));
  // Credentials go in the URL only for the clone call and are never logged;
  // `run` uses execFile so the URL is never exposed to a shell.
  const auth = target.token ? `${encodeURIComponent(target.token)}@` : '';
  const url = `https://${auth}github.com/${target.owner}/${target.repo}.git`;

  const args = ['clone', '--depth', '1', '--single-branch', '--no-tags', '--quiet'];
  if (target.ref) args.push('--branch', target.ref);
  args.push('--', url, temp);

  options.logger.info('Cloning repository', {
    owner: target.owner,
    repo: target.repo,
    ref: target.ref ?? 'default',
  });

  try {
    await run('git', args, {
      timeoutMs: 300_000,
      signal: options.signal,
      env: minimalEnv({
        // Never let git stop for an interactive credential prompt on a server.
        GIT_TERMINAL_PROMPT: '0',
        GIT_ASKPASS: 'echo',
      }),
    });
  } catch {
    await rm(temp, { recursive: true, force: true });
    throw errors.unsupportedTarget(
      `Unable to clone ${target.owner}/${target.repo}. Check the repository exists, the ref is valid, and a token is supplied for private repositories.`,
    );
  }

  return { root: temp, temp };
}

async function materializeArchive(
  target: Extract<ScanTarget, { type: 'archive' }>,
  options: MaterializeOptions,
): Promise<{ root: string; temp: string }> {
  const temp = await mkdtemp(join(tmpdir(), 'sentinel-zip-'));
  const buffer = await readFile(target.archivePath);

  const entries = readZipEntries(buffer);
  await extractZip(buffer, temp, { logger: options.logger });

  // GitHub-style archives nest everything under `<repo>-<sha>/`.
  const singleRoot = detectSingleRoot(entries);
  const root = singleRoot ? join(temp, singleRoot) : temp;
  const rootExists = await stat(root)
    .then((s) => s.isDirectory())
    .catch(() => false);

  return { root: rootExists ? root : temp, temp };
}

async function materializeLocal(
  target: Extract<ScanTarget, { type: 'local' }>,
  options: MaterializeOptions,
): Promise<{ root: string; temp?: string }> {
  const root = target.path;
  const info = await stat(root).catch(() => null);
  if (!info?.isDirectory()) {
    throw errors.unsupportedTarget(`Local path "${target.path}" is not a readable directory`);
  }

  // In server mode the caller pins allowed roots so an API client cannot ask
  // Sentinel to scan (and thereby read) arbitrary host directories.
  const allowed = options.allowedLocalRoots ?? [];
  if (allowed.length) {
    const { isInside } = await import('@sentinel/core');
    if (!allowed.some((allowedRoot) => isInside(allowedRoot, root))) {
      throw errors.forbidden('Local path is outside the configured scan roots');
    }
  }

  return { root };
}

export async function materializeWorkspace(
  target: ScanTarget,
  options: MaterializeOptions,
): Promise<Workspace> {
  const started = Date.now();
  let root: string;
  let temp: string | undefined;

  switch (target.type) {
    case 'github': {
      const result = await materializeGithub(target, options);
      root = result.root;
      temp = result.temp;
      break;
    }
    case 'archive': {
      const result = await materializeArchive(target, options);
      root = result.root;
      temp = result.temp;
      break;
    }
    case 'local': {
      const result = await materializeLocal(target, options);
      root = result.root;
      break;
    }
  }

  // Loaded from the materialized root, so it works for cloned and extracted
  // targets, not only local paths.
  const ignoreRules = await loadIgnoreRules(root, options.logger);

  const { files, truncated, totalBytes } = await walkFiles(root, {
    maxFiles: options.maxFiles,
    ignoreRules,
    maxFileSizeBytes: options.maxFileSizeBytes,
    exclude: options.exclude,
    include: options.include,
    logger: options.logger,
    signal: options.signal,
  });

  if (truncated) {
    options.logger.warn('File limit reached; some files were not analyzed', {
      maxFiles: options.maxFiles,
    });
  }

  const git = await readGitMetadata(root, options.logger);
  const name =
    target.type === 'github'
      ? `${target.owner}/${target.repo}`
      : target.type === 'archive'
        ? (target.originalName ?? 'archive').replace(/\.zip$/i, '')
        : (root.split('/').filter(Boolean).pop() ?? 'repository');

  const repository: RepositoryInfo = {
    name,
    url: target.type === 'github' ? `https://github.com/${target.owner}/${target.repo}` : git.url,
    ref: target.type !== 'archive' ? (target.ref ?? git.ref) : undefined,
    commit: git.commit,
    defaultBranch: git.defaultBranch,
    languages: summarizeLanguages(files),
    fileCount: files.length,
    totalBytes,
    linesOfCode: await countLines(files),
  };

  options.logger.info('Workspace ready', {
    files: files.length,
    languages: repository.languages.length,
    durationMs: Date.now() - started,
  });

  return {
    root,
    repository,
    files,
    cleanup: async () => {
      if (temp) await rm(temp, { recursive: true, force: true }).catch(() => {});
    },
  };
}
