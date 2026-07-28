import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { silentLogger } from '@sentinel/core';
import { isIgnored, loadIgnoreRules, parseIgnoreFile, parseIgnoreLine } from './ignore.js';
import { walkFiles } from './workspace.js';

describe('parseIgnoreLine', () => {
  it('ignores blanks and comments', () => {
    expect(parseIgnoreLine('')).toBeUndefined();
    expect(parseIgnoreLine('   ')).toBeUndefined();
    expect(parseIgnoreLine('# a comment')).toBeUndefined();
  });

  it('makes an unanchored pattern match at any depth', () => {
    expect(parseIgnoreLine('*.generated.ts')).toEqual({
      pattern: '**/*.generated.ts',
      negated: false,
    });
  });

  it('anchors a leading slash to the repository root', () => {
    expect(parseIgnoreLine('/build')).toEqual({ pattern: 'build/**', negated: false });
  });

  it('expands a trailing slash to the whole subtree', () => {
    expect(parseIgnoreLine('fixtures/')).toEqual({ pattern: '**/fixtures/**', negated: false });
  });

  it('treats a bare name as a directory subtree', () => {
    // `fixtures` should behave like `fixtures/**`, matching what users expect
    // from .gitignore rather than only the directory entry itself.
    expect(parseIgnoreLine('fixtures')).toEqual({ pattern: '**/fixtures/**', negated: false });
  });

  it('records negation', () => {
    expect(parseIgnoreLine('!fixtures/keep.ts')).toEqual({
      pattern: '**/fixtures/keep.ts',
      negated: true,
    });
  });
});

describe('parseIgnoreFile', () => {
  it('separates exclusions from negations', () => {
    const rules = parseIgnoreFile(
      ['# Test data', 'fixtures/', '*.snap', '', '!fixtures/real-code.ts'].join('\n'),
    );

    expect(rules.exclude).toEqual(['**/fixtures/**', '**/*.snap']);
    expect(rules.include).toEqual(['**/fixtures/real-code.ts']);
  });
});

describe('isIgnored', () => {
  const rules = parseIgnoreFile(['fixtures/', '*.example.ts', '!fixtures/real-code.ts'].join('\n'));

  it('excludes matching paths', () => {
    expect(isIgnored('fixtures/vulnerable-app/.env', rules)).toBe(true);
    expect(isIgnored('src/config.example.ts', rules)).toBe(true);
  });

  it('leaves everything else alone', () => {
    expect(isIgnored('src/index.ts', rules)).toBe(false);
  });

  it('lets a negation re-include a specific path', () => {
    expect(isIgnored('fixtures/real-code.ts', rules)).toBe(false);
  });

  it('is a no-op with no rules', () => {
    expect(isIgnored('anything', { exclude: [], include: [] })).toBe(false);
  });
});

describe('walker integration', () => {
  let root: string;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'sentinel-ignore-'));
    await mkdir(join(root, 'src'), { recursive: true });
    await mkdir(join(root, 'fixtures', 'nested'), { recursive: true });

    await writeFile(join(root, 'src/app.ts'), 'export const a = 1;');
    await writeFile(join(root, 'fixtures/bad.ts'), 'eval(userInput);');
    await writeFile(join(root, 'fixtures/nested/worse.ts'), 'eval(userInput);');
    await writeFile(join(root, 'notes.example.ts'), 'const key = "sk-example";');
  });

  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it('walks everything when no ignore file exists', async () => {
    const { files } = await walkFiles(root, { maxFiles: 100, maxFileSizeBytes: 1024 * 1024 });
    expect(files.map((f) => f.path).sort()).toEqual([
      'fixtures/bad.ts',
      'fixtures/nested/worse.ts',
      'notes.example.ts',
      'src/app.ts',
    ]);
  });

  it('applies .sentinelignore, including nested paths', async () => {
    await writeFile(join(root, '.sentinelignore'), 'fixtures/\n*.example.ts\n');
    const ignoreRules = await loadIgnoreRules(root, silentLogger);

    const { files } = await walkFiles(root, {
      maxFiles: 100,
      maxFileSizeBytes: 1024 * 1024,
      ignoreRules,
    });

    expect(files.map((f) => f.path)).toEqual(['src/app.ts']);
  });

  it('honours negations', async () => {
    await writeFile(join(root, '.sentinelignore'), 'fixtures/\n!fixtures/bad.ts\n');
    const ignoreRules = await loadIgnoreRules(root, silentLogger);

    const { files } = await walkFiles(root, {
      maxFiles: 100,
      maxFileSizeBytes: 1024 * 1024,
      ignoreRules,
    });

    const paths = files.map((f) => f.path).sort();
    expect(paths).toContain('fixtures/bad.ts');
    expect(paths).not.toContain('fixtures/nested/worse.ts');
  });

  it('returns empty rules when the file is absent', async () => {
    expect(await loadIgnoreRules(root)).toEqual({ exclude: [], include: [] });
  });
});
