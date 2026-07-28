import { describe, expect, it } from 'vitest';
import {
  isAnalyzableFile,
  isInside,
  isSafeArchiveEntry,
  languageOf,
  matchesAnyGlob,
  matchesGlob,
  safeResolve,
} from './paths.js';
import { SentinelError } from './errors.js';

describe('path containment', () => {
  it('accepts paths inside the root', () => {
    expect(isInside('/tmp/repo', '/tmp/repo/src/index.ts')).toBe(true);
    expect(isInside('/tmp/repo', '/tmp/repo')).toBe(true);
  });

  it('rejects traversal and sibling escapes', () => {
    expect(isInside('/tmp/repo', '/tmp/repo/../secrets')).toBe(false);
    expect(isInside('/tmp/repo', '/tmp/repository')).toBe(false);
    expect(isInside('/tmp/repo', '/etc/passwd')).toBe(false);
  });

  it('safeResolve throws instead of escaping', () => {
    expect(safeResolve('/tmp/repo', 'src/app.ts')).toBe('/tmp/repo/src/app.ts');
    expect(() => safeResolve('/tmp/repo', '../../etc/passwd')).toThrow(SentinelError);
  });
});

describe('archive entry safety', () => {
  it('accepts ordinary relative entries', () => {
    expect(isSafeArchiveEntry('src/index.ts')).toBe(true);
    expect(isSafeArchiveEntry('README.md')).toBe(true);
  });

  it('rejects zip-slip shapes', () => {
    expect(isSafeArchiveEntry('../../etc/passwd')).toBe(false);
    expect(isSafeArchiveEntry('/etc/passwd')).toBe(false);
    expect(isSafeArchiveEntry('C:\\Windows\\System32')).toBe(false);
    expect(isSafeArchiveEntry('src/../../escape.txt')).toBe(false);
    expect(isSafeArchiveEntry('bad\0name')).toBe(false);
    expect(isSafeArchiveEntry('')).toBe(false);
  });

  it('rejects paths that use backslashes to hide traversal', () => {
    expect(isSafeArchiveEntry('src\\..\\..\\escape')).toBe(false);
  });
});

describe('glob matching', () => {
  it('matches single-segment wildcards', () => {
    expect(matchesGlob('src/index.ts', 'src/*.ts')).toBe(true);
    expect(matchesGlob('src/deep/index.ts', 'src/*.ts')).toBe(false);
  });

  it('matches globstar across segments', () => {
    expect(matchesGlob('a/b/c/node_modules/x/y.js', '**/node_modules/**')).toBe(true);
    expect(matchesGlob('node_modules/x.js', '**/node_modules/**')).toBe(true);
    expect(matchesGlob('src/app.min.js', '**/*.min.js')).toBe(true);
  });

  it('supports brace alternation', () => {
    expect(matchesGlob('src/app.tsx', '**/*.{ts,tsx}')).toBe(true);
    expect(matchesGlob('src/app.py', '**/*.{ts,tsx}')).toBe(false);
  });

  it('treats a bare directory name as a path segment match', () => {
    expect(matchesGlob('deep/vendor/lib.js', 'vendor')).toBe(true);
    expect(matchesGlob('deep/vendorly/lib.js', 'vendor')).toBe(false);
  });

  it('matchesAnyGlob short-circuits over a list', () => {
    expect(matchesAnyGlob('dist/main.js', ['**/src/**', '**/dist/**'])).toBe(true);
    expect(matchesAnyGlob('lib/main.js', ['**/src/**', '**/dist/**'])).toBe(false);
  });
});

describe('language detection', () => {
  it('maps extensions to languages', () => {
    expect(languageOf('src/app.tsx')).toBe('typescript');
    expect(languageOf('main.go')).toBe('go');
    expect(languageOf('Program.cs')).toBe('csharp');
    expect(languageOf('index.php')).toBe('php');
    expect(languageOf('notes.txt')).toBe('other');
  });

  it('recognizes extensionless files worth analyzing', () => {
    expect(isAnalyzableFile('Dockerfile')).toBe(true);
    expect(isAnalyzableFile('deploy/Dockerfile.prod')).toBe(true);
    expect(isAnalyzableFile('.env.production')).toBe(true);
    expect(isAnalyzableFile('logo.png')).toBe(false);
  });
});
