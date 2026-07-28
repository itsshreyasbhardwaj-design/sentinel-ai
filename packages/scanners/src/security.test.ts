import { createWriteStream } from 'node:fs';
import { mkdtemp, readdir, readFile, rm, stat, writeFile, mkdir, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { deflateRawSync } from 'node:zlib';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { silentLogger } from '@sentinel/core';
import { DEFAULT_ZIP_LIMITS, extractZip, readZipEntries } from './zip.js';
import { run } from './exec.js';
import { walkFiles } from './workspace.js';
import { runScan } from './engine.js';

/**
 * Security regression suite.
 *
 * These tests guard the controls that protect the *host running Sentinel*, not
 * the code being scanned. Every case here corresponds to a way a malicious
 * repository or upload could attack the scanner itself, so a regression in any
 * of them is a vulnerability in the product rather than a missed detection.
 */

/* ------------------------------------------------------------------ */
/* Minimal ZIP writer, so the archive tests build exactly the bytes    */
/* they need — including deliberately malformed ones.                  */
/* ------------------------------------------------------------------ */

function crc32(buffer: Buffer): number {
  let crc = ~0;
  for (const byte of buffer) {
    crc ^= byte;
    for (let i = 0; i < 8; i += 1) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return ~crc >>> 0;
}

interface ZipInput {
  name: string;
  content: Buffer;
  /** 0 = stored, 8 = deflate. */
  method?: 0 | 8;
}

function buildZip(entries: ZipInput[]): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;

  for (const entry of entries) {
    const method = entry.method ?? 0;
    const data = method === 8 ? deflateRawSync(entry.content) : entry.content;
    const nameBuffer = Buffer.from(entry.name, 'utf8');

    const local = Buffer.alloc(30 + nameBuffer.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(crc32(entry.content), 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(entry.content.length, 22);
    local.writeUInt16LE(nameBuffer.length, 26);
    nameBuffer.copy(local, 30);

    locals.push(local, data);

    const central = Buffer.alloc(46 + nameBuffer.length);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(crc32(entry.content), 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(entry.content.length, 24);
    central.writeUInt16LE(nameBuffer.length, 28);
    central.writeUInt32LE(offset, 42);
    nameBuffer.copy(central, 46);

    centrals.push(central);
    offset += local.length + data.length;
  }

  const centralDirectory = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralDirectory.length, 12);
  eocd.writeUInt32LE(offset, 16);

  return Buffer.concat([...locals, centralDirectory, eocd]);
}

/* ------------------------------------------------------------------ */

let workDir: string;

beforeEach(async () => {
  workDir = await mkdtemp(join(tmpdir(), 'sentinel-sec-test-'));
});

afterEach(async () => {
  await rm(workDir, { recursive: true, force: true });
});

describe('archive extraction: zip slip', () => {
  it('refuses to write outside the destination via ../ traversal', async () => {
    const zip = buildZip([
      { name: '../../../../../../tmp/sentinel-pwned.txt', content: Buffer.from('owned') },
      { name: 'safe.txt', content: Buffer.from('fine') },
    ]);

    const destination = join(workDir, 'out');
    const result = await extractZip(zip, destination, { logger: silentLogger });

    expect(result.filesWritten).toBe(1);
    expect(result.skipped).toHaveLength(1);
    expect(result.skipped[0]?.reason).toMatch(/unsafe path/);

    // The traversal target must not exist anywhere outside the destination.
    await expect(stat('/tmp/sentinel-pwned.txt')).rejects.toThrow();
    expect(await readdir(destination)).toEqual(['safe.txt']);
  });

  it('refuses absolute paths', async () => {
    const zip = buildZip([{ name: '/tmp/sentinel-absolute.txt', content: Buffer.from('x') }]);
    const result = await extractZip(zip, join(workDir, 'out'), { logger: silentLogger });

    expect(result.filesWritten).toBe(0);
    await expect(stat('/tmp/sentinel-absolute.txt')).rejects.toThrow();
  });

  it('refuses Windows-style absolute and backslash traversal paths', async () => {
    const zip = buildZip([
      { name: 'C:\\Windows\\System32\\evil.dll', content: Buffer.from('x') },
      { name: '..\\..\\escape.txt', content: Buffer.from('x') },
    ]);
    const result = await extractZip(zip, join(workDir, 'out'), { logger: silentLogger });
    expect(result.filesWritten).toBe(0);
    expect(result.skipped).toHaveLength(2);
  });

  it('refuses names containing a null byte', async () => {
    const zip = buildZip([{ name: 'safe.txt\u0000.sh', content: Buffer.from('x') }]);
    const result = await extractZip(zip, join(workDir, 'out'), { logger: silentLogger });
    expect(result.filesWritten).toBe(0);
  });

  it('extracts legitimate nested paths', async () => {
    const zip = buildZip([
      { name: 'src/deep/nested/file.ts', content: Buffer.from('export const a = 1;') },
    ]);
    const destination = join(workDir, 'out');
    const result = await extractZip(zip, destination, { logger: silentLogger });

    expect(result.filesWritten).toBe(1);
    expect(await readFile(join(destination, 'src/deep/nested/file.ts'), 'utf8')).toContain(
      'export',
    );
  });
});

describe('archive extraction: zip bombs', () => {
  it('rejects an entry with an implausible compression ratio', () => {
    // 10MB of zeroes compresses to almost nothing — the classic bomb signature.
    const bomb = buildZip([
      { name: 'bomb.txt', content: Buffer.alloc(10 * 1024 * 1024, 0), method: 8 },
    ]);

    expect(() => readZipEntries(bomb)).toThrow(/zip bomb|compression ratio/i);
  });

  it('rejects an archive exceeding the total uncompressed limit', () => {
    const zip = buildZip([{ name: 'big.bin', content: Buffer.alloc(1024) }]);
    expect(() =>
      readZipEntries(zip, { ...DEFAULT_ZIP_LIMITS, maxTotalUncompressedBytes: 100 }),
    ).toThrow(/maximum total uncompressed size/i);
  });

  it('rejects an archive with too many entries', () => {
    const zip = buildZip([
      { name: 'a.txt', content: Buffer.from('a') },
      { name: 'b.txt', content: Buffer.from('b') },
    ]);
    expect(() => readZipEntries(zip, { ...DEFAULT_ZIP_LIMITS, maxEntries: 1 })).toThrow(
      /exceeding the 1 limit/i,
    );
  });

  it('rejects an entry larger than the per-file limit', () => {
    const zip = buildZip([{ name: 'big.bin', content: Buffer.alloc(5000) }]);
    expect(() => readZipEntries(zip, { ...DEFAULT_ZIP_LIMITS, maxEntryBytes: 1000 })).toThrow(
      /per-file size limit/i,
    );
  });

  it('rejects a truncated or non-ZIP payload rather than crashing', () => {
    expect(() => readZipEntries(Buffer.from('not a zip at all'))).toThrow(/not a valid zip/i);
    expect(() => readZipEntries(Buffer.alloc(0))).toThrow(/not a valid zip/i);
  });
});

describe('subprocess execution', () => {
  it('never invokes a shell, so metacharacters are inert', async () => {
    const marker = join(workDir, 'command-injection-marker');

    // If any shell interpreted this argument, the file would be created.
    const result = await run('echo', [`hello; touch ${marker}`], { okExitCodes: [0] });

    expect(result.stdout).toContain('hello;');
    await expect(stat(marker)).rejects.toThrow();
  });

  it('passes arguments literally, including backticks and pipes', async () => {
    const marker = join(workDir, 'backtick-marker');
    const result = await run('echo', ['a`touch ' + marker + '`b', '|', 'c'], { okExitCodes: [0] });

    expect(result.stdout).toContain('|');
    await expect(stat(marker)).rejects.toThrow();
  });

  it('does not leak the parent environment to the child', async () => {
    process.env['SENTINEL_TEST_SECRET'] = 'super-secret-value';
    try {
      const result = await run('env', [], { okExitCodes: [0] });
      // Only PATH, HOME and LANG are forwarded; a scanner must not see our secrets.
      expect(result.stdout).not.toContain('super-secret-value');
      expect(result.stdout).not.toContain('SENTINEL_TEST_SECRET');
    } finally {
      delete process.env['SENTINEL_TEST_SECRET'];
    }
  });

  it('reports a missing binary as a scanner failure rather than hanging', async () => {
    await expect(run('sentinel-definitely-not-a-real-binary', [])).rejects.toThrow(
      /not installed|not on PATH/i,
    );
  });

  it('enforces a timeout', async () => {
    await expect(run('sleep', ['5'], { timeoutMs: 150 })).rejects.toThrow(/timed out/i);
  });
});

describe('repository walking', () => {
  it('does not follow symlinks out of the repository', async () => {
    const repo = join(workDir, 'repo');
    const outside = join(workDir, 'outside');
    await mkdir(repo, { recursive: true });
    await mkdir(outside, { recursive: true });

    await writeFile(join(repo, 'app.ts'), 'const a = 1;');
    await writeFile(join(outside, 'secrets.env'), 'AWS_SECRET=AKIAIOSFODNN7EXAMPLE');
    await symlink(outside, join(repo, 'escape'));
    await symlink(join(outside, 'secrets.env'), join(repo, 'linked.env'));

    const { files } = await walkFiles(repo, { maxFiles: 1000, maxFileSizeBytes: 1024 * 1024 });
    const paths = files.map((f) => f.path);

    expect(paths).toContain('app.ts');
    // Neither the symlinked directory nor the symlinked file may be walked.
    expect(paths.some((p) => p.startsWith('escape'))).toBe(false);
    expect(paths).not.toContain('linked.env');
  });

  it('honours the file-count limit', async () => {
    const repo = join(workDir, 'many');
    await mkdir(repo, { recursive: true });
    for (let i = 0; i < 20; i += 1) {
      await writeFile(join(repo, `file-${i}.ts`), `export const v${i} = ${i};`);
    }

    const { files, truncated } = await walkFiles(repo, {
      maxFiles: 5,
      maxFileSizeBytes: 1024 * 1024,
    });
    expect(files).toHaveLength(5);
    expect(truncated).toBe(true);
  });

  it('skips files above the size limit', async () => {
    const repo = join(workDir, 'sizes');
    await mkdir(repo, { recursive: true });
    await writeFile(join(repo, 'small.ts'), 'a');
    await writeFile(join(repo, 'large.ts'), 'x'.repeat(10_000));

    const { files } = await walkFiles(repo, { maxFiles: 100, maxFileSizeBytes: 1000 });
    expect(files.map((f) => f.path)).toEqual(['small.ts']);
  });

  it('produces only relative paths, never absolute ones', async () => {
    const repo = join(workDir, 'paths');
    await mkdir(join(repo, 'src'), { recursive: true });
    await writeFile(join(repo, 'src/index.ts'), 'export {};');

    const { files } = await walkFiles(repo, { maxFiles: 100, maxFileSizeBytes: 1024 * 1024 });
    for (const file of files) {
      expect(file.path.startsWith('/')).toBe(false);
      expect(file.path).not.toContain(workDir);
    }
  });
});

/** Split so no literal matching a real provider format is committed. */
const SAMPLE_GITHUB_TOKEN = `ghp${'_'}A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8`;

describe('findings never leak host information', () => {
  it('reports repository-relative paths only', async () => {
    const repo = join(workDir, 'leak-check');
    await mkdir(join(repo, 'src'), { recursive: true });
    await writeFile(
      join(repo, 'src/db.js'),
      [
        'const { exec } = require("child_process");',
        'function ping(host) {',
        '  exec(`ping -c 1 ${host}`);',
        '}',
      ].join('\n'),
    );

    const result = await runScan({
      target: { type: 'local', path: repo },
      options: { kinds: ['sast'], allowNetwork: false },
      logger: silentLogger,
    });

    expect(result.findings.length).toBeGreaterThan(0);
    const serialized = JSON.stringify(result.findings);

    // An absolute host path in a finding would leak the server's directory
    // layout into every report and export.
    expect(serialized).not.toContain(workDir);
    expect(serialized).not.toContain(tmpdir());
  });

  it('masks credential values in secret findings', async () => {
    const repo = join(workDir, 'secret-check');
    await mkdir(repo, { recursive: true });
    await writeFile(join(repo, '.env'), `GITHUB_TOKEN=${SAMPLE_GITHUB_TOKEN}\n`);

    const result = await runScan({
      target: { type: 'local', path: repo },
      options: { kinds: ['secrets'], allowNetwork: false },
      logger: silentLogger,
    });

    const secrets = result.findings.filter((f) => f.kind === 'secrets');
    expect(secrets.length).toBeGreaterThan(0);

    // The whole serialized result — snippet, metadata, description — must never
    // contain the live credential.
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain(SAMPLE_GITHUB_TOKEN);
    expect(serialized).toContain('ghp_');
  });
});

describe('scan robustness against hostile input', () => {
  it('survives a file of pathological single-line length', async () => {
    const repo = join(workDir, 'longline');
    await mkdir(repo, { recursive: true });
    // A minified bundle shape: one enormous line. Naive regex engines hang here.
    await writeFile(join(repo, 'bundle.js'), `var a="${'x'.repeat(200_000)}";`);

    const started = Date.now();
    const result = await runScan({
      target: { type: 'local', path: repo },
      options: { kinds: ['sast'], allowNetwork: false },
      logger: silentLogger,
    });

    expect(result.status).toBe('completed');
    expect(Date.now() - started).toBeLessThan(15_000);
  }, 20_000);

  it('survives deeply nested directories', async () => {
    const repo = join(workDir, 'deep');
    const deep = join(repo, ...Array.from({ length: 30 }, (_, i) => `level${i}`));
    await mkdir(deep, { recursive: true });
    await writeFile(join(deep, 'file.ts'), 'export const deep = true;');

    const result = await runScan({
      target: { type: 'local', path: repo },
      options: { kinds: ['sast'], allowNetwork: false },
      logger: silentLogger,
    });
    expect(result.status).toBe('completed');
  });

  it('survives binary and invalid-UTF8 content', async () => {
    const repo = join(workDir, 'binary');
    await mkdir(repo, { recursive: true });
    await writeFile(join(repo, 'data.json'), Buffer.from([0xff, 0xfe, 0x00, 0x01, 0x02, 0xff]));
    await writeFile(join(repo, 'app.ts'), 'export const ok = true;');

    const result = await runScan({
      target: { type: 'local', path: repo },
      options: { allowNetwork: false },
      logger: silentLogger,
    });
    expect(result.status).toBe('completed');
  });

  it('does not scan an empty directory into an error', async () => {
    const repo = join(workDir, 'empty');
    await mkdir(repo, { recursive: true });

    const result = await runScan({
      target: { type: 'local', path: repo },
      options: { allowNetwork: false },
      logger: silentLogger,
    });

    expect(result.status).toBe('completed');
    expect(result.scores.overall).toBeGreaterThanOrEqual(0);
  });
});

describe('local scan root restriction', () => {
  it('refuses a path outside the configured roots', async () => {
    const allowed = join(workDir, 'allowed');
    const forbidden = join(workDir, 'forbidden');
    await mkdir(allowed, { recursive: true });
    await mkdir(forbidden, { recursive: true });
    await writeFile(join(forbidden, 'app.ts'), 'export const a = 1;');

    const result = await runScan({
      target: { type: 'local', path: forbidden },
      logger: silentLogger,
      allowedLocalRoots: [allowed],
    });

    // A hosted deployment pins the roots; anything else must be refused, not
    // silently scanned.
    expect(result.status).toBe('failed');
    expect(result.error).toMatch(/outside the configured scan roots/i);
  });

  it('allows a path inside the configured roots', async () => {
    const allowed = join(workDir, 'allowed2');
    const inside = join(allowed, 'project');
    await mkdir(inside, { recursive: true });
    await writeFile(join(inside, 'app.ts'), 'export const a = 1;');

    const result = await runScan({
      target: { type: 'local', path: inside },
      options: { kinds: ['sast'], allowNetwork: false },
      logger: silentLogger,
      allowedLocalRoots: [allowed],
    });

    expect(result.status).toBe('completed');
  });
});

describe('suppression comments', () => {
  it('honours an inline suppression marker', async () => {
    const repo = join(workDir, 'suppress');
    await mkdir(repo, { recursive: true });
    await writeFile(
      join(repo, 'app.js'),
      [
        'const { exec } = require("child_process");',
        '// sentinel-disable-next-line js-command-injection',
        'exec(`ping -c 1 ${host}`);',
      ].join('\n'),
    );

    const result = await runScan({
      target: { type: 'local', path: repo },
      options: { kinds: ['sast'], allowNetwork: false },
      logger: silentLogger,
    });

    expect(result.findings.filter((f) => f.ruleId === 'js-command-injection')).toHaveLength(0);
  });

  it('still reports rules the marker does not name', async () => {
    const repo = join(workDir, 'suppress-scoped');
    await mkdir(repo, { recursive: true });
    await writeFile(
      join(repo, 'app.js'),
      ['// sentinel-disable-next-line js-xss-dangerous-html', 'eval(userInput);'].join('\n'),
    );

    const result = await runScan({
      target: { type: 'local', path: repo },
      options: { kinds: ['sast'], allowNetwork: false },
      logger: silentLogger,
    });

    expect(result.findings.some((f) => f.ruleId === 'js-code-injection-eval')).toBe(true);
  });
});

/** Keep the import used so the writer helper is not tree-shaken in coverage runs. */
void createWriteStream;
void resolve;
