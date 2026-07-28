import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { errors } from '@sentinel/core';

const execFileAsync = promisify(execFile);

/**
 * The smallest environment a scanner can work in.
 *
 * Child processes inherit `process.env` by default, which would hand every
 * external scanner our database URL, API keys and GitHub token. Passing an
 * explicit allowlist instead means a compromised or merely chatty third-party
 * binary has nothing to leak.
 *
 * Typed as a partial record and cast: Next.js augments `ProcessEnv` to require
 * `NODE_ENV`, which is exactly the kind of variable we are excluding on purpose.
 */
export function minimalEnv(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  return {
    PATH: process.env['PATH'] ?? '',
    HOME: process.env['HOME'] ?? '',
    LANG: process.env['LANG'] ?? 'en_US.UTF-8',
    ...extra,
  } as unknown as NodeJS.ProcessEnv;
}

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export interface ExecOptions {
  cwd?: string;
  timeoutMs?: number;
  /** Bytes of stdout to accept before killing the child. */
  maxBuffer?: number;
  env?: NodeJS.ProcessEnv;
  signal?: AbortSignal;
  /** Exit codes that are expected and should not throw (scanners use 1 for "findings found"). */
  okExitCodes?: number[];
}

/**
 * Run an external binary.
 *
 * Always `execFile`, never `exec` — no shell is spawned, so repository names,
 * refs and file paths cannot be turned into command injection. Arguments are
 * passed as an array and never interpolated into a string.
 */
export async function run(
  command: string,
  args: readonly string[],
  options: ExecOptions = {},
): Promise<ExecResult> {
  const okCodes = new Set(options.okExitCodes ?? [0]);

  try {
    const { stdout, stderr } = await execFileAsync(command, args as string[], {
      cwd: options.cwd,
      timeout: options.timeoutMs ?? 120_000,
      maxBuffer: options.maxBuffer ?? 64 * 1024 * 1024,
      // A minimal environment: scanners have no business reading our secrets.
      env: options.env ?? minimalEnv(),
      signal: options.signal,
      windowsHide: true,
    });
    return { stdout, stderr, exitCode: 0 };
  } catch (error) {
    const err = error as NodeJS.ErrnoException & {
      stdout?: string;
      stderr?: string;
      code?: number | string;
      killed?: boolean;
    };

    if (err.code === 'ENOENT') {
      // The reason belongs in the message, not only in `cause`: this surfaces
      // in the scanner-coverage table, where "scanner failed" with no
      // explanation is useless to whoever has to fix it.
      throw errors.scannerFailure(
        `${command} is not installed or not on PATH`,
        new Error(`spawn ${command} ENOENT`),
      );
    }
    if (err.killed || err.code === 'ETIMEDOUT') {
      throw errors.timeout(`${command} execution`, options.timeoutMs ?? 120_000);
    }

    const exitCode = typeof err.code === 'number' ? err.code : 1;
    if (okCodes.has(exitCode)) {
      return { stdout: err.stdout ?? '', stderr: err.stderr ?? '', exitCode };
    }

    throw errors.scannerFailure(
      command,
      new Error(
        `${command} exited with code ${exitCode}: ${(err.stderr ?? err.message).slice(0, 500)}`,
      ),
    );
  }
}

const availabilityCache = new Map<string, { version?: string } | null>();

/**
 * Probe whether a binary exists, caching the answer for the process lifetime.
 * Scanners call this on every scan; shelling out repeatedly for a stable fact
 * is pure latency.
 */
export async function probeBinary(
  command: string,
  versionArgs: readonly string[] = ['--version'],
): Promise<{ available: boolean; version?: string }> {
  if (availabilityCache.has(command)) {
    const cached = availabilityCache.get(command);
    return cached ? { available: true, ...cached } : { available: false };
  }

  try {
    const result = await run(command, versionArgs, { timeoutMs: 10_000, okExitCodes: [0, 1] });
    const version = (result.stdout || result.stderr).trim().split('\n')[0]?.trim();
    availabilityCache.set(command, version ? { version } : {});
    return version ? { available: true, version } : { available: true };
  } catch {
    availabilityCache.set(command, null);
    return { available: false };
  }
}

/** Test seam — availability is cached for the process lifetime. */
export function clearBinaryCache(): void {
  availabilityCache.clear();
}

/** Parse JSON from a tool, returning undefined rather than throwing on garbage. */
export function tryParseJson<T>(text: string): T | undefined {
  const trimmed = text.trim();
  if (!trimmed) return undefined;
  try {
    return JSON.parse(trimmed) as T;
  } catch {
    return undefined;
  }
}

/** Some tools emit newline-delimited JSON; tolerate both shapes. */
export function parseJsonLines<T>(text: string): T[] {
  const out: T[] = [];
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      out.push(JSON.parse(trimmed) as T);
    } catch {
      // A single malformed line should not discard the whole report.
    }
  }
  return out;
}
