import { errors } from './errors.js';

/**
 * Map over items with bounded concurrency, preserving input order.
 *
 * Scanning is IO-heavy; unbounded `Promise.all` over 25 000 files exhausts file
 * descriptors long before it exhausts CPU.
 */
export async function mapLimit<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  if (limit < 1) throw errors.validation('Concurrency limit must be at least 1');
  const results = new Array<R>(items.length);
  let cursor = 0;

  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const index = cursor;
      cursor += 1;
      if (index >= items.length) return;
      results[index] = await fn(items[index]!, index);
    }
  });

  await Promise.all(workers);
  return results;
}

/** Reject with a typed timeout rather than hanging a scan forever. */
export async function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(errors.timeout(label, ms)), ms);
        // Do not keep the event loop alive purely for the timeout.
        timer.unref?.();
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * Run tasks concurrently, converting rejections into a result union so one bad
 * scanner cannot abort the whole scan.
 */
export type Settled<T> = { ok: true; value: T } | { ok: false; error: unknown };

export async function settleLimit<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<Settled<R>[]> {
  return mapLimit(items, limit, async (item, index) => {
    try {
      return { ok: true as const, value: await fn(item, index) };
    } catch (error) {
      return { ok: false as const, error };
    }
  });
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export interface RetryOptions {
  attempts?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
  /** Return false to stop retrying immediately (e.g. on a 4xx). */
  shouldRetry?: (error: unknown, attempt: number) => boolean;
  onRetry?: (error: unknown, attempt: number, delayMs: number) => void;
}

/** Exponential backoff with full jitter, to avoid synchronized retry storms. */
export async function retry<T>(fn: () => Promise<T>, options: RetryOptions = {}): Promise<T> {
  const attempts = options.attempts ?? 3;
  const base = options.baseDelayMs ?? 250;
  const max = options.maxDelayMs ?? 8_000;
  let lastError: unknown;

  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      if (attempt === attempts) break;
      if (options.shouldRetry && !options.shouldRetry(error, attempt)) break;
      const ceiling = Math.min(max, base * 2 ** (attempt - 1));
      const delay = Math.round(Math.random() * ceiling);
      options.onRetry?.(error, attempt, delay);
      await sleep(delay);
    }
  }

  throw lastError;
}
