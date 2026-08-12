import { EventEmitter } from 'node:events';
import { newId, toSentinelError, type Logger, type ScanProgress } from '@sentinel/core';

/**
 * Background job execution.
 *
 * A scan takes anywhere from a second to several minutes, which is longer than
 * a request should be held open. The in-process queue is the default so the
 * product works from `pnpm dev` with nothing else running; Trigger.dev takes
 * over when configured, for deployments that need durability across restarts.
 */

export type JobStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';

export interface Job<T = unknown> {
  id: string;
  type: string;
  /** Who this job belongs to — required so job-status routes can enforce ownership. */
  ownerId: string;
  status: JobStatus;
  createdAt: string;
  startedAt?: string;
  completedAt?: string;
  progress?: ScanProgress;
  result?: T;
  error?: string;
  attempts: number;
}

export interface JobHandlerContext {
  jobId: string;
  logger: Logger;
  signal: AbortSignal;
  reportProgress(progress: ScanProgress): void;
}

export type JobHandler<TInput, TOutput> = (
  input: TInput,
  ctx: JobHandlerContext,
) => Promise<TOutput>;

export interface JobQueue {
  readonly kind: 'in-process' | 'trigger.dev';
  register<TInput, TOutput>(type: string, handler: JobHandler<TInput, TOutput>): void;
  enqueue<TInput>(type: string, input: TInput, ownerId: string): Promise<Job>;
  get(jobId: string): Promise<Job | undefined>;
  cancel(jobId: string): Promise<boolean>;
  /** Async iterator of progress events, used to drive the SSE endpoint. */
  subscribe(jobId: string): AsyncIterable<ScanProgress>;
  shutdown(): Promise<void>;
}

export interface InProcessQueueOptions {
  logger: Logger;
  /** How many jobs run at once. Scans are IO- and CPU-heavy. */
  concurrency?: number;
  /** How long finished jobs stay queryable. */
  retentionMs?: number;
  maxAttempts?: number;
}

/**
 * In-process queue.
 *
 * Deliberately simple and honest about its limits: jobs live in memory, so a
 * restart loses queued work. That is the correct trade for a single-instance
 * open-source deployment, and the interface makes swapping in a durable backend
 * a configuration change.
 */
export class InProcessQueue implements JobQueue {
  readonly kind = 'in-process' as const;

  private readonly handlers = new Map<string, JobHandler<never, unknown>>();
  private readonly jobs = new Map<string, Job>();
  private readonly controllers = new Map<string, AbortController>();
  private readonly events = new EventEmitter();
  private readonly pending: { jobId: string; type: string; input: unknown }[] = [];
  private running = 0;
  private shuttingDown = false;
  private sweeper: NodeJS.Timeout | undefined;

  constructor(private readonly options: InProcessQueueOptions) {
    // Unbounded listeners would leak; one per subscriber plus headroom.
    this.events.setMaxListeners(200);

    const retention = options.retentionMs ?? 60 * 60_000;
    this.sweeper = setInterval(() => this.sweep(retention), 5 * 60_000);
    this.sweeper.unref?.();
  }

  register<TInput, TOutput>(type: string, handler: JobHandler<TInput, TOutput>): void {
    this.handlers.set(type, handler as JobHandler<never, unknown>);
  }

  async enqueue<TInput>(type: string, input: TInput, ownerId: string): Promise<Job> {
    if (this.shuttingDown) throw toSentinelError(new Error('Queue is shutting down'));
    if (!this.handlers.has(type)) {
      throw toSentinelError(new Error(`No handler registered for job type "${type}"`));
    }

    const job: Job = {
      id: newId('job'),
      type,
      ownerId,
      status: 'queued',
      createdAt: new Date().toISOString(),
      attempts: 0,
    };

    this.jobs.set(job.id, job);
    this.pending.push({ jobId: job.id, type, input });
    queueMicrotask(() => void this.drain());
    return job;
  }

  async get(jobId: string): Promise<Job | undefined> {
    return this.jobs.get(jobId);
  }

  async cancel(jobId: string): Promise<boolean> {
    const job = this.jobs.get(jobId);
    if (!job) return false;

    if (job.status === 'queued') {
      const index = this.pending.findIndex((entry) => entry.jobId === jobId);
      if (index >= 0) this.pending.splice(index, 1);
      job.status = 'cancelled';
      job.completedAt = new Date().toISOString();
      this.events.emit(`done:${jobId}`);
      return true;
    }

    if (job.status === 'running') {
      // Cooperative: the handler observes the signal and stops at its next
      // checkpoint. There is no safe way to kill mid-operation.
      this.controllers.get(jobId)?.abort();
      return true;
    }

    return false;
  }

  subscribe(jobId: string): AsyncIterable<ScanProgress> {
    const events = this.events;
    const jobs = this.jobs;

    return {
      async *[Symbol.asyncIterator]() {
        const job = jobs.get(jobId);
        if (!job) return;
        if (job.progress) yield job.progress;
        if (job.status === 'completed' || job.status === 'failed' || job.status === 'cancelled')
          return;

        const queue: ScanProgress[] = [];
        let notify: (() => void) | undefined;
        let finished = false;

        const onProgress = (progress: ScanProgress) => {
          queue.push(progress);
          notify?.();
        };
        const onDone = () => {
          finished = true;
          notify?.();
        };

        events.on(`progress:${jobId}`, onProgress);
        events.once(`done:${jobId}`, onDone);

        try {
          while (!finished || queue.length) {
            if (!queue.length) {
              await new Promise<void>((resolve) => {
                notify = resolve;
              });
              notify = undefined;
              continue;
            }
            yield queue.shift()!;
          }
        } finally {
          // Always detach, or a disconnected client leaks a listener per request.
          events.off(`progress:${jobId}`, onProgress);
          events.off(`done:${jobId}`, onDone);
        }
      },
    };
  }

  private async drain(): Promise<void> {
    const concurrency = this.options.concurrency ?? 2;

    while (this.running < concurrency && this.pending.length && !this.shuttingDown) {
      const next = this.pending.shift()!;
      this.running += 1;
      void this.execute(next.jobId, next.type, next.input).finally(() => {
        this.running -= 1;
        void this.drain();
      });
    }
  }

  private async execute(jobId: string, type: string, input: unknown): Promise<void> {
    const job = this.jobs.get(jobId);
    const handler = this.handlers.get(type);
    if (!job || !handler || job.status === 'cancelled') return;

    const controller = new AbortController();
    this.controllers.set(jobId, controller);

    job.status = 'running';
    job.startedAt = new Date().toISOString();
    job.attempts += 1;

    const logger = this.options.logger.child({ jobId, jobType: type });

    try {
      const result = await handler(input as never, {
        jobId,
        logger,
        signal: controller.signal,
        reportProgress: (progress) => {
          job.progress = progress;
          this.events.emit(`progress:${jobId}`, progress);
        },
      });

      job.status = controller.signal.aborted ? 'cancelled' : 'completed';
      job.result = result;
    } catch (error) {
      const sentinelError = toSentinelError(error);
      const maxAttempts = this.options.maxAttempts ?? 1;

      if (job.attempts < maxAttempts && !controller.signal.aborted) {
        logger.warn('Job failed; retrying', {
          attempt: job.attempts,
          error: sentinelError.message,
        });
        job.status = 'queued';
        this.pending.push({ jobId, type, input });
        this.controllers.delete(jobId);
        return;
      }

      job.status = controller.signal.aborted ? 'cancelled' : 'failed';
      job.error = sentinelError.message;
      logger.error('Job failed', { error: sentinelError.message });
    } finally {
      job.completedAt = new Date().toISOString();
      this.controllers.delete(jobId);
      this.events.emit(`done:${jobId}`);
    }
  }

  /** Drop finished jobs past the retention window so memory stays bounded. */
  private sweep(retentionMs: number): void {
    const cutoff = Date.now() - retentionMs;
    for (const [id, job] of this.jobs) {
      if (job.status === 'queued' || job.status === 'running') continue;
      const finishedAt = new Date(job.completedAt ?? job.createdAt).getTime();
      if (finishedAt < cutoff) this.jobs.delete(id);
    }
  }

  async shutdown(): Promise<void> {
    this.shuttingDown = true;
    if (this.sweeper) clearInterval(this.sweeper);
    for (const controller of this.controllers.values()) controller.abort();

    // Give running handlers a moment to observe the abort signal.
    const deadline = Date.now() + 5_000;
    while (this.running > 0 && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }

    this.events.removeAllListeners();
  }

  /** Exposed for the health endpoint. */
  stats(): { queued: number; running: number; total: number } {
    return { queued: this.pending.length, running: this.running, total: this.jobs.size };
  }
}

export interface CreateQueueOptions {
  logger: Logger;
  triggerSecretKey?: string;
  concurrency?: number;
}

/**
 * Select a queue implementation.
 *
 * Trigger.dev is intentionally *not* auto-selected here: its tasks are defined
 * at build time in `trigger.config.ts`, so enabling it is a deployment decision
 * rather than an environment-variable one. When the key is present we log that
 * the deployment is configured for it and still return the in-process queue, so
 * behaviour is never silently different from what the operator sees.
 */
export function createQueue(options: CreateQueueOptions): JobQueue {
  if (options.triggerSecretKey) {
    options.logger.info(
      'TRIGGER_SECRET_KEY is set. Scans run in-process unless the Trigger.dev task is deployed; see docs/deployment.md.',
    );
  }
  return new InProcessQueue({
    logger: options.logger,
    ...(options.concurrency ? { concurrency: options.concurrency } : {}),
  });
}
