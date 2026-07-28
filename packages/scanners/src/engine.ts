import { readFile } from 'node:fs/promises';
import {
  DEFAULT_EXCLUDES,
  computeScores,
  dedupeFindings,
  diffFindings,
  newId,
  normalizeFindings,
  sortFindings,
  toSentinelError,
  withTimeout,
  type Finding,
  type Logger,
  type ScanKind,
  type ScanOptions,
  type ScanProgress,
  type ScanResult,
  type ScanTarget,
  type ScannerRun,
  type Sbom,
  type SuppressionRule,
} from '@sentinel/core';
import { materializeWorkspace } from './workspace.js';
import { selectScanners } from './registry.js';
import { generateSbom } from './native/sbom.js';
import type { FileEntry, ScanContext } from './types.js';

/**
 * Scan orchestration.
 *
 * Runs every selected scanner, normalizes and deduplicates their output, scores
 * the result, and produces an SBOM. Individual scanner failures are recorded and
 * survived — a partial result with an honest "this scanner failed" note is far
 * more useful than an exception that discards the work of the other eight.
 */

export interface RunScanOptions {
  target: ScanTarget;
  options?: ScanOptions;
  projectId?: string;
  logger: Logger;
  signal?: AbortSignal;
  /** Emitted as each phase completes, for streaming progress to the UI. */
  onProgress?: (progress: ScanProgress) => void;
  /** Previous scan findings, used to compute the introduced/resolved diff. */
  previousFindings?: readonly Finding[];
  previousScanId?: string;
  suppressions?: SuppressionRule[];
  /** Restrict `local` targets to these roots (server deployments). */
  allowedLocalRoots?: string[];
}

const DEFAULTS = {
  maxFiles: 25_000,
  maxFileSizeBytes: 2 * 1024 * 1024,
  concurrency: 8,
  allowNetwork: false,
  timeoutMs: 15 * 60_000,
} as const;

/** Cache file contents for the scan duration — eight scanners read the same files. */
function createFileReader(logger: Logger): (entry: FileEntry) => Promise<string> {
  const cache = new Map<string, Promise<string>>();
  // Bound the cache so a huge repository cannot exhaust memory; source files
  // are small, and eviction just means re-reading from the page cache.
  const MAX_CACHED = 4_000;

  return (entry: FileEntry) => {
    let pending = cache.get(entry.absolutePath);
    if (!pending) {
      pending = readFile(entry.absolutePath, 'utf8').catch((error) => {
        logger.debug('File read failed', { path: entry.path, error: String(error) });
        return '';
      });
      if (cache.size < MAX_CACHED) cache.set(entry.absolutePath, pending);
    }
    return pending;
  };
}

export async function runScan(config: RunScanOptions): Promise<ScanResult> {
  const scanId = newId('scan');
  const startedAt = new Date().toISOString();
  const started = Date.now();
  const logger = config.logger.child({ scanId });

  const options: ScanOptions = {
    exclude: DEFAULT_EXCLUDES as unknown as string[],
    ...config.options,
  };

  const resolved = {
    maxFiles: options.maxFiles ?? DEFAULTS.maxFiles,
    maxFileSizeBytes: options.maxFileSizeBytes ?? DEFAULTS.maxFileSizeBytes,
    concurrency: options.concurrency ?? DEFAULTS.concurrency,
    allowNetwork: options.allowNetwork ?? DEFAULTS.allowNetwork,
  };

  let workspace: Awaited<ReturnType<typeof materializeWorkspace>> | undefined;
  const scannerRuns: ScannerRun[] = [];
  let progressCount = 0;

  const emit = (
    phase: string,
    percent: number,
    message?: string,
    totalScanners = 0,
    findings = 0,
  ) => {
    config.onProgress?.({
      scanId,
      status: 'running',
      percent: Math.min(99, Math.round(percent)),
      phase,
      ...(message ? { message } : {}),
      completedScanners: scannerRuns.map((r) => r.scanner),
      totalScanners,
      findingsSoFar: findings,
      startedAt,
      updatedAt: new Date().toISOString(),
    });
  };

  try {
    /* ---------------- Phase 1: materialize ---------------- */
    emit('preparing', 2, 'Preparing repository');

    workspace = await materializeWorkspace(config.target, {
      logger,
      maxFiles: resolved.maxFiles,
      maxFileSizeBytes: resolved.maxFileSizeBytes,
      ...(options.exclude ? { exclude: options.exclude } : {}),
      ...(options.include ? { include: options.include } : {}),
      ...(config.allowedLocalRoots ? { allowedLocalRoots: config.allowedLocalRoots } : {}),
      ...(config.signal ? { signal: config.signal } : {}),
    });

    emit('preparing', 8, `Analyzing ${workspace.files.length} files`);

    const ctx: ScanContext = {
      scanId,
      root: workspace.root,
      target: config.target,
      options: { ...options, ...resolved },
      files: workspace.files,
      logger,
      ...(config.signal ? { signal: config.signal } : {}),
      readFile: createFileReader(logger),
      onProgress: (message) => emit('scanning', 10 + progressCount, message),
    };

    /* ---------------- Phase 2: select scanners ---------------- */
    const { selected, skipped } = await selectScanners(ctx, {
      ...(options.kinds ? { kinds: options.kinds } : {}),
      ...(options.preferExternalScanners !== undefined
        ? { preferExternal: options.preferExternalScanners }
        : {}),
    });

    for (const entry of skipped) {
      scannerRuns.push({
        scanner: entry.scanner.id,
        kind: entry.scanner.kind,
        scannerKind: entry.scanner.origin,
        status: 'skipped',
        durationMs: 0,
        findingCount: 0,
        reason: entry.reason,
      });
    }

    if (!selected.length) {
      throw toSentinelError(
        new Error('No scanners are available for the requested analysis kinds'),
      );
    }

    /* ---------------- Phase 3: run scanners ---------------- */
    const allFindings: Finding[] = [];
    const perScannerBudget = Math.floor(85 / selected.length);

    // Sequential rather than parallel: scanners are individually concurrent
    // internally, and running eight file-walkers at once thrashes the disk and
    // makes progress reporting meaningless.
    for (const { scanner, availability } of selected) {
      if (config.signal?.aborted) break;

      const scannerStarted = Date.now();
      emit(
        'scanning',
        10 + progressCount,
        `Running ${scanner.name}`,
        selected.length,
        allFindings.length,
      );

      try {
        const raw = await withTimeout(
          scanner.scan(ctx),
          options.timeoutMs ?? DEFAULTS.timeoutMs,
          `${scanner.name} scan`,
        );

        const normalized = normalizeFindings(raw, {
          scanId,
          scanner: scanner.id,
          scannerKind: scanner.origin,
          ...(config.suppressions ? { suppressions: config.suppressions } : {}),
          ...(config.previousFindings
            ? {
                previouslySeen: new Map(
                  config.previousFindings.map((f) => [f.fingerprint, f.firstSeenAt]),
                ),
              }
            : {}),
        });

        allFindings.push(...normalized);
        scannerRuns.push({
          scanner: scanner.id,
          kind: scanner.kind,
          scannerKind: scanner.origin,
          status: 'ok',
          durationMs: Date.now() - scannerStarted,
          findingCount: normalized.length,
          ...(availability.version ? { version: availability.version } : {}),
        });

        logger.info('Scanner completed', {
          scanner: scanner.id,
          findings: normalized.length,
          durationMs: Date.now() - scannerStarted,
        });
      } catch (error) {
        const sentinelError = toSentinelError(error);
        // Record and continue. A failed scanner is a coverage gap to surface,
        // not a reason to throw away every other scanner's results.
        scannerRuns.push({
          scanner: scanner.id,
          kind: scanner.kind,
          scannerKind: scanner.origin,
          status: 'failed',
          durationMs: Date.now() - scannerStarted,
          findingCount: 0,
          reason: sentinelError.message,
        });
        logger.error('Scanner failed', { scanner: scanner.id, error: sentinelError.message });
      }

      progressCount += perScannerBudget;
    }

    /* ---------------- Phase 4: consolidate ---------------- */
    emit('consolidating', 95, 'Consolidating findings');

    const findings = sortFindings(dedupeFindings(allFindings));
    const analyzedKinds = [
      ...new Set(scannerRuns.filter((r) => r.status === 'ok').map((r) => r.kind)),
    ] as ScanKind[];

    const scores = computeScores({ findings, analyzedKinds });

    let sbom: Sbom | undefined;
    if (analyzedKinds.includes('sbom')) {
      try {
        sbom = await generateSbom(ctx, workspace.repository);
      } catch (error) {
        logger.warn('SBOM generation failed', { error: String(error) });
      }
    }

    const diff =
      config.previousFindings && config.previousScanId
        ? (() => {
            const delta = diffFindings(config.previousFindings!, findings);
            return {
              previousScanId: config.previousScanId!,
              introduced: delta.introduced.map((f) => f.id),
              resolved: delta.resolved.map((f) => f.id),
              unchanged: delta.unchanged.length,
              scoreDelta: 0,
            };
          })()
        : undefined;

    const completedAt = new Date().toISOString();

    config.onProgress?.({
      scanId,
      status: 'completed',
      percent: 100,
      phase: 'completed',
      completedScanners: scannerRuns.filter((r) => r.status === 'ok').map((r) => r.scanner),
      totalScanners: selected.length,
      findingsSoFar: findings.length,
      startedAt,
      updatedAt: completedAt,
    });

    logger.info('Scan completed', {
      findings: findings.length,
      score: scores.overall,
      durationMs: Date.now() - started,
    });

    return {
      id: scanId,
      projectId: config.projectId ?? 'default',
      status: 'completed',
      target: config.target,
      options,
      repository: workspace.repository,
      findings,
      scannerRuns,
      scores,
      ...(sbom ? { sbom } : {}),
      startedAt,
      completedAt,
      durationMs: Date.now() - started,
      ...(diff ? { diff } : {}),
    };
  } catch (error) {
    const sentinelError = toSentinelError(error);
    logger.error('Scan failed', { error: sentinelError.message, code: sentinelError.code });

    config.onProgress?.({
      scanId,
      status: 'failed',
      percent: 100,
      phase: 'failed',
      message: sentinelError.message,
      completedScanners: scannerRuns.filter((r) => r.status === 'ok').map((r) => r.scanner),
      totalScanners: scannerRuns.length,
      findingsSoFar: 0,
      startedAt,
      updatedAt: new Date().toISOString(),
    });

    return {
      id: scanId,
      projectId: config.projectId ?? 'default',
      status: 'failed',
      target: config.target,
      options,
      repository: workspace?.repository ?? {
        name: 'unknown',
        languages: [],
        fileCount: 0,
        totalBytes: 0,
        linesOfCode: 0,
      },
      findings: [],
      scannerRuns,
      scores: computeScores({ findings: [], analyzedKinds: [] }),
      startedAt,
      completedAt: new Date().toISOString(),
      durationMs: Date.now() - started,
      error: sentinelError.message,
    };
  } finally {
    // Always clean up the temp clone/extraction, even on failure.
    await workspace?.cleanup();
  }
}

/** CI gate: does this result exceed the configured failure threshold? */
export function shouldFailBuild(result: ScanResult, failOn: ScanOptions['failOn']): boolean {
  if (!failOn) return false;
  const order = ['info', 'low', 'medium', 'high', 'critical'];
  const threshold = order.indexOf(failOn);
  return result.findings.some(
    (finding) => !finding.suppressed && order.indexOf(finding.severity) >= threshold,
  );
}
