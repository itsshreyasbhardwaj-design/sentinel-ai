import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import {
  errors,
  newId,
  type Finding,
  type Logger,
  type Project,
  type ScanOptions,
  type ScanResult,
  type ScanTarget,
} from '@sentinel/core';
import { runScan } from '@sentinel/scanners';
import {
  createAnalyst,
  enrichScanResult,
  type ExecutiveSummary,
  type PrioritizedFinding,
} from '@sentinel/ai';
import { cacheKeys, type Platform } from '@sentinel/platform';

/**
 * Scan orchestration for the web application.
 *
 * Sits between the API routes and the engine: creates the project record if
 * needed, enqueues the work, enriches the result with AI analysis, persists it,
 * and invalidates the caches the dashboard reads. Route handlers stay thin
 * because all of that lives here.
 */

export const SCAN_JOB_TYPE = 'scan';

export interface ScanJobInput {
  projectId: string;
  target: ScanTarget;
  options: ScanOptions;
  ownerId: string;
}

/**
 * Register the scan handler with the queue.
 *
 * Called from every route that can enqueue a scan. Registration overwrites by
 * type, so calling it repeatedly is harmless — and it must not be guarded by a
 * module-level flag, because each Next.js route bundle has its own copy of this
 * module while sharing one queue.
 */
export function registerScanHandler(platform: Platform): void {
  platform.queue.register<ScanJobInput, { scanId: string }>(SCAN_JOB_TYPE, async (input, ctx) => {
    const previous = await platform.storage.getLatestScan(input.projectId);

    const result = await runScan({
      target: input.target,
      options: input.options,
      projectId: input.projectId,
      logger: ctx.logger,
      signal: ctx.signal,
      onProgress: ctx.reportProgress,
      ...(previous ? { previousFindings: previous.findings, previousScanId: previous.id } : {}),
      // A hosted deployment must not let an API client point `local` at an
      // arbitrary host path and read the filesystem through scan results.
      ...(platform.env.NODE_ENV === 'production' ? { allowedLocalRoots: [] } : {}),
    });

    const enriched = await enrichAndPersist(result, platform, ctx.logger);
    return { scanId: enriched.id };
  });
}

/**
 * Attach AI analysis, then persist.
 *
 * Enrichment failure is never fatal: a scan result with findings and no
 * explanations is far more useful than a lost scan.
 */
export async function enrichAndPersist(
  result: ScanResult,
  platform: Platform,
  logger: Logger,
): Promise<ScanResult> {
  let finalResult = result;
  let analysis: ScanAnalysis | undefined;

  if (result.status === 'completed') {
    try {
      const analyst = createAnalyst({ logger, env: platform.env });
      const enriched = await enrichScanResult(result, {
        analyst,
        logger,
        maxExplanations: platform.env.AI_MAX_EXPLANATIONS,
        ...(result.target.type === 'local'
          ? { readContext: makeContextReader(result.target.path) }
          : {}),
      });

      finalResult = enriched.result;
      analysis = { summary: enriched.summary, priorities: enriched.priorities };
    } catch (error) {
      logger.error('AI enrichment failed; storing the unenriched scan', { error: String(error) });
    }
  }

  await platform.storage.saveScan(finalResult);

  await platform.cache.deletePrefix(`scan:${result.id}`);
  await platform.cache.deletePrefix(`project:${result.projectId}`);

  // Stored under its own prefix so scan-data invalidation (re-save, triage)
  // never discards it.
  if (analysis) {
    await platform.cache.set(cacheKeys.scanAnalysis(result.id), analysis, 60 * 60 * 24);
  }

  return finalResult;
}

/** Read the source around a finding so explanations can cite real code. */
function makeContextReader(root: string) {
  const cache = new Map<string, Promise<string[]>>();

  return async (finding: Finding): Promise<string | undefined> => {
    const path = finding.location?.path;
    if (!path) return undefined;

    let pending = cache.get(path);
    if (!pending) {
      pending = readFile(resolve(root, path), 'utf8')
        .then((content) => content.split('\n'))
        .catch(() => []);
      cache.set(path, pending);
    }

    const lines = await pending;
    if (!lines.length) return undefined;

    const start = Math.max(0, (finding.location?.startLine ?? 1) - 8);
    return lines.slice(start, start + 20).join('\n');
  };
}

/* ------------------------------------------------------------------ */
/* Projects                                                            */
/* ------------------------------------------------------------------ */

export function slugify(value: string): string {
  return (
    value
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 60) || 'project'
  );
}

export function describeTargetName(target: ScanTarget): string {
  switch (target.type) {
    case 'github':
      return `${target.owner}/${target.repo}`;
    case 'archive':
      return (target.originalName ?? 'archive').replace(/\.zip$/i, '');
    case 'local':
      return target.path.split('/').filter(Boolean).pop() ?? 'local repository';
  }
}

/**
 * Find or create the project a scan belongs to.
 *
 * Scans are always attached to a project so trends and diffs work from the very
 * first scan, without the user having to create anything up front.
 */
export async function resolveProject(
  platform: Platform,
  ownerId: string,
  target: ScanTarget,
  explicitProjectId?: string,
  name?: string,
): Promise<Project> {
  if (explicitProjectId) {
    const existing = await platform.storage.getProject(explicitProjectId);
    if (!existing) throw errors.notFound('Project');
    if (existing.ownerId !== ownerId) throw errors.notFound('Project');
    return existing;
  }

  const displayName = name ?? describeTargetName(target);
  const slug = slugify(displayName);

  const existing = await platform.storage.getProjectBySlug(ownerId, slug);
  if (existing) return existing;

  const now = new Date().toISOString();
  return platform.storage.createProject({
    id: newId('proj'),
    name: displayName,
    slug,
    ownerId,
    target,
    createdAt: now,
    updatedAt: now,
  });
}

/* ------------------------------------------------------------------ */
/* Cached reads                                                        */
/* ------------------------------------------------------------------ */

export interface ScanAnalysis {
  summary?: ExecutiveSummary;
  priorities?: PrioritizedFinding[];
}

export async function getScanAnalysis(platform: Platform, scanId: string): Promise<ScanAnalysis> {
  return (await platform.cache.get<ScanAnalysis>(cacheKeys.scanAnalysis(scanId))) ?? {};
}

/** Load a scan, enforcing ownership through its project. */
export async function loadScanForUser(
  platform: Platform,
  scanId: string,
  userId: string,
): Promise<ScanResult> {
  const cached = await platform.cache.get<ScanResult>(cacheKeys.scan(scanId));
  const scan = cached ?? (await platform.storage.getScan(scanId));
  if (!scan) throw errors.notFound('Scan');

  const project = await platform.storage.getProject(scan.projectId);
  // A missing project means orphaned data; treat it as not found rather than
  // exposing a scan nobody can be shown to own.
  if (!project || project.ownerId !== userId) throw errors.notFound('Scan');

  if (!cached) await platform.cache.set(cacheKeys.scan(scanId), scan, 300);
  return scan;
}
