import type {
  Finding,
  HealthScores,
  Project,
  ScanResult,
  ScanStatus,
  ScoreHistoryPoint,
} from '@sentinel/core';
import type { FindingFilter } from '@sentinel/core';

/**
 * Persistence contract.
 *
 * Two implementations ship: SQLite (default, zero configuration, uses Node's
 * built-in driver) and Postgres/Supabase (for deployments that need it). The
 * interface is deliberately narrow so a third implementation is a day of work
 * rather than a refactor.
 */

export interface StoredScan {
  id: string;
  projectId: string;
  status: ScanStatus;
  startedAt: string;
  completedAt?: string;
  durationMs: number;
  scores: HealthScores;
  findingCount: number;
  error?: string;
  /** Full result, rehydrated on demand. */
  result?: ScanResult;
}

export interface Paginated<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface ListScansOptions {
  projectId?: string;
  status?: ScanStatus[];
  limit?: number;
  offset?: number;
}

export interface ListFindingsOptions extends FindingFilter {
  limit?: number;
  offset?: number;
}

export interface Storage {
  readonly kind: 'sqlite' | 'postgres' | 'memory';

  init(): Promise<void>;
  close(): Promise<void>;

  /* Projects */
  createProject(project: Project): Promise<Project>;
  getProject(id: string): Promise<Project | undefined>;
  getProjectBySlug(ownerId: string, slug: string): Promise<Project | undefined>;
  listProjects(ownerId: string): Promise<Project[]>;
  updateProject(id: string, patch: Partial<Project>): Promise<Project | undefined>;
  deleteProject(id: string): Promise<boolean>;

  /* Scans */
  saveScan(result: ScanResult): Promise<void>;
  getScan(id: string): Promise<ScanResult | undefined>;
  listScans(options: ListScansOptions): Promise<Paginated<StoredScan>>;
  /** Most recent completed scan, used to compute the introduced/resolved diff. */
  getLatestScan(projectId: string): Promise<ScanResult | undefined>;
  deleteScan(id: string): Promise<boolean>;

  /* Findings */
  listFindings(scanId: string, options: ListFindingsOptions): Promise<Paginated<Finding>>;
  getFinding(scanId: string, findingId: string): Promise<Finding | undefined>;
  updateFindingStatus(
    scanId: string,
    findingId: string,
    status: Finding['status'],
    note?: string,
  ): Promise<Finding | undefined>;

  /* Trends */
  getScoreHistory(projectId: string, limit?: number): Promise<ScoreHistoryPoint[]>;
}
