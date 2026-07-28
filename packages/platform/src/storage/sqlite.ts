import { mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import {
  errors,
  filterFindings,
  toHistoryPoint,
  type Finding,
  type Logger,
  type Project,
  type ScanResult,
  type ScoreHistoryPoint,
} from '@sentinel/core';
import type {
  ListFindingsOptions,
  ListScansOptions,
  Paginated,
  Storage,
  StoredScan,
} from './types.js';
import { optionalImport } from '../optional-import.js';

/**
 * SQLite storage — the default.
 *
 * Uses `node:sqlite`, built into Node 22.5+, so there is no native module to
 * compile and no service to run. A developer clones the repo, runs one command,
 * and has working persistence. That matters more for an open-source security
 * tool than any scalability argument, and the Postgres adapter is there for
 * deployments that outgrow it.
 */

interface SqliteStatement {
  run(...params: unknown[]): { changes: number | bigint; lastInsertRowid: number | bigint };
  get(...params: unknown[]): unknown;
  all(...params: unknown[]): unknown[];
}

interface SqliteDatabase {
  exec(sql: string): void;
  prepare(sql: string): SqliteStatement;
  close(): void;
}

const SCHEMA = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS projects (
  id           TEXT PRIMARY KEY,
  owner_id     TEXT NOT NULL,
  slug         TEXT NOT NULL,
  name         TEXT NOT NULL,
  description  TEXT,
  target       TEXT NOT NULL,
  options      TEXT,
  last_scan_id TEXT,
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL,
  UNIQUE (owner_id, slug)
);

CREATE TABLE IF NOT EXISTS scans (
  id            TEXT PRIMARY KEY,
  project_id    TEXT NOT NULL,
  status        TEXT NOT NULL,
  started_at    TEXT NOT NULL,
  completed_at  TEXT,
  duration_ms   INTEGER NOT NULL DEFAULT 0,
  overall_score INTEGER NOT NULL DEFAULT 0,
  finding_count INTEGER NOT NULL DEFAULT 0,
  error         TEXT,
  payload       TEXT NOT NULL,
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scans_project_started ON scans(project_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);

-- Findings are denormalized out of the scan payload so filtering and counting
-- are index-backed rather than requiring a full JSON parse per request.
CREATE TABLE IF NOT EXISTS findings (
  id           TEXT NOT NULL,
  scan_id      TEXT NOT NULL,
  project_id   TEXT NOT NULL,
  fingerprint  TEXT NOT NULL,
  rule_id      TEXT NOT NULL,
  severity     TEXT NOT NULL,
  kind         TEXT NOT NULL,
  status       TEXT NOT NULL,
  scanner      TEXT NOT NULL,
  risk_score   INTEGER NOT NULL,
  path         TEXT,
  title        TEXT NOT NULL,
  suppressed   INTEGER NOT NULL DEFAULT 0,
  first_seen   TEXT NOT NULL,
  payload      TEXT NOT NULL,
  PRIMARY KEY (scan_id, id),
  FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(scan_id, severity);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(project_id, fingerprint);

CREATE TABLE IF NOT EXISTS score_history (
  scan_id    TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  timestamp  TEXT NOT NULL,
  payload    TEXT NOT NULL,
  FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_history_project ON score_history(project_id, timestamp DESC);
`;

export interface SqliteStorageOptions {
  path: string;
  logger: Logger;
}

export class SqliteStorage implements Storage {
  readonly kind = 'sqlite' as const;
  private db: SqliteDatabase | undefined;

  constructor(private readonly options: SqliteStorageOptions) {}

  private get database(): SqliteDatabase {
    if (!this.db) throw errors.storage('Storage has not been initialized; call init() first');
    return this.db;
  }

  async init(): Promise<void> {
    if (this.db) return;

    // Loaded through the runtime importer rather than a static specifier:
    // `node:sqlite` is newer than the built-in module list several bundlers
    // ship with, and they try to resolve a package literally named "sqlite"
    // instead of leaving it external.
    const { DatabaseSync } = await optionalImport<{
      DatabaseSync: new (path: string) => SqliteDatabase;
    }>('node:sqlite', 'SQLite storage (requires Node 22.5 or newer)');

    if (this.options.path !== ':memory:') {
      await mkdir(dirname(resolve(this.options.path)), { recursive: true });
    }

    this.db = new DatabaseSync(this.options.path);
    this.db.exec(SCHEMA);
    this.options.logger.info('SQLite storage ready', { path: this.options.path });
  }

  async close(): Promise<void> {
    this.db?.close();
    this.db = undefined;
  }

  /* ---------------------------------------------------------------- */
  /* Projects                                                          */
  /* ---------------------------------------------------------------- */

  async createProject(project: Project): Promise<Project> {
    this.database
      .prepare(
        `INSERT INTO projects (id, owner_id, slug, name, description, target, options, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        project.id,
        project.ownerId,
        project.slug,
        project.name,
        project.description ?? null,
        JSON.stringify(project.target),
        project.defaultOptions ? JSON.stringify(project.defaultOptions) : null,
        project.createdAt,
        project.updatedAt,
      );
    return project;
  }

  async getProject(id: string): Promise<Project | undefined> {
    const row = this.database.prepare('SELECT * FROM projects WHERE id = ?').get(id);
    return row ? rowToProject(row as Record<string, unknown>) : undefined;
  }

  async getProjectBySlug(ownerId: string, slug: string): Promise<Project | undefined> {
    const row = this.database
      .prepare('SELECT * FROM projects WHERE owner_id = ? AND slug = ?')
      .get(ownerId, slug);
    return row ? rowToProject(row as Record<string, unknown>) : undefined;
  }

  async listProjects(ownerId: string): Promise<Project[]> {
    const rows = this.database
      .prepare('SELECT * FROM projects WHERE owner_id = ? ORDER BY updated_at DESC')
      .all(ownerId);
    return rows.map((row) => rowToProject(row as Record<string, unknown>));
  }

  async updateProject(id: string, patch: Partial<Project>): Promise<Project | undefined> {
    const existing = await this.getProject(id);
    if (!existing) return undefined;

    const merged: Project = { ...existing, ...patch, id, updatedAt: new Date().toISOString() };
    this.database
      .prepare(
        `UPDATE projects SET name = ?, description = ?, target = ?, options = ?, last_scan_id = ?, updated_at = ?
         WHERE id = ?`,
      )
      .run(
        merged.name,
        merged.description ?? null,
        JSON.stringify(merged.target),
        merged.defaultOptions ? JSON.stringify(merged.defaultOptions) : null,
        merged.lastScanId ?? null,
        merged.updatedAt,
        id,
      );
    return merged;
  }

  async deleteProject(id: string): Promise<boolean> {
    const result = this.database.prepare('DELETE FROM projects WHERE id = ?').run(id);
    return Number(result.changes) > 0;
  }

  /* ---------------------------------------------------------------- */
  /* Scans                                                             */
  /* ---------------------------------------------------------------- */

  async saveScan(result: ScanResult): Promise<void> {
    const db = this.database;

    // A scan and its findings must appear together or not at all: a half-written
    // scan would show a score with no findings behind it.
    db.exec('BEGIN IMMEDIATE');
    try {
      db.prepare(
        `INSERT OR REPLACE INTO scans
           (id, project_id, status, started_at, completed_at, duration_ms, overall_score, finding_count, error, payload)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        result.id,
        result.projectId,
        result.status,
        result.startedAt,
        result.completedAt ?? null,
        result.durationMs,
        result.scores.overall,
        result.findings.length,
        result.error ?? null,
        JSON.stringify(result),
      );

      db.prepare('DELETE FROM findings WHERE scan_id = ?').run(result.id);
      const insertFinding = db.prepare(
        `INSERT INTO findings
           (id, scan_id, project_id, fingerprint, rule_id, severity, kind, status, scanner,
            risk_score, path, title, suppressed, first_seen, payload)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      );

      for (const finding of result.findings) {
        insertFinding.run(
          finding.id,
          result.id,
          result.projectId,
          finding.fingerprint,
          finding.ruleId,
          finding.severity,
          finding.kind,
          finding.status,
          finding.scanner,
          finding.riskScore,
          finding.location?.path ?? null,
          finding.title,
          finding.suppressed ? 1 : 0,
          finding.firstSeenAt,
          JSON.stringify(finding),
        );
      }

      if (result.status === 'completed') {
        const point = toHistoryPoint(
          result.id,
          result.scores,
          result.completedAt ?? result.startedAt,
        );
        db.prepare(
          'INSERT OR REPLACE INTO score_history (scan_id, project_id, timestamp, payload) VALUES (?, ?, ?, ?)',
        ).run(result.id, result.projectId, point.timestamp, JSON.stringify(point));

        db.prepare('UPDATE projects SET last_scan_id = ?, updated_at = ? WHERE id = ?').run(
          result.id,
          new Date().toISOString(),
          result.projectId,
        );
      }

      db.exec('COMMIT');
    } catch (error) {
      db.exec('ROLLBACK');
      throw errors.storage('Failed to save scan', error);
    }
  }

  async getScan(id: string): Promise<ScanResult | undefined> {
    const row = this.database.prepare('SELECT payload FROM scans WHERE id = ?').get(id) as
      { payload: string } | undefined;
    return row ? (JSON.parse(row.payload) as ScanResult) : undefined;
  }

  async listScans(options: ListScansOptions): Promise<Paginated<StoredScan>> {
    const limit = Math.min(options.limit ?? 20, 200);
    const offset = options.offset ?? 0;

    const where: string[] = [];
    const params: unknown[] = [];
    if (options.projectId) {
      where.push('project_id = ?');
      params.push(options.projectId);
    }
    if (options.status?.length) {
      where.push(`status IN (${options.status.map(() => '?').join(',')})`);
      params.push(...options.status);
    }
    const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const total = Number(
      (
        this.database.prepare(`SELECT COUNT(*) AS n FROM scans ${clause}`).get(...params) as {
          n: number;
        }
      ).n,
    );

    const rows = this.database
      .prepare(
        `SELECT id, project_id, status, started_at, completed_at, duration_ms, overall_score, finding_count, error, payload
         FROM scans ${clause} ORDER BY started_at DESC LIMIT ? OFFSET ?`,
      )
      .all(...params, limit, offset) as Record<string, unknown>[];

    return {
      items: rows.map((row) => ({
        id: String(row['id']),
        projectId: String(row['project_id']),
        status: row['status'] as StoredScan['status'],
        startedAt: String(row['started_at']),
        ...(row['completed_at'] ? { completedAt: String(row['completed_at']) } : {}),
        durationMs: Number(row['duration_ms']),
        findingCount: Number(row['finding_count']),
        ...(row['error'] ? { error: String(row['error']) } : {}),
        scores: (JSON.parse(String(row['payload'])) as ScanResult).scores,
      })),
      total,
      limit,
      offset,
    };
  }

  async getLatestScan(projectId: string): Promise<ScanResult | undefined> {
    const row = this.database
      .prepare(
        `SELECT payload FROM scans WHERE project_id = ? AND status = 'completed'
         ORDER BY started_at DESC LIMIT 1`,
      )
      .get(projectId) as { payload: string } | undefined;
    return row ? (JSON.parse(row.payload) as ScanResult) : undefined;
  }

  async deleteScan(id: string): Promise<boolean> {
    const result = this.database.prepare('DELETE FROM scans WHERE id = ?').run(id);
    return Number(result.changes) > 0;
  }

  /* ---------------------------------------------------------------- */
  /* Findings                                                          */
  /* ---------------------------------------------------------------- */

  async listFindings(scanId: string, options: ListFindingsOptions): Promise<Paginated<Finding>> {
    const limit = Math.min(options.limit ?? 50, 500);
    const offset = options.offset ?? 0;

    // Coarse filters run in SQL against indexes; the text search runs in memory
    // over the already-narrowed set, which keeps the query planner simple
    // without giving up index use on the selective columns.
    const where: string[] = ['scan_id = ?'];
    const params: unknown[] = [scanId];

    if (options.severity?.length) {
      where.push(`severity IN (${options.severity.map(() => '?').join(',')})`);
      params.push(...options.severity);
    }
    if (options.kind?.length) {
      where.push(`kind IN (${options.kind.map(() => '?').join(',')})`);
      params.push(...options.kind);
    }
    if (options.status?.length) {
      where.push(`status IN (${options.status.map(() => '?').join(',')})`);
      params.push(...options.status);
    }
    if (options.scanner?.length) {
      where.push(`scanner IN (${options.scanner.map(() => '?').join(',')})`);
      params.push(...options.scanner);
    }
    if (options.suppressed !== undefined) {
      where.push('suppressed = ?');
      params.push(options.suppressed ? 1 : 0);
    }
    if (options.path) {
      where.push('path LIKE ?');
      params.push(`%${options.path}%`);
    }

    const clause = `WHERE ${where.join(' AND ')}`;
    const rows = this.database
      .prepare(`SELECT payload FROM findings ${clause} ORDER BY risk_score DESC`)
      .all(...params) as { payload: string }[];

    let findings = rows.map((row) => JSON.parse(row.payload) as Finding);
    if (options.search) findings = filterFindings(findings, { search: options.search });

    return {
      items: findings.slice(offset, offset + limit),
      total: findings.length,
      limit,
      offset,
    };
  }

  async getFinding(scanId: string, findingId: string): Promise<Finding | undefined> {
    const row = this.database
      .prepare('SELECT payload FROM findings WHERE scan_id = ? AND id = ?')
      .get(scanId, findingId) as { payload: string } | undefined;
    return row ? (JSON.parse(row.payload) as Finding) : undefined;
  }

  async updateFindingStatus(
    scanId: string,
    findingId: string,
    status: Finding['status'],
    note?: string,
  ): Promise<Finding | undefined> {
    const existing = await this.getFinding(scanId, findingId);
    if (!existing) return undefined;

    const updated: Finding = {
      ...existing,
      status,
      ...(note ? { suppressionReason: note } : {}),
      suppressed: status === 'accepted-risk' || status === 'false-positive',
    };

    this.database
      .prepare(
        'UPDATE findings SET status = ?, suppressed = ?, payload = ? WHERE scan_id = ? AND id = ?',
      )
      .run(status, updated.suppressed ? 1 : 0, JSON.stringify(updated), scanId, findingId);

    // Keep the denormalized copy in the scan payload consistent, otherwise a
    // re-export would show the pre-triage status.
    const scan = await this.getScan(scanId);
    if (scan) {
      const next: ScanResult = {
        ...scan,
        findings: scan.findings.map((f) => (f.id === findingId ? updated : f)),
      };
      this.database
        .prepare('UPDATE scans SET payload = ? WHERE id = ?')
        .run(JSON.stringify(next), scanId);
    }

    return updated;
  }

  /* ---------------------------------------------------------------- */
  /* Trends                                                            */
  /* ---------------------------------------------------------------- */

  async getScoreHistory(projectId: string, limit = 30): Promise<ScoreHistoryPoint[]> {
    const rows = this.database
      .prepare(
        'SELECT payload FROM score_history WHERE project_id = ? ORDER BY timestamp DESC LIMIT ?',
      )
      .all(projectId, limit) as { payload: string }[];

    return rows.map((row) => JSON.parse(row.payload) as ScoreHistoryPoint).reverse();
  }
}

function rowToProject(row: Record<string, unknown>): Project {
  return {
    id: String(row['id']),
    ownerId: String(row['owner_id']),
    slug: String(row['slug']),
    name: String(row['name']),
    ...(row['description'] ? { description: String(row['description']) } : {}),
    target: JSON.parse(String(row['target'])) as Project['target'],
    ...(row['options'] ? { defaultOptions: JSON.parse(String(row['options'])) } : {}),
    ...(row['last_scan_id'] ? { lastScanId: String(row['last_scan_id']) } : {}),
    createdAt: String(row['created_at']),
    updatedAt: String(row['updated_at']),
  };
}
