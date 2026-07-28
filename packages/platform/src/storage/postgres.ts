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
 * PostgreSQL / Supabase storage.
 *
 * Selected automatically when `DATABASE_URL` is set. The driver (`postgres`) is
 * an optional dependency loaded dynamically, so a default install stays free of
 * it and the failure mode when it is missing is an actionable message rather
 * than a module-not-found stack trace.
 */

/** The slice of the postgres.js API this adapter uses. */
type SqlTag = {
  <T = Record<string, unknown>>(strings: TemplateStringsArray, ...values: unknown[]): Promise<T[]>;
  begin<T>(fn: (sql: SqlTag) => Promise<T>): Promise<T>;
  end(): Promise<void>;
  unsafe(query: string, params?: unknown[]): Promise<Record<string, unknown>[]>;
};

const SCHEMA = `
CREATE TABLE IF NOT EXISTS projects (
  id           TEXT PRIMARY KEY,
  owner_id     TEXT NOT NULL,
  slug         TEXT NOT NULL,
  name         TEXT NOT NULL,
  description  TEXT,
  target       JSONB NOT NULL,
  options      JSONB,
  last_scan_id TEXT,
  created_at   TIMESTAMPTZ NOT NULL,
  updated_at   TIMESTAMPTZ NOT NULL,
  UNIQUE (owner_id, slug)
);

CREATE TABLE IF NOT EXISTS scans (
  id            TEXT PRIMARY KEY,
  project_id    TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  status        TEXT NOT NULL,
  started_at    TIMESTAMPTZ NOT NULL,
  completed_at  TIMESTAMPTZ,
  duration_ms   INTEGER NOT NULL DEFAULT 0,
  overall_score INTEGER NOT NULL DEFAULT 0,
  finding_count INTEGER NOT NULL DEFAULT 0,
  error         TEXT,
  payload       JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_project_started ON scans(project_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);

CREATE TABLE IF NOT EXISTS findings (
  id          TEXT NOT NULL,
  scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  project_id  TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  rule_id     TEXT NOT NULL,
  severity    TEXT NOT NULL,
  kind        TEXT NOT NULL,
  status      TEXT NOT NULL,
  scanner     TEXT NOT NULL,
  risk_score  INTEGER NOT NULL,
  path        TEXT,
  title       TEXT NOT NULL,
  suppressed  BOOLEAN NOT NULL DEFAULT FALSE,
  first_seen  TIMESTAMPTZ NOT NULL,
  payload     JSONB NOT NULL,
  PRIMARY KEY (scan_id, id)
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(scan_id, severity);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(project_id, fingerprint);

CREATE TABLE IF NOT EXISTS score_history (
  scan_id    TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL,
  timestamp  TIMESTAMPTZ NOT NULL,
  payload    JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_history_project ON score_history(project_id, timestamp DESC);
`;

export interface PostgresStorageOptions {
  connectionString: string;
  logger: Logger;
  maxConnections?: number;
  /** Supabase and most managed Postgres require TLS. */
  ssl?: boolean | 'require';
}

export class PostgresStorage implements Storage {
  readonly kind = 'postgres' as const;
  private sql: SqlTag | undefined;

  constructor(private readonly options: PostgresStorageOptions) {}

  private get client(): SqlTag {
    if (!this.sql) throw errors.storage('Storage has not been initialized; call init() first');
    return this.sql;
  }

  async init(): Promise<void> {
    if (this.sql) return;

    const module = await optionalImport<{
      default: (url: string, options: Record<string, unknown>) => SqlTag;
    }>('postgres', 'PostgreSQL storage (selected because DATABASE_URL is set)');
    const createClient = module.default;

    this.sql = createClient(this.options.connectionString, {
      max: this.options.maxConnections ?? 10,
      ssl: this.options.ssl ?? 'require',
      // Sentinel stores JSON documents; let the driver hand them back parsed.
      transform: { undefined: null },
    });

    await this.client.unsafe(SCHEMA);
    this.options.logger.info('PostgreSQL storage ready');
  }

  async close(): Promise<void> {
    await this.sql?.end();
    this.sql = undefined;
  }

  /* ---------------------------------------------------------------- */
  /* Projects                                                          */
  /* ---------------------------------------------------------------- */

  async createProject(project: Project): Promise<Project> {
    await this.client`
      INSERT INTO projects (id, owner_id, slug, name, description, target, options, created_at, updated_at)
      VALUES (${project.id}, ${project.ownerId}, ${project.slug}, ${project.name},
              ${project.description ?? null}, ${JSON.stringify(project.target)}::jsonb,
              ${project.defaultOptions ? JSON.stringify(project.defaultOptions) : null}::jsonb,
              ${project.createdAt}, ${project.updatedAt})
    `;
    return project;
  }

  async getProject(id: string): Promise<Project | undefined> {
    const rows = await this.client`SELECT * FROM projects WHERE id = ${id}`;
    return rows[0] ? rowToProject(rows[0]) : undefined;
  }

  async getProjectBySlug(ownerId: string, slug: string): Promise<Project | undefined> {
    const rows = await this.client`
      SELECT * FROM projects WHERE owner_id = ${ownerId} AND slug = ${slug}
    `;
    return rows[0] ? rowToProject(rows[0]) : undefined;
  }

  async listProjects(ownerId: string): Promise<Project[]> {
    const rows = await this.client`
      SELECT * FROM projects WHERE owner_id = ${ownerId} ORDER BY updated_at DESC
    `;
    return rows.map(rowToProject);
  }

  async updateProject(id: string, patch: Partial<Project>): Promise<Project | undefined> {
    const existing = await this.getProject(id);
    if (!existing) return undefined;

    const merged: Project = { ...existing, ...patch, id, updatedAt: new Date().toISOString() };
    await this.client`
      UPDATE projects SET
        name = ${merged.name},
        description = ${merged.description ?? null},
        target = ${JSON.stringify(merged.target)}::jsonb,
        options = ${merged.defaultOptions ? JSON.stringify(merged.defaultOptions) : null}::jsonb,
        last_scan_id = ${merged.lastScanId ?? null},
        updated_at = ${merged.updatedAt}
      WHERE id = ${id}
    `;
    return merged;
  }

  async deleteProject(id: string): Promise<boolean> {
    const rows = await this.client`DELETE FROM projects WHERE id = ${id} RETURNING id`;
    return rows.length > 0;
  }

  /* ---------------------------------------------------------------- */
  /* Scans                                                             */
  /* ---------------------------------------------------------------- */

  async saveScan(result: ScanResult): Promise<void> {
    // One transaction: a scan row without its findings would render as a score
    // with nothing behind it.
    await this.client.begin(async (tx) => {
      await tx`
        INSERT INTO scans (id, project_id, status, started_at, completed_at, duration_ms,
                           overall_score, finding_count, error, payload)
        VALUES (${result.id}, ${result.projectId}, ${result.status}, ${result.startedAt},
                ${result.completedAt ?? null}, ${result.durationMs}, ${result.scores.overall},
                ${result.findings.length}, ${result.error ?? null}, ${JSON.stringify(result)}::jsonb)
        ON CONFLICT (id) DO UPDATE SET
          status = EXCLUDED.status,
          completed_at = EXCLUDED.completed_at,
          duration_ms = EXCLUDED.duration_ms,
          overall_score = EXCLUDED.overall_score,
          finding_count = EXCLUDED.finding_count,
          error = EXCLUDED.error,
          payload = EXCLUDED.payload
      `;

      await tx`DELETE FROM findings WHERE scan_id = ${result.id}`;

      for (const finding of result.findings) {
        await tx`
          INSERT INTO findings (id, scan_id, project_id, fingerprint, rule_id, severity, kind,
                                status, scanner, risk_score, path, title, suppressed, first_seen, payload)
          VALUES (${finding.id}, ${result.id}, ${result.projectId}, ${finding.fingerprint},
                  ${finding.ruleId}, ${finding.severity}, ${finding.kind}, ${finding.status},
                  ${finding.scanner}, ${finding.riskScore}, ${finding.location?.path ?? null},
                  ${finding.title}, ${finding.suppressed ?? false}, ${finding.firstSeenAt},
                  ${JSON.stringify(finding)}::jsonb)
        `;
      }

      if (result.status === 'completed') {
        const point = toHistoryPoint(
          result.id,
          result.scores,
          result.completedAt ?? result.startedAt,
        );
        await tx`
          INSERT INTO score_history (scan_id, project_id, timestamp, payload)
          VALUES (${result.id}, ${result.projectId}, ${point.timestamp}, ${JSON.stringify(point)}::jsonb)
          ON CONFLICT (scan_id) DO UPDATE SET payload = EXCLUDED.payload
        `;
        await tx`
          UPDATE projects SET last_scan_id = ${result.id}, updated_at = ${new Date().toISOString()}
          WHERE id = ${result.projectId}
        `;
      }
    });
  }

  async getScan(id: string): Promise<ScanResult | undefined> {
    const rows = await this.client<{ payload: ScanResult }>`
      SELECT payload FROM scans WHERE id = ${id}
    `;
    return rows[0]?.payload;
  }

  async listScans(options: ListScansOptions): Promise<Paginated<StoredScan>> {
    const limit = Math.min(options.limit ?? 20, 200);
    const offset = options.offset ?? 0;

    const conditions: string[] = [];
    const params: unknown[] = [];
    if (options.projectId) {
      params.push(options.projectId);
      conditions.push(`project_id = $${params.length}`);
    }
    if (options.status?.length) {
      params.push(options.status);
      conditions.push(`status = ANY($${params.length})`);
    }
    const clause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

    const countRows = await this.client.unsafe(
      `SELECT COUNT(*)::int AS n FROM scans ${clause}`,
      params,
    );
    const total = Number((countRows[0] as { n: number })?.n ?? 0);

    const rows = await this.client.unsafe(
      `SELECT id, project_id, status, started_at, completed_at, duration_ms, finding_count, error, payload
       FROM scans ${clause} ORDER BY started_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
      [...params, limit, offset],
    );

    return {
      items: rows.map((row) => ({
        id: String(row['id']),
        projectId: String(row['project_id']),
        status: row['status'] as StoredScan['status'],
        startedAt: new Date(row['started_at'] as string).toISOString(),
        ...(row['completed_at']
          ? { completedAt: new Date(row['completed_at'] as string).toISOString() }
          : {}),
        durationMs: Number(row['duration_ms']),
        findingCount: Number(row['finding_count']),
        ...(row['error'] ? { error: String(row['error']) } : {}),
        scores: (row['payload'] as ScanResult).scores,
      })),
      total,
      limit,
      offset,
    };
  }

  async getLatestScan(projectId: string): Promise<ScanResult | undefined> {
    const rows = await this.client<{ payload: ScanResult }>`
      SELECT payload FROM scans
      WHERE project_id = ${projectId} AND status = 'completed'
      ORDER BY started_at DESC LIMIT 1
    `;
    return rows[0]?.payload;
  }

  async deleteScan(id: string): Promise<boolean> {
    const rows = await this.client`DELETE FROM scans WHERE id = ${id} RETURNING id`;
    return rows.length > 0;
  }

  /* ---------------------------------------------------------------- */
  /* Findings                                                          */
  /* ---------------------------------------------------------------- */

  async listFindings(scanId: string, options: ListFindingsOptions): Promise<Paginated<Finding>> {
    const limit = Math.min(options.limit ?? 50, 500);
    const offset = options.offset ?? 0;

    const params: unknown[] = [scanId];
    const conditions = ['scan_id = $1'];

    const addAnyFilter = (column: string, values: string[] | undefined) => {
      if (!values?.length) return;
      params.push(values);
      conditions.push(`${column} = ANY($${params.length})`);
    };

    addAnyFilter('severity', options.severity);
    addAnyFilter('kind', options.kind);
    addAnyFilter('status', options.status);
    addAnyFilter('scanner', options.scanner);

    if (options.suppressed !== undefined) {
      params.push(options.suppressed);
      conditions.push(`suppressed = $${params.length}`);
    }
    if (options.path) {
      params.push(`%${options.path}%`);
      conditions.push(`path ILIKE $${params.length}`);
    }

    const rows = await this.client.unsafe(
      `SELECT payload FROM findings WHERE ${conditions.join(' AND ')} ORDER BY risk_score DESC`,
      params,
    );

    let findings = rows.map((row) => row['payload'] as Finding);
    if (options.search) findings = filterFindings(findings, { search: options.search });

    return { items: findings.slice(offset, offset + limit), total: findings.length, limit, offset };
  }

  async getFinding(scanId: string, findingId: string): Promise<Finding | undefined> {
    const rows = await this.client<{ payload: Finding }>`
      SELECT payload FROM findings WHERE scan_id = ${scanId} AND id = ${findingId}
    `;
    return rows[0]?.payload;
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

    await this.client.begin(async (tx) => {
      await tx`
        UPDATE findings SET status = ${status}, suppressed = ${updated.suppressed ?? false},
                            payload = ${JSON.stringify(updated)}::jsonb
        WHERE scan_id = ${scanId} AND id = ${findingId}
      `;
      // Keep the scan payload consistent so exports reflect triage decisions.
      await tx`
        UPDATE scans SET payload = jsonb_set(
          payload,
          '{findings}',
          (
            SELECT jsonb_agg(CASE WHEN f->>'id' = ${findingId}
                             THEN ${JSON.stringify(updated)}::jsonb ELSE f END)
            FROM jsonb_array_elements(payload->'findings') AS f
          )
        )
        WHERE id = ${scanId}
      `;
    });

    return updated;
  }

  /* ---------------------------------------------------------------- */
  /* Trends                                                            */
  /* ---------------------------------------------------------------- */

  async getScoreHistory(projectId: string, limit = 30): Promise<ScoreHistoryPoint[]> {
    const rows = await this.client<{ payload: ScoreHistoryPoint }>`
      SELECT payload FROM score_history
      WHERE project_id = ${projectId} ORDER BY timestamp DESC LIMIT ${limit}
    `;
    return rows.map((row) => row.payload).reverse();
  }
}

function rowToProject(row: Record<string, unknown>): Project {
  return {
    id: String(row['id']),
    ownerId: String(row['owner_id']),
    slug: String(row['slug']),
    name: String(row['name']),
    ...(row['description'] ? { description: String(row['description']) } : {}),
    target: row['target'] as Project['target'],
    ...(row['options'] ? { defaultOptions: row['options'] as Project['defaultOptions'] } : {}),
    ...(row['last_scan_id'] ? { lastScanId: String(row['last_scan_id']) } : {}),
    createdAt: new Date(row['created_at'] as string).toISOString(),
    updatedAt: new Date(row['updated_at'] as string).toISOString(),
  };
}
