import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { silentLogger } from '@sentinel/core';
import { runScan } from './engine.js';

/**
 * Credential samples are assembled at runtime so no literal that matches a real
 * provider format is committed. See the note in rules/secrets.test.ts.
 */
const sample = {
  stripe: `sk_${'live'}_51HxYzAbCdEfGhIjKlMnOpQrStUv`,
  github: `ghp${'_'}A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8`,
  postgres: `postgresql:${'//'}admin:hunter2@db.internal:5432/prod`,
};

/**
 * False-positive regression suite.
 *
 * Every case here was found by running Sentinel against its own source. They are
 * kept as tests because precision regressions are silent — the scan still
 * "works", it just produces noise, and a noisy report is one nobody reads.
 */

let root: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'sentinel-precision-'));
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

async function scan(files: Record<string, string>, kinds: ('sast' | 'secrets' | 'config')[]) {
  for (const [path, content] of Object.entries(files)) {
    const full = join(root, path);
    await mkdir(join(full, '..'), { recursive: true });
    await writeFile(full, content);
  }

  const result = await runScan({
    target: { type: 'local', path: root },
    options: { kinds, allowNetwork: false },
    logger: silentLogger,
  });

  expect(result.status).toBe('completed');
  return result;
}

describe('secret scanning precision', () => {
  it('does not flag placeholders in a .env.example file', async () => {
    const result = await scan(
      {
        '.env.example': [
          `# DATABASE_URL=${sample.postgres}`,
          `STRIPE_SECRET_KEY=${sample.stripe}`,
          `GITHUB_TOKEN=${sample.github}`,
        ].join('\n'),
      },
      ['secrets'],
    );

    // The entire point of a template file is to show the shape of each value.
    expect(result.findings.filter((f) => f.kind === 'secrets')).toHaveLength(0);
  });

  it('does not flag a commented-out connection string', async () => {
    const result = await scan(
      {
        'config/database.env': [
          '# Example, for reference only:',
          `# DATABASE_URL=${sample.postgres}`,
          'POOL_SIZE=10',
        ].join('\n'),
      },
      ['secrets'],
    );

    expect(result.findings.filter((f) => f.kind === 'secrets')).toHaveLength(0);
  });

  it('still flags a live credential in a real env file', async () => {
    const result = await scan(
      {
        '.env': `GITHUB_TOKEN=${sample.github}\n`,
      },
      ['secrets'],
    );

    // Precision must not come at the cost of missing the actual case.
    expect(result.findings.filter((f) => f.kind === 'secrets').length).toBeGreaterThan(0);
  });

  it('still flags a live credential on an uncommented line below a comment', async () => {
    const result = await scan(
      {
        'app.env': ['# Production configuration', `STRIPE_SECRET_KEY=${sample.stripe}`].join('\n'),
      },
      ['secrets'],
    );

    expect(result.findings.filter((f) => f.kind === 'secrets').length).toBeGreaterThan(0);
  });
});

describe('sensitive-logging precision', () => {
  it('does not flag a sensitive word that appears only in the log message', async () => {
    const result = await scan(
      {
        'src/auth.ts': [
          'export function verify(error: unknown) {',
          "  logger.debug('Token verification failed', { error: String(error) });",
          "  logger.info('Secret scan complete', { count: 3 });",
          '}',
        ].join('\n'),
      },
      ['sast'],
    );

    // These describe what happened; they do not log a credential.
    expect(result.findings.filter((f) => f.ruleId === 'common-sensitive-data-logged')).toHaveLength(
      0,
    );
  });

  it('still flags a credential passed as a logged value', async () => {
    const result = await scan(
      {
        'src/login.ts': [
          'export function login(email: string, password: string) {',
          "  console.log('login attempt', email, password);",
          '}',
        ].join('\n'),
      },
      ['sast'],
    );

    expect(
      result.findings.filter((f) => f.ruleId === 'common-sensitive-data-logged').length,
    ).toBeGreaterThan(0);
  });

  it('still flags a credential in a structured log field', async () => {
    const result = await scan(
      {
        'src/client.ts': [
          'export function connect(apiKey: string) {',
          "  logger.info('connecting', { api_key: apiKey });",
          '}',
        ].join('\n'),
      },
      ['sast'],
    );

    expect(
      result.findings.filter((f) => f.ruleId === 'common-sensitive-data-logged').length,
    ).toBeGreaterThan(0);
  });
});

describe('ordinary code produces no findings', () => {
  it('leaves a clean TypeScript module alone', async () => {
    const result = await scan(
      {
        'src/clean.ts': [
          'import { randomBytes } from "node:crypto";',
          '',
          'export function createToken(): string {',
          '  return randomBytes(32).toString("base64url");',
          '}',
          '',
          'export async function findUser(db: Db, id: string) {',
          '  return db.query("SELECT * FROM users WHERE id = $1", [id]);',
          '}',
        ].join('\n'),
      },
      ['sast', 'secrets'],
    );

    const noisy = result.findings.filter((f) => f.severity !== 'info');
    expect(noisy, JSON.stringify(noisy.map((f) => f.ruleId))).toHaveLength(0);
  });

  it('leaves a clean Python module alone', async () => {
    const result = await scan(
      {
        'app/clean.py': [
          'import secrets',
          '',
          'def create_token() -> str:',
          '    return secrets.token_urlsafe(32)',
          '',
          'def find_user(cursor, user_id):',
          '    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
          '    return cursor.fetchone()',
        ].join('\n'),
      },
      ['sast', 'secrets'],
    );

    const noisy = result.findings.filter((f) => f.severity !== 'info');
    expect(noisy, JSON.stringify(noisy.map((f) => f.ruleId))).toHaveLength(0);
  });
});
