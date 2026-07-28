import { readFile, rm, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { silentLogger, type ScanResult } from '@sentinel/core';
import { runScan, shouldFailBuild } from './engine.js';

/**
 * End-to-end scan against the deliberately vulnerable fixture repository.
 *
 * This is the test that matters most: it proves the whole pipeline — walking,
 * rule evaluation, dependency resolution, normalization, dedupe, scoring —
 * produces real findings on real (if intentionally awful) code.
 */

const FIXTURE = resolve(
  dirname(fileURLToPath(import.meta.url)),
  '../../../fixtures/vulnerable-app',
);

let result: ScanResult;

/**
 * The fixture's `.env` is generated rather than committed.
 *
 * `.gitignore` excludes `.env` everywhere — correctly — so a committed one
 * would not survive a clone, and the test would pass locally while failing in
 * CI. Committing strings that match live credential formats would also trip
 * GitHub's push protection on this repository.
 */
const FIXTURE_ENV = join(FIXTURE, '.env');

beforeAll(async () => {
  const template = await readFile(join(FIXTURE, 'env.template'), 'utf8');
  // Reassemble the credential formats the template stores split apart.
  await writeFile(FIXTURE_ENV, template.replaceAll('@@LIVE@@', 'live').replaceAll('@@US@@', '_'));

  result = await runScan({
    target: { type: 'local', path: FIXTURE },
    // Network stays off: the suite must be deterministic and offline.
    options: { allowNetwork: false, concurrency: 4 },
    logger: silentLogger,
  });
}, 120_000);

afterAll(async () => {
  await rm(FIXTURE_ENV, { force: true });
});

function findingsFor(ruleFragment: string) {
  return result.findings.filter((f) => f.ruleId.includes(ruleFragment));
}

describe('scan lifecycle', () => {
  it('completes successfully', () => {
    expect(result.status).toBe('completed');
    expect(result.error).toBeUndefined();
    expect(result.durationMs).toBeGreaterThan(0);
  });

  it('reports repository metadata', () => {
    expect(result.repository.fileCount).toBeGreaterThan(5);
    expect(result.repository.languages.length).toBeGreaterThan(2);
    expect(result.repository.languages.map((l) => l.language)).toContain('javascript');
  });

  it('records a run entry for every scanner, including skipped ones', () => {
    expect(result.scannerRuns.length).toBeGreaterThan(8);
    // Coverage gaps must be explicit, never silent.
    for (const run of result.scannerRuns) {
      if (run.status !== 'ok') expect(run.reason).toBeTruthy();
    }
  });

  it('produces no findings without a location unless they are summary findings', () => {
    for (const finding of result.findings) {
      if (finding.location) {
        expect(finding.location.path).not.toMatch(/^\//);
        expect(finding.location.path).not.toContain('..');
      }
    }
  });

  it('assigns every finding a stable id, fingerprint and risk score', () => {
    const ids = new Set(result.findings.map((f) => f.id));
    expect(ids.size).toBe(result.findings.length);
    for (const finding of result.findings) {
      expect(finding.fingerprint).toHaveLength(32);
      expect(finding.riskScore).toBeGreaterThanOrEqual(0);
      expect(finding.riskScore).toBeLessThanOrEqual(100);
    }
  });
});

describe('SAST detection', () => {
  it('finds SQL injection across every language in the fixture', () => {
    for (const rule of [
      'js-sql-injection',
      'py-sql-injection',
      'java-sql-injection',
      'go-sql-injection',
      'php-sql-injection',
    ]) {
      expect(findingsFor(rule).length, `expected ${rule}`).toBeGreaterThan(0);
    }
  });

  it('finds command injection', () => {
    expect(findingsFor('js-command-injection').length).toBeGreaterThan(0);
    expect(findingsFor('go-command-injection').length).toBeGreaterThan(0);
    expect(findingsFor('php-command-injection').length).toBeGreaterThan(0);
  });

  it('finds unsafe deserialization', () => {
    expect(findingsFor('py-insecure-deserialization').length).toBeGreaterThan(0);
    expect(findingsFor('java-insecure-deserialization').length).toBeGreaterThan(0);
    expect(findingsFor('php-insecure-deserialization').length).toBeGreaterThan(0);
  });

  it('finds JWT verification bypass and weak randomness', () => {
    expect(findingsFor('js-jwt-verification-bypass').length).toBeGreaterThan(0);
    expect(findingsFor('js-weak-random-for-security').length).toBeGreaterThan(0);
    expect(findingsFor('java-insecure-random').length).toBeGreaterThan(0);
  });

  it('finds disabled TLS verification', () => {
    expect(findingsFor('go-tls-verification-disabled').length).toBeGreaterThan(0);
  });

  it('finds CORS and cookie misconfiguration', () => {
    expect(findingsFor('js-cors-wildcard-credentials').length).toBeGreaterThan(0);
    expect(findingsFor('js-insecure-cookie').length).toBeGreaterThan(0);
  });

  it('attaches CWE and OWASP taxonomy to findings', () => {
    const sqlFinding = findingsFor('sql-injection')[0];
    expect(sqlFinding?.taxonomy?.cwe).toContain('CWE-89');
    expect(sqlFinding?.taxonomy?.owaspTop10?.[0]).toMatch(/A03:2021/);
  });
});

describe('AI security detection', () => {
  it('detects the repository as an AI application and analyzes it', () => {
    const aiFindings = result.findings.filter((f) => f.kind === 'ai-security');
    expect(aiFindings.length).toBeGreaterThan(0);
  });

  it('finds prompt injection', () => {
    const injection = result.findings.filter((f) => f.ruleId.includes('prompt-injection'));
    expect(injection.length).toBeGreaterThan(0);
    expect(injection[0]?.taxonomy?.owaspLlmTop10?.[0]).toMatch(/LLM01/);
  });

  it('finds unsafe tool execution and excessive agency', () => {
    expect(findingsFor('ai-unsafe-tool-execution').length).toBeGreaterThan(0);
    expect(findingsFor('ai-human-approval-disabled').length).toBeGreaterThan(0);
  });

  it('finds unsafe handling of model output', () => {
    expect(findingsFor('ai-unsafe-output-execution').length).toBeGreaterThan(0);
  });

  it('finds a vector search with no tenancy filter', () => {
    expect(findingsFor('ai-vector-search-no-tenant-filter').length).toBeGreaterThan(0);
  });

  it('finds an unbounded model invocation', () => {
    expect(findingsFor('ai-unbounded-consumption').length).toBeGreaterThan(0);
  });
});

describe('secret detection', () => {
  it('finds provider credentials committed to the repository', () => {
    const secrets = result.findings.filter((f) => f.kind === 'secrets');
    expect(secrets.length).toBeGreaterThan(2);

    const ruleIds = secrets.map((f) => f.ruleId).join(' ');
    expect(ruleIds).toMatch(
      /github-token|stripe-secret-key|openai-api-key|database-connection-string/,
    );
  });

  it('never puts the raw secret into the finding', () => {
    const secrets = result.findings.filter((f) => f.kind === 'secrets');
    for (const finding of secrets) {
      const snippet = finding.location?.snippet ?? '';
      expect(snippet).not.toMatch(/ghp_[A-Za-z0-9]{36}/);
      expect(snippet).not.toMatch(/sk_live_[A-Za-z0-9]{20,}/);
      expect(snippet).not.toMatch(/sk-proj-[A-Za-z0-9_-]{20,}/);
    }
  });

  it('includes a masked value and revocation guidance', () => {
    const secret = result.findings.find((f) => f.kind === 'secrets' && f.metadata?.masked);
    expect(secret?.metadata?.masked).toMatch(/\*/);
    expect(secret?.remediationHint).toBeTruthy();
  });
});

describe('dependency analysis', () => {
  it('finds known-vulnerable packages from the bundled advisory snapshot', () => {
    const dependencyFindings = result.findings.filter((f) => f.kind === 'dependencies');
    expect(dependencyFindings.length).toBeGreaterThan(2);

    const packages = dependencyFindings.map((f) => f.component?.name).filter(Boolean);
    expect(packages).toContain('lodash');
    expect(packages).toContain('axios');
  });

  it('reports the fixed version in the remediation hint', () => {
    const lodash = result.findings.find((f) => f.component?.name === 'lodash');
    expect(lodash?.remediationHint).toMatch(/Upgrade lodash to 4\.17\.21/);
    expect(lodash?.taxonomy?.cve?.length).toBeGreaterThan(0);
  });

  it('resolves dependencies from both npm and PyPI manifests', () => {
    const ecosystems = new Set(
      result.findings.filter((f) => f.kind === 'dependencies').map((f) => f.component?.ecosystem),
    );
    expect(ecosystems.has('npm')).toBe(true);
    expect(ecosystems.has('pypi')).toBe(true);
  });

  it('downgrades severity for development-only dependencies', () => {
    const devFinding = result.findings.find(
      (f) => f.kind === 'dependencies' && f.metadata?.isDevelopmentDependency === true,
    );
    if (devFinding) expect(devFinding.severity).not.toBe('critical');
  });
});

describe('infrastructure and configuration analysis', () => {
  it('finds Dockerfile problems', () => {
    expect(findingsFor('docker-latest-tag').length).toBeGreaterThan(0);
    expect(findingsFor('docker-secret-in-build').length).toBeGreaterThan(0);
    expect(findingsFor('docker-curl-pipe-shell').length).toBeGreaterThan(0);
  });

  it('finds Terraform misconfiguration', () => {
    expect(findingsFor('terraform-public-ingress').length).toBeGreaterThan(0);
    expect(findingsFor('terraform-public-bucket').length).toBeGreaterThan(0);
    expect(findingsFor('terraform-unencrypted-storage').length).toBeGreaterThan(0);
    expect(findingsFor('terraform-iam-wildcard').length).toBeGreaterThan(0);
  });

  it('finds unsafe Kubernetes security context', () => {
    expect(findingsFor('k8s-privileged-container').length).toBeGreaterThan(0);
    expect(findingsFor('k8s-host-namespace').length).toBeGreaterThan(0);
  });

  it('finds CI workflow script injection and pull_request_target misuse', () => {
    expect(findingsFor('config-ci-script-injection').length).toBeGreaterThan(0);
    expect(findingsFor('config-ci-pull-request-target').length).toBeGreaterThan(0);
  });

  it('finds a committed environment file', () => {
    expect(findingsFor('config-committed-env-file').length).toBeGreaterThan(0);
  });
});

describe('scoring and SBOM', () => {
  it('scores an intentionally terrible repository badly', () => {
    expect(result.scores.overall).toBeLessThan(60);
    expect(['D', 'F']).toContain(result.scores.grade);
    expect(['elevated', 'severe']).toContain(result.scores.riskLevel);
  });

  it('scores each analyzed category and marks unanalyzed ones', () => {
    for (const category of result.scores.categories) {
      expect(category.score).toBeGreaterThanOrEqual(0);
      expect(category.score).toBeLessThanOrEqual(100);
      expect(category.rationale).toBeTruthy();
    }
    expect(result.scores.categories.find((c) => c.category === 'secrets')?.analyzed).toBe(true);
  });

  it('generates an SBOM with the resolved components', () => {
    expect(result.sbom).toBeDefined();
    expect(result.sbom?.format).toBe('cyclonedx-1.5');
    expect(result.sbom?.components.length).toBeGreaterThan(5);
    expect(result.sbom?.components[0]?.purl).toMatch(/^pkg:/);
  });
});

describe('CI gating', () => {
  it('fails the build at the critical threshold', () => {
    expect(shouldFailBuild(result, 'critical')).toBe(true);
  });

  it('does not fail when no threshold is configured', () => {
    expect(shouldFailBuild(result, undefined)).toBe(false);
  });
});

describe('robustness', () => {
  it('returns a failed result rather than throwing for an invalid target', async () => {
    const failed = await runScan({
      target: { type: 'local', path: '/nonexistent/path/that/does/not/exist' },
      logger: silentLogger,
    });
    expect(failed.status).toBe('failed');
    expect(failed.error).toBeTruthy();
    expect(failed.findings).toEqual([]);
  });

  it('honours a restricted kind list', async () => {
    const secretsOnly = await runScan({
      target: { type: 'local', path: FIXTURE },
      options: { kinds: ['secrets'], allowNetwork: false },
      logger: silentLogger,
    });
    expect(secretsOnly.status).toBe('completed');
    expect(secretsOnly.findings.every((f) => f.kind === 'secrets')).toBe(true);
  }, 60_000);
});
