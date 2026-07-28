import { retry, severityFromCvss, type Logger, type Severity } from '@sentinel/core';
import type { ParsedDependency } from '../manifests/index.js';
import { osvRangeToExpression } from './semver.js';
import type { Advisory } from './bundled.js';

/**
 * OSV.dev client.
 *
 * OSV is free, requires no API key, and aggregates GitHub Security Advisories,
 * RustSec, the Go vulnerability database, PyPA and others. It is queried only
 * when the operator explicitly enables network access, because a security
 * scanner that phones home by default is not one you can run on a private
 * codebase without asking permission first.
 */

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns';

/** OSV ecosystem names differ from purl types in a few cases. */
const ECOSYSTEM_MAP: Record<string, string> = {
  npm: 'npm',
  pypi: 'PyPI',
  golang: 'Go',
  cargo: 'crates.io',
  maven: 'Maven',
  composer: 'Packagist',
  nuget: 'NuGet',
  rubygems: 'RubyGems',
};

interface OsvSeverity {
  type: string;
  score: string;
}

interface OsvAffected {
  package?: { name?: string; ecosystem?: string };
  ranges?: {
    type?: string;
    events?: { introduced?: string; fixed?: string; last_affected?: string }[];
  }[];
  versions?: string[];
  ecosystem_specific?: { severity?: string };
}

interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: OsvSeverity[];
  affected?: OsvAffected[];
  references?: { type?: string; url?: string }[];
  database_specific?: { severity?: string; cwe_ids?: string[] };
}

interface OsvBatchResponse {
  results?: { vulns?: { id: string; modified?: string }[] }[];
}

/** Pull the base score out of a CVSS vector string like `CVSS:3.1/AV:N/.../A:H`. */
function cvssScoreFrom(severities: OsvSeverity[] | undefined): number | undefined {
  const entry = severities?.find((s) => s.type?.startsWith('CVSS'));
  if (!entry) return undefined;
  const numeric = Number.parseFloat(entry.score);
  return Number.isFinite(numeric) ? numeric : undefined;
}

function severityFrom(vuln: OsvVulnerability): { severity: Severity; cvss?: number } {
  const cvss = cvssScoreFrom(vuln.severity);
  if (cvss !== undefined) return { severity: severityFromCvss(cvss), cvss };

  const label = vuln.database_specific?.severity?.toLowerCase();
  if (label === 'critical') return { severity: 'critical' };
  if (label === 'high') return { severity: 'high' };
  if (label === 'low') return { severity: 'low' };
  if (label === 'moderate' || label === 'medium') return { severity: 'medium' };

  // Unknown severity is reported as medium rather than dropped — an advisory we
  // cannot rank is still an advisory the developer should see.
  return { severity: 'medium' };
}

function toAdvisory(vuln: OsvVulnerability, dependency: ParsedDependency): Advisory | undefined {
  const osvEcosystem = ECOSYSTEM_MAP[dependency.ecosystem];
  const affected = vuln.affected?.find(
    (entry) =>
      entry.package?.name?.toLowerCase() === dependency.name.toLowerCase() &&
      (!osvEcosystem || entry.package?.ecosystem === osvEcosystem),
  );

  const ranges = affected?.ranges?.flatMap((range) => range.events ?? []) ?? [];
  const expression = ranges.length ? osvRangeToExpression(ranges) : '';
  // Some advisories enumerate exact versions instead of ranges.
  const explicitVersions = affected?.versions ?? [];
  const vulnerableRange =
    expression ||
    (explicitVersions.length ? explicitVersions.map((v) => `=${v}`).join(' || ') : '');
  if (!vulnerableRange) return undefined;

  const fixedVersions = ranges.map((event) => event.fixed).filter((v): v is string => Boolean(v));
  const { severity, cvss } = severityFrom(vuln);

  return {
    id: vuln.id,
    ecosystem: dependency.ecosystem,
    package: dependency.name,
    vulnerableRange,
    fixedVersions,
    severity,
    ...(cvss !== undefined ? { cvss } : {}),
    title: vuln.summary ?? vuln.id,
    description: vuln.details?.slice(0, 1500) ?? vuln.summary ?? 'No description provided by OSV.',
    cve: vuln.aliases?.filter((alias) => alias.startsWith('CVE-')) ?? [],
    cwe: vuln.database_specific?.cwe_ids ?? [],
    references: (vuln.references ?? [])
      .map((r) => r.url)
      .filter((url): url is string => Boolean(url))
      .slice(0, 5),
  };
}

export interface OsvClientOptions {
  logger: Logger;
  timeoutMs?: number;
  signal?: AbortSignal;
  /** Injected in tests so the suite never touches the network. */
  fetchImpl?: typeof fetch;
}

/**
 * Query OSV for a set of dependencies.
 *
 * Failure is never fatal: if OSV is unreachable, the caller still has the
 * bundled advisories. Returning partial results beats failing the whole scan.
 */
export async function queryOsv(
  dependencies: readonly ParsedDependency[],
  options: OsvClientOptions,
): Promise<Map<string, Advisory[]>> {
  const result = new Map<string, Advisory[]>();
  const queryable = dependencies.filter(
    (d) => d.version && d.version !== 'unknown' && ECOSYSTEM_MAP[d.ecosystem],
  );
  if (!queryable.length) return result;

  const doFetch = options.fetchImpl ?? fetch;
  const timeoutMs = options.timeoutMs ?? 20_000;
  // OSV documents a 1000-query cap per batch; stay well under it.
  const BATCH_SIZE = 250;

  for (let offset = 0; offset < queryable.length; offset += BATCH_SIZE) {
    const batch = queryable.slice(offset, offset + BATCH_SIZE);

    try {
      const response = await retry(
        async () => {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeoutMs);
          options.signal?.addEventListener('abort', () => controller.abort(), { once: true });

          try {
            const res = await doFetch(OSV_BATCH_URL, {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({
                queries: batch.map((d) => ({
                  version: d.version,
                  package: { name: d.name, ecosystem: ECOSYSTEM_MAP[d.ecosystem] },
                })),
              }),
              signal: controller.signal,
            });
            if (!res.ok) throw new Error(`OSV responded ${res.status}`);
            return (await res.json()) as OsvBatchResponse;
          } finally {
            clearTimeout(timer);
          }
        },
        {
          attempts: 3,
          baseDelayMs: 500,
          // Client errors will not fix themselves on retry.
          shouldRetry: (error) => !String(error).includes('OSV responded 4'),
        },
      );

      // The batch endpoint returns ids only; fetch details for the ones that matched.
      const detailIds = new Set<string>();
      response.results?.forEach((entry) => entry.vulns?.forEach((v) => detailIds.add(v.id)));
      if (!detailIds.size) continue;

      const details = await fetchVulnerabilityDetails(
        [...detailIds],
        doFetch,
        timeoutMs,
        options.logger,
      );

      response.results?.forEach((entry, index) => {
        const dependency = batch[index];
        if (!dependency || !entry.vulns?.length) return;

        const advisories = entry.vulns
          .map((v) => details.get(v.id))
          .filter((v): v is OsvVulnerability => Boolean(v))
          .map((v) => toAdvisory(v, dependency))
          .filter((a): a is Advisory => Boolean(a));

        if (advisories.length) {
          result.set(`${dependency.ecosystem}:${dependency.name.toLowerCase()}`, advisories);
        }
      });
    } catch (error) {
      options.logger.warn('OSV lookup failed; falling back to bundled advisories', {
        error: String(error),
        batchStart: offset,
      });
    }
  }

  return result;
}

async function fetchVulnerabilityDetails(
  ids: readonly string[],
  doFetch: typeof fetch,
  timeoutMs: number,
  logger: Logger,
): Promise<Map<string, OsvVulnerability>> {
  const details = new Map<string, OsvVulnerability>();
  // Bound the detail fan-out; a pathological repo should not issue thousands of
  // requests.
  const capped = ids.slice(0, 300);
  const CONCURRENCY = 8;

  for (let i = 0; i < capped.length; i += CONCURRENCY) {
    const slice = capped.slice(i, i + CONCURRENCY);
    await Promise.all(
      slice.map(async (id) => {
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeoutMs);
          try {
            const res = await doFetch(`${OSV_VULN_URL}/${encodeURIComponent(id)}`, {
              signal: controller.signal,
            });
            if (!res.ok) return;
            details.set(id, (await res.json()) as OsvVulnerability);
          } finally {
            clearTimeout(timer);
          }
        } catch (error) {
          logger.debug('Failed to fetch OSV vulnerability detail', { id, error: String(error) });
        }
      }),
    );
  }

  return details;
}
