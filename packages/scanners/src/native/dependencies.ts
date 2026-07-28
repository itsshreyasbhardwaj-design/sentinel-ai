import type { RawFinding } from '@sentinel/core';
import { advisoriesFor, type Advisory } from '../advisories/bundled.js';
import { queryOsv } from '../advisories/osv.js';
import { lowestFixedVersion, satisfiesRange } from '../advisories/semver.js';
import type { ParsedDependency } from '../manifests/index.js';
import { getDependencyInventory } from './inventory.js';
import type { Scanner } from '../types.js';

/**
 * Software composition analysis.
 *
 * Matches the resolved dependency inventory against advisories from two
 * sources: a bundled snapshot that always works offline, and OSV.dev when the
 * operator has enabled network access. Every finding records which source it
 * came from, because "we checked and found nothing" means something different
 * depending on the answer.
 */

function toFinding(
  dependency: ParsedDependency,
  advisory: Advisory,
  source: 'bundled' | 'osv',
): RawFinding {
  const fixed = lowestFixedVersion(advisory.fixedVersions);
  const isDev = dependency.dependencyType === 'development';

  return {
    ruleId: `dependency-${advisory.id}`,
    title: `${dependency.name}@${dependency.version}: ${advisory.title}`,
    description: advisory.description,
    // A vulnerability reachable only from the test suite is real but less
    // urgent than the same flaw in shipped code.
    severity:
      isDev && advisory.severity === 'critical'
        ? 'high'
        : isDev && advisory.severity === 'high'
          ? 'medium'
          : advisory.severity,
    kind: 'dependencies',
    confidence: dependency.version === 'unknown' ? 'low' : 'high',
    location: { path: dependency.path, startLine: 1 },
    component: {
      name: dependency.name,
      version: dependency.version,
      purl: dependency.purl,
      ecosystem: dependency.ecosystem,
      scope: dependency.scope,
      dependencyType: dependency.dependencyType,
      path: dependency.path,
    },
    taxonomy: {
      cve: advisory.cve?.length ? advisory.cve : [advisory.id],
      cwe: advisory.cwe,
      owaspTop10: ['A06:2021-Vulnerable and Outdated Components'],
      references: advisory.references.map((url) => ({ title: 'Advisory', url })),
    },
    metadata: {
      advisoryId: advisory.id,
      advisorySource: source,
      cvss: advisory.cvss,
      vulnerableRange: advisory.vulnerableRange,
      fixedVersions: advisory.fixedVersions,
      dependencyType: dependency.dependencyType,
      isDevelopmentDependency: isDev,
    },
    remediationHint: fixed
      ? `Upgrade ${dependency.name} to ${fixed} or later.`
      : `No fixed version is published yet. Assess whether the vulnerable code path is reachable, and consider an alternative package.`,
  };
}

export const nativeDependencyScanner: Scanner = {
  id: 'native-dependencies',
  name: 'Sentinel Dependency Scanner',
  kind: 'dependencies',
  origin: 'native',
  description:
    'Resolves dependencies from npm, PyPI, Go, Cargo, Maven, Composer, NuGet and RubyGems manifests and matches them against bundled advisories, augmented by OSV.dev when network access is enabled.',

  async isAvailable() {
    return { available: true };
  },

  async scan(ctx) {
    const dependencies = await getDependencyInventory(ctx);
    if (!dependencies.length) return [];

    const findings: RawFinding[] = [];
    const matched = new Set<string>();

    /* --- Bundled advisories: always available --- */
    for (const dependency of dependencies) {
      for (const advisory of advisoriesFor(dependency.ecosystem, dependency.name)) {
        if (dependency.version === 'unknown') continue;
        if (!satisfiesRange(dependency.version, advisory.vulnerableRange)) continue;
        matched.add(`${advisory.id}:${dependency.name}`);
        findings.push(toFinding(dependency, advisory, 'bundled'));
      }
    }

    /* --- OSV.dev: opt-in, additive --- */
    if (ctx.options.allowNetwork) {
      ctx.onProgress?.('Querying OSV.dev for advisories');
      const osvResults = await queryOsv(dependencies, {
        logger: ctx.logger,
        ...(ctx.signal ? { signal: ctx.signal } : {}),
      });

      for (const dependency of dependencies) {
        const advisories = osvResults.get(
          `${dependency.ecosystem}:${dependency.name.toLowerCase()}`,
        );
        if (!advisories) continue;

        for (const advisory of advisories) {
          const key = `${advisory.id}:${dependency.name}`;
          if (matched.has(key)) continue;
          if (!satisfiesRange(dependency.version, advisory.vulnerableRange)) continue;
          matched.add(key);
          findings.push(toFinding(dependency, advisory, 'osv'));
        }
      }
    } else {
      ctx.logger.info(
        'Network access disabled: dependency analysis used the bundled advisory snapshot only',
        { dependencies: dependencies.length },
      );
    }

    /* --- Dependencies we could not resolve to a concrete version --- */
    const unresolved = dependencies.filter((d) => d.version === 'unknown');
    if (unresolved.length) {
      findings.push({
        ruleId: 'dependency-unresolved-versions',
        title: `${unresolved.length} dependencies could not be resolved to an exact version`,
        description:
          'These packages are declared without a lockfile-pinned version, so they cannot be matched against advisories. Vulnerability coverage for them is incomplete.',
        severity: 'info',
        kind: 'dependencies',
        confidence: 'high',
        location: { path: unresolved[0]!.path, startLine: 1 },
        taxonomy: { cwe: ['CWE-1104'] },
        metadata: { packages: unresolved.slice(0, 50).map((d) => d.name) },
        remediationHint:
          'Commit a lockfile so every dependency resolves to an exact version that can be checked against advisories.',
      });
    }

    return findings;
  },
};
