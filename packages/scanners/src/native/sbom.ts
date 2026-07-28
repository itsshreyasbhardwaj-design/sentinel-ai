import { randomUUID } from 'node:crypto';
import type { RepositoryInfo, Sbom, SbomComponent } from '@sentinel/core';
import { classifyLicense } from './license.js';
import { getDependencyInventory } from './inventory.js';
import type { ScanContext, Scanner } from '../types.js';

/**
 * CycloneDX 1.5 SBOM generation.
 *
 * CycloneDX is the format procurement and compliance teams actually ask for,
 * and it is what `trivy`, `syft` and GitHub dependency submission all speak, so
 * the output drops straight into an existing supply-chain workflow.
 */

export async function generateSbom(ctx: ScanContext, repository: RepositoryInfo): Promise<Sbom> {
  const dependencies = await getDependencyInventory(ctx);

  const rootRef = `root:${repository.name}`;
  const components: SbomComponent[] = dependencies.map((dependency) => {
    const license = classifyLicense(dependency.licenses?.[0]);

    return {
      'bom-ref':
        dependency.purl ?? `${dependency.ecosystem}:${dependency.name}@${dependency.version}`,
      type: 'library',
      name: dependency.name,
      version: dependency.version,
      ...(dependency.purl ? { purl: dependency.purl } : {}),
      ...(license.id !== 'UNKNOWN' ? { licenses: [{ license: { id: license.id } }] } : {}),
      scope: dependency.dependencyType === 'optional' ? 'optional' : 'required',
      properties: [
        { name: 'sentinel:ecosystem', value: dependency.ecosystem },
        { name: 'sentinel:scope', value: dependency.scope },
        { name: 'sentinel:dependencyType', value: dependency.dependencyType },
        { name: 'sentinel:manifest', value: dependency.path },
      ],
    };
  });

  return {
    format: 'cyclonedx-1.5',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${randomUUID()}`,
    generatedAt: new Date().toISOString(),
    components,
    dependencies: [
      { ref: rootRef, dependsOn: components.map((c) => c['bom-ref']) },
      // Transitive edges are not recoverable from every manifest format, so we
      // publish a flat graph rather than an invented one.
      ...components.map((c) => ({ ref: c['bom-ref'], dependsOn: [] })),
    ],
  };
}

/** Serialize to the canonical CycloneDX JSON envelope. */
export function toCycloneDxJson(sbom: Sbom, repository: RepositoryInfo): string {
  return JSON.stringify(
    {
      bomFormat: 'CycloneDX',
      specVersion: sbom.specVersion,
      serialNumber: sbom.serialNumber,
      version: 1,
      metadata: {
        timestamp: sbom.generatedAt,
        tools: {
          components: [
            {
              type: 'application',
              name: 'Sentinel AI',
              version: '0.1.0',
              publisher: 'Sentinel AI',
            },
          ],
        },
        component: {
          type: 'application',
          'bom-ref': `root:${repository.name}`,
          name: repository.name,
          version: repository.commit?.slice(0, 12) ?? 'unknown',
          ...(repository.url ? { externalReferences: [{ type: 'vcs', url: repository.url }] } : {}),
        },
      },
      components: sbom.components,
      dependencies: sbom.dependencies,
    },
    null,
    2,
  );
}

/**
 * The SBOM "scanner" produces an artifact rather than findings. It is modelled
 * as a scanner so it participates in the same registry, availability reporting
 * and progress accounting as everything else.
 */
export const nativeSbomScanner: Scanner = {
  id: 'native-sbom',
  name: 'Sentinel SBOM Generator',
  kind: 'sbom',
  origin: 'native',
  description:
    'Produces a CycloneDX 1.5 software bill of materials from the resolved dependency inventory.',

  async isAvailable() {
    return { available: true };
  },

  async scan(ctx) {
    const dependencies = await getDependencyInventory(ctx);

    if (!dependencies.length) {
      return [
        {
          ruleId: 'sbom-no-dependencies',
          title: 'No dependency manifests found',
          description:
            'Sentinel could not locate a recognized dependency manifest, so no SBOM could be produced and dependency analysis has no input.',
          severity: 'info',
          kind: 'sbom',
          confidence: 'high',
          remediationHint:
            'Confirm the repository root was scanned and that manifests are not excluded by an ignore pattern.',
        },
      ];
    }

    return [
      {
        ruleId: 'sbom-generated',
        title: `Software bill of materials generated for ${dependencies.length} components`,
        description:
          'A CycloneDX 1.5 SBOM is available for export. Supply-chain regulations increasingly require one to be produced and retained for each release.',
        severity: 'info',
        kind: 'sbom',
        confidence: 'high',
        metadata: {
          componentCount: dependencies.length,
          ecosystems: [...new Set(dependencies.map((d) => d.ecosystem))],
        },
        taxonomy: {
          references: [
            {
              title: 'CycloneDX specification',
              url: 'https://cyclonedx.org/specification/overview/',
            },
          ],
        },
        remediationHint: 'Export the SBOM and attach it to your release artifacts.',
      },
    ];
  },
};
