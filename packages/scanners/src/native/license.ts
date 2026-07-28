import type { RawFinding } from '@sentinel/core';
import { getDependencyInventory } from './inventory.js';
import type { Scanner } from '../types.js';

/**
 * License analysis.
 *
 * Classifies dependency licenses by obligation class and reports the ones that
 * are likely to conflict with shipping proprietary software. This is legal
 * *risk surfacing*, not legal advice, and the findings say so — the goal is to
 * get the right packages in front of a human, not to adjudicate them.
 */

export type LicenseCategory =
  | 'permissive'
  | 'weak-copyleft'
  | 'strong-copyleft'
  | 'network-copyleft'
  | 'proprietary'
  | 'public-domain'
  | 'unknown';

interface LicenseInfo {
  category: LicenseCategory;
  /** Full SPDX name, for display. */
  name: string;
  /** Why it matters when distributing a closed-source product. */
  obligation: string;
}

const LICENSES: Record<string, LicenseInfo> = {
  MIT: { category: 'permissive', name: 'MIT License', obligation: 'Attribution only.' },
  'APACHE-2.0': {
    category: 'permissive',
    name: 'Apache License 2.0',
    obligation: 'Attribution plus notice of modifications; includes a patent grant.',
  },
  'BSD-2-CLAUSE': { category: 'permissive', name: 'BSD 2-Clause', obligation: 'Attribution only.' },
  'BSD-3-CLAUSE': {
    category: 'permissive',
    name: 'BSD 3-Clause',
    obligation: 'Attribution, no endorsement.',
  },
  ISC: { category: 'permissive', name: 'ISC License', obligation: 'Attribution only.' },
  'CC0-1.0': {
    category: 'public-domain',
    name: 'Creative Commons Zero',
    obligation: 'No obligations.',
  },
  UNLICENSE: { category: 'public-domain', name: 'The Unlicense', obligation: 'No obligations.' },
  '0BSD': { category: 'public-domain', name: 'BSD Zero Clause', obligation: 'No obligations.' },
  'MPL-2.0': {
    category: 'weak-copyleft',
    name: 'Mozilla Public License 2.0',
    obligation:
      'Modified MPL files must be released under MPL; the rest of your code is unaffected.',
  },
  'LGPL-2.1': {
    category: 'weak-copyleft',
    name: 'GNU Lesser General Public License 2.1',
    obligation:
      'Dynamic linking is generally acceptable; static linking triggers source obligations.',
  },
  'LGPL-3.0': {
    category: 'weak-copyleft',
    name: 'GNU Lesser General Public License 3.0',
    obligation:
      'Dynamic linking is generally acceptable; static linking triggers source obligations.',
  },
  'EPL-2.0': {
    category: 'weak-copyleft',
    name: 'Eclipse Public License 2.0',
    obligation: 'Modifications to EPL files must be published.',
  },
  'GPL-2.0': {
    category: 'strong-copyleft',
    name: 'GNU General Public License 2.0',
    obligation: 'Distributing a derived work requires releasing your source under the GPL.',
  },
  'GPL-3.0': {
    category: 'strong-copyleft',
    name: 'GNU General Public License 3.0',
    obligation: 'Distributing a derived work requires releasing your source under the GPL.',
  },
  'AGPL-3.0': {
    category: 'network-copyleft',
    name: 'GNU Affero General Public License 3.0',
    obligation:
      'Providing the software over a network counts as distribution, so a SaaS deployment triggers the source-release obligation.',
  },
  'SSPL-1.0': {
    category: 'network-copyleft',
    name: 'Server Side Public License',
    obligation:
      'Offering the software as a service requires releasing the entire service stack under the SSPL.',
  },
  'BUSL-1.1': {
    category: 'proprietary',
    name: 'Business Source License 1.1',
    obligation:
      'Production use is restricted until the change date; commercial terms may be required.',
  },
  'ELASTIC-2.0': {
    category: 'proprietary',
    name: 'Elastic License 2.0',
    obligation: 'Prohibits offering the software as a managed service.',
  },
  'CC-BY-NC-4.0': {
    category: 'proprietary',
    name: 'Creative Commons Attribution-NonCommercial 4.0',
    obligation: 'Commercial use is prohibited.',
  },
};

const SEVERITY_BY_CATEGORY: Record<LicenseCategory, RawFinding['severity']> = {
  permissive: 'info',
  'public-domain': 'info',
  'weak-copyleft': 'low',
  'strong-copyleft': 'medium',
  'network-copyleft': 'high',
  proprietary: 'high',
  unknown: 'low',
};

export function normalizeLicenseId(raw: string): string {
  return (
    raw
      .trim()
      .toUpperCase()
      .replace(/\s+/g, '-')
      .replace(/^\(|\)$/g, '')
      // `MIT OR Apache-2.0` — evaluate the first, most permissive option.
      .split(/-OR-|-AND-/)[0]!
      .replace(/-ONLY$|-OR-LATER$|\+$/, '')
  );
}

export function classifyLicense(raw: string | undefined): LicenseInfo & { id: string } {
  if (!raw) {
    return {
      id: 'UNKNOWN',
      category: 'unknown',
      name: 'Unknown',
      obligation: 'The license could not be determined from the package metadata.',
    };
  }

  const id = normalizeLicenseId(raw);
  const known = LICENSES[id];
  if (known) return { id, ...known };

  // Unrecognized but declared — treat as unknown rather than guessing.
  return {
    id,
    category: 'unknown',
    name: raw,
    obligation: 'This license is not in the known set and should be reviewed manually.',
  };
}

export const nativeLicenseScanner: Scanner = {
  id: 'native-license',
  name: 'Sentinel License Analyzer',
  kind: 'license',
  origin: 'native',
  description:
    'Classifies dependency licenses by obligation class and flags copyleft and source-available licenses that may conflict with proprietary distribution.',

  async isAvailable() {
    return { available: true };
  },

  async scan(ctx) {
    const dependencies = await getDependencyInventory(ctx);
    if (!dependencies.length) return [];

    const findings: RawFinding[] = [];
    const byCategory = new Map<LicenseCategory, { name: string; license: string }[]>();

    for (const dependency of dependencies) {
      const declared = dependency.licenses?.[0];
      const info = classifyLicense(declared);
      const bucket = byCategory.get(info.category) ?? [];
      bucket.push({ name: `${dependency.name}@${dependency.version}`, license: info.id });
      byCategory.set(info.category, bucket);

      // Individual findings only for the categories that carry real obligations;
      // one finding per MIT package would bury everything else.
      if (
        info.category === 'network-copyleft' ||
        info.category === 'strong-copyleft' ||
        info.category === 'proprietary'
      ) {
        findings.push({
          ruleId: `license-${info.category}`,
          title: `${dependency.name} is licensed under ${info.name}`,
          description: `${info.obligation} This is a legal-review signal, not legal advice — confirm with counsel how it applies to your distribution model.`,
          severity: SEVERITY_BY_CATEGORY[info.category],
          kind: 'license',
          confidence: declared ? 'high' : 'low',
          location: { path: dependency.path, startLine: 1 },
          component: {
            name: dependency.name,
            version: dependency.version,
            purl: dependency.purl,
            ecosystem: dependency.ecosystem,
            licenses: [info.id],
            scope: dependency.scope,
            dependencyType: dependency.dependencyType,
          },
          taxonomy: {
            references: [
              { title: `SPDX: ${info.id}`, url: `https://spdx.org/licenses/${info.id}.html` },
            ],
          },
          metadata: { licenseId: info.id, category: info.category, obligation: info.obligation },
          remediationHint:
            info.category === 'network-copyleft'
              ? 'Replace the package, obtain a commercial licence, or accept the source-release obligation for your service.'
              : 'Confirm the obligation is compatible with how you distribute this product.',
        });
      }
    }

    const unknown = byCategory.get('unknown') ?? [];
    if (unknown.length) {
      findings.push({
        ruleId: 'license-unknown',
        title: `${unknown.length} dependencies have an unknown or unrecognized license`,
        description:
          'These packages did not declare a license Sentinel recognizes. An undeclared license means no rights are granted by default, so each one needs manual review.',
        severity: 'low',
        kind: 'license',
        confidence: 'medium',
        location: { path: dependencies[0]!.path, startLine: 1 },
        metadata: { packages: unknown.slice(0, 50) },
        remediationHint:
          'Check each package repository for its licence and record the result in your inventory.',
      });
    }

    return findings;
  },
};
