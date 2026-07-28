import type { ScanKind } from '@sentinel/core';
import { nativeSastScanner } from './native/sast.js';
import { nativeSecretsScanner } from './native/secrets.js';
import { nativeAiSecurityScanner } from './native/ai-security.js';
import {
  nativeConfigScanner,
  nativeContainerScanner,
  nativeIacScanner,
} from './native/infrastructure.js';
import { nativeDependencyScanner } from './native/dependencies.js';
import { nativeLicenseScanner } from './native/license.js';
import { nativeSbomScanner } from './native/sbom.js';
import { semgrepScanner } from './external/semgrep.js';
import { gitleaksScanner } from './external/gitleaks.js';
import { trivyScanner } from './external/trivy.js';
import {
  checkovScanner,
  hadolintScanner,
  osvScannerScanner,
  syftScanner,
} from './external/misc.js';
import type { ScanContext, Scanner, ScannerAvailability } from './types.js';

/**
 * Scanner registry.
 *
 * The registry is the plugin seam: a new scanner is a `Scanner` object passed to
 * `register`, and it immediately participates in selection, availability
 * reporting, scoring and export with no other changes.
 */

const registry = new Map<string, Scanner>();

export function register(scanner: Scanner): void {
  if (registry.has(scanner.id)) {
    throw new Error(`Scanner "${scanner.id}" is already registered`);
  }
  registry.set(scanner.id, scanner);
}

export function unregister(id: string): boolean {
  return registry.delete(id);
}

export function getScanner(id: string): Scanner | undefined {
  return registry.get(id);
}

export function allScanners(): Scanner[] {
  return [...registry.values()];
}

/** Built-in scanners, registered on module load. */
const BUILT_IN: Scanner[] = [
  // Native — always available, zero dependencies.
  nativeSastScanner,
  nativeSecretsScanner,
  nativeAiSecurityScanner,
  nativeDependencyScanner,
  nativeContainerScanner,
  nativeIacScanner,
  nativeConfigScanner,
  nativeLicenseScanner,
  nativeSbomScanner,
  // External — used when the binary is on PATH.
  semgrepScanner,
  gitleaksScanner,
  trivyScanner,
  osvScannerScanner,
  checkovScanner,
  hadolintScanner,
  syftScanner,
];

for (const scanner of BUILT_IN) register(scanner);

export interface SelectedScanner {
  scanner: Scanner;
  availability: ScannerAvailability;
}

export interface SelectionResult {
  /** Scanners that will run. */
  selected: SelectedScanner[];
  /** Scanners that will not, with the reason — never silently dropped. */
  skipped: { scanner: Scanner; reason: string }[];
}

/**
 * Choose which scanners run for this scan.
 *
 * The rule that matters: when a best-in-class external tool is installed and
 * declares it `supersedes` a bundled one, the bundled one stands down. That is
 * how we integrate rather than reinvent — but coverage never drops to zero,
 * because the native scanner takes over again the moment the binary is absent.
 */
export async function selectScanners(
  ctx: ScanContext,
  options: { kinds?: ScanKind[]; preferExternal?: boolean } = {},
): Promise<SelectionResult> {
  const requestedKinds = options.kinds?.length ? new Set(options.kinds) : undefined;
  const preferExternal = options.preferExternal ?? true;

  const candidates = allScanners().filter(
    (scanner) => !requestedKinds || requestedKinds.has(scanner.kind),
  );

  const availabilities = await Promise.all(
    candidates.map(async (scanner) => {
      try {
        return { scanner, availability: await scanner.isAvailable(ctx) };
      } catch (error) {
        return {
          scanner,
          availability: { available: false, reason: `Availability check failed: ${String(error)}` },
        };
      }
    }),
  );

  const availableIds = new Set(
    availabilities.filter((entry) => entry.availability.available).map((entry) => entry.scanner.id),
  );

  // Any native scanner named in an available external scanner's `supersedes`.
  const superseded = new Set<string>();
  if (preferExternal) {
    for (const { scanner, availability } of availabilities) {
      if (!availability.available || scanner.origin !== 'external') continue;
      for (const id of scanner.supersedes ?? []) {
        if (availableIds.has(id)) superseded.add(id);
      }
    }
  }

  const selected: SelectedScanner[] = [];
  const skipped: SelectionResult['skipped'] = [];

  for (const { scanner, availability } of availabilities) {
    if (!availability.available) {
      skipped.push({ scanner, reason: availability.reason ?? 'Scanner is unavailable' });
      continue;
    }
    if (superseded.has(scanner.id)) {
      const replacement = availabilities.find(
        (entry) => entry.availability.available && entry.scanner.supersedes?.includes(scanner.id),
      );
      skipped.push({
        scanner,
        reason: `Superseded by ${replacement?.scanner.name ?? 'an external scanner'}, which is installed and covers the same analysis`,
      });
      continue;
    }
    selected.push({ scanner, availability });
  }

  ctx.logger.info('Scanner selection complete', {
    selected: selected.map((s) => s.scanner.id),
    skipped: skipped.length,
  });

  return { selected, skipped };
}

/** Report which external tools are present, for the settings UI. */
export async function scannerCatalog(ctx: ScanContext): Promise<
  {
    id: string;
    name: string;
    kind: ScanKind;
    origin: string;
    description: string;
    availability: ScannerAvailability;
  }[]
> {
  return Promise.all(
    allScanners().map(async (scanner) => ({
      id: scanner.id,
      name: scanner.name,
      kind: scanner.kind,
      origin: scanner.origin,
      description: scanner.description,
      availability: await scanner
        .isAvailable(ctx)
        .catch(() => ({ available: false, reason: 'probe failed' })),
    })),
  );
}
