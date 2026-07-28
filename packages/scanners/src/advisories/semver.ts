/**
 * Just enough semantic versioning to decide "is this installed version inside
 * the vulnerable range?".
 *
 * A full semver implementation is not needed and would be a liability: advisory
 * ranges are simple interval expressions, and the failure mode we care about is
 * *silently deciding a vulnerable version is safe*. Every ambiguous case here
 * therefore resolves toward reporting rather than skipping.
 */

export interface ParsedVersion {
  major: number;
  minor: number;
  patch: number;
  /** Pre-release identifiers, e.g. `["beta", 1]` for `1.0.0-beta.1`. */
  prerelease: (string | number)[];
  raw: string;
}

export function parseVersion(input: string): ParsedVersion | undefined {
  const cleaned = input.trim().replace(/^[v=\s]+/, '');
  const match = /^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-.]([0-9A-Za-z.-]+))?/.exec(cleaned);
  if (!match) return undefined;

  const prerelease = (match[4] ?? '')
    .split('.')
    .filter(Boolean)
    .map((part) => (/^\d+$/.test(part) ? Number(part) : part));

  return {
    major: Number(match[1]),
    minor: Number(match[2] ?? 0),
    patch: Number(match[3] ?? 0),
    prerelease,
    raw: cleaned,
  };
}

/** Returns <0, 0 or >0 in the manner of a comparator. */
export function compareVersions(a: ParsedVersion, b: ParsedVersion): number {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  if (a.patch !== b.patch) return a.patch - b.patch;

  // A version with a pre-release tag sorts *before* the same version without one.
  if (a.prerelease.length && !b.prerelease.length) return -1;
  if (!a.prerelease.length && b.prerelease.length) return 1;

  for (let i = 0; i < Math.max(a.prerelease.length, b.prerelease.length); i += 1) {
    const left = a.prerelease[i];
    const right = b.prerelease[i];
    if (left === undefined) return -1;
    if (right === undefined) return 1;
    if (left === right) continue;
    if (typeof left === 'number' && typeof right === 'number') return left - right;
    return String(left).localeCompare(String(right));
  }

  return 0;
}

export function compareVersionStrings(a: string, b: string): number {
  const left = parseVersion(a);
  const right = parseVersion(b);
  if (!left || !right) return a.localeCompare(b);
  return compareVersions(left, right);
}

/**
 * A vulnerable-range expression, e.g. `>=4.0.0 <4.17.21` or `<1.2.3`.
 * Space-separated clauses are ANDed; `||` separates ORed groups.
 */
export function satisfiesRange(version: string, range: string): boolean {
  const parsed = parseVersion(version);
  if (!parsed) return false;

  return range.split('||').some((group) =>
    group
      .trim()
      .split(/\s+/)
      .filter(Boolean)
      .every((clause) => satisfiesClause(parsed, clause)),
  );
}

function satisfiesClause(version: ParsedVersion, clause: string): boolean {
  const match = /^(>=|<=|>|<|=|==)?\s*(.+)$/.exec(clause.trim());
  if (!match) return false;

  const operator = match[1] ?? '=';
  const target = parseVersion(match[2]!);
  if (!target) return false;

  const cmp = compareVersions(version, target);
  switch (operator) {
    case '>':
      return cmp > 0;
    case '>=':
      return cmp >= 0;
    case '<':
      return cmp < 0;
    case '<=':
      return cmp <= 0;
    default:
      return cmp === 0;
  }
}

/**
 * OSV expresses ranges as introduced/fixed event pairs. Translate that into our
 * clause syntax so both sources share one matcher.
 */
export function osvRangeToExpression(
  events: { introduced?: string; fixed?: string; last_affected?: string }[],
): string {
  const clauses: string[] = [];
  let introduced: string | undefined;

  for (const event of events) {
    if (event.introduced !== undefined) {
      introduced = event.introduced === '0' ? '0.0.0' : event.introduced;
    }
    if (event.fixed !== undefined && introduced !== undefined) {
      clauses.push(`>=${introduced} <${event.fixed}`);
      introduced = undefined;
    } else if (event.last_affected !== undefined && introduced !== undefined) {
      clauses.push(`>=${introduced} <=${event.last_affected}`);
      introduced = undefined;
    }
  }

  // An `introduced` with no matching `fixed` means everything from there on is
  // still affected.
  if (introduced !== undefined) clauses.push(`>=${introduced}`);

  return clauses.join(' || ');
}

/** The lowest version that is not vulnerable, for upgrade advice. */
export function lowestFixedVersion(fixedVersions: readonly string[]): string | undefined {
  const sorted = [...fixedVersions].filter(Boolean).sort(compareVersionStrings);
  return sorted[0];
}
