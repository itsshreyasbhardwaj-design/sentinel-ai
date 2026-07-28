import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import {
  SEVERITIES,
  createLogger,
  isAtLeast,
  silentLogger,
  type ScanKind,
  type ScanResult,
  type ScanTarget,
  type Severity,
} from '@sentinel/core';
import { runScan, scannerCatalog, type ScanContext } from '@sentinel/scanners';
import { createAnalyst, enrichScanResult, type EnrichedScan } from '@sentinel/ai';
import { EXPORT_FORMATS, exportReport, type ExportFormat } from '@sentinel/reports';

/**
 * Command-line interface.
 *
 * The CLI is the primary way Sentinel runs in CI, so it has to work with no
 * services configured, exit with a meaningful code, and print something a human
 * can act on without opening a dashboard.
 */

const C = {
  reset: '[0m',
  bold: '[1m',
  dim: '[2m',
  red: '[31m',
  green: '[32m',
  yellow: '[33m',
  blue: '[34m',
  magenta: '[35m',
  cyan: '[36m',
  grey: '[90m',
};

/** Respect NO_COLOR and non-TTY output, as every well-behaved CLI should. */
const useColor = process.stdout.isTTY && !process.env['NO_COLOR'];
const c = (code: string, text: string) => (useColor ? `${code}${text}${C.reset}` : text);

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: C.red,
  high: C.magenta,
  medium: C.yellow,
  low: C.blue,
  info: C.grey,
};

export interface CliOptions {
  target: ScanTarget;
  kinds?: ScanKind[];
  formats: ExportFormat[];
  outputDir?: string;
  failOn?: Severity;
  allowNetwork: boolean;
  explain: boolean;
  minSeverity?: Severity;
  quiet: boolean;
  json: boolean;
  maxFindings: number;
  concurrency?: number;
  listScanners: boolean;
}

export const HELP = `
${c(C.bold, 'sentinel')} — AI-native application security scanning

${c(C.bold, 'USAGE')}
  sentinel <path|owner/repo|archive.zip> [options]

${c(C.bold, 'OPTIONS')}
  --kinds <list>        Analysis domains to run (comma separated).
                        sast, dependencies, secrets, container, iac, license, sbom, config, ai-security
  --format <list>       Export formats: ${EXPORT_FORMATS.join(', ')}
  --output <dir>        Directory to write reports into
  --fail-on <severity>  Exit non-zero when a finding at or above this severity exists
  --min-severity <sev>  Only report findings at or above this severity
  --explain             Generate AI explanations (default: on)
  --no-explain          Skip explanations for a faster scan
  --network             Allow scanners to query OSV.dev for live advisories
  --concurrency <n>     File analysis concurrency (default: 8)
  --max-findings <n>    Cap findings included in reports (default: 100)
  --ref <ref>           Git ref to scan for a GitHub target
  --token <token>       GitHub token for private repositories
  --list-scanners       Show which scanners are available on this machine
  --json                Emit machine-readable JSON to stdout
  --quiet               Suppress progress output
  -h, --help            Show this help

${c(C.bold, 'EXAMPLES')}
  sentinel .
  sentinel . --fail-on high --format sarif --output ./reports
  sentinel acme/web --ref main --token "$GITHUB_TOKEN"
  sentinel ./upload.zip --kinds secrets,dependencies
  sentinel . --network --format html,pdf --output ./reports

${c(C.bold, 'EXIT CODES')}
  0  scan completed and the failure threshold was not met
  1  findings at or above --fail-on were detected
  2  the scan itself failed
`;

function parseList<T extends string>(
  value: string | undefined,
  valid: readonly T[],
): T[] | undefined {
  if (!value) return undefined;
  const items = value
    .split(',')
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);

  const invalid = items.filter((item) => !(valid as readonly string[]).includes(item));
  if (invalid.length) {
    throw new Error(`Unknown value(s): ${invalid.join(', ')}. Valid: ${valid.join(', ')}`);
  }
  return items as T[];
}

/**
 * Interpret the positional argument.
 *
 * `owner/repo` is only treated as GitHub when it is not also a path that
 * exists on disk — a local directory literally named `foo/bar` must win, or
 * scanning a subdirectory silently hits the network instead.
 */
export async function resolveTarget(
  input: string,
  ref?: string,
  token?: string,
): Promise<ScanTarget> {
  const { stat } = await import('node:fs/promises');
  const exists = await stat(input).then(
    (info) => ({ isDirectory: info.isDirectory(), isFile: info.isFile() }),
    () => null,
  );

  if (exists?.isDirectory) {
    return { type: 'local', path: resolve(input), ...(ref ? { ref } : {}) };
  }
  if (exists?.isFile && /\.zip$/i.test(input)) {
    return { type: 'archive', archivePath: resolve(input), originalName: input.split('/').pop() };
  }

  const githubMatch =
    /^(?:https:\/\/github\.com\/)?([A-Za-z0-9][\w.-]*)\/([\w.-]+?)(?:\.git)?$/.exec(input);
  if (githubMatch) {
    return {
      type: 'github',
      owner: githubMatch[1]!,
      repo: githubMatch[2]!,
      ...(ref ? { ref } : {}),
      ...(token ? { token } : {}),
    };
  }

  throw new Error(
    `Cannot interpret "${input}" as a directory, a .zip archive, or an owner/repo reference.`,
  );
}

export async function parseArgs(argv: readonly string[]): Promise<CliOptions | 'help'> {
  const args = [...argv];
  if (!args.length || args.includes('--help') || args.includes('-h')) return 'help';

  const flag = (name: string): string | undefined => {
    const index = args.indexOf(name);
    if (index === -1) return undefined;
    const value = args[index + 1];
    if (value === undefined || value.startsWith('--')) {
      throw new Error(`${name} requires a value`);
    }
    args.splice(index, 2);
    return value;
  };
  const bool = (name: string): boolean => {
    const index = args.indexOf(name);
    if (index === -1) return false;
    args.splice(index, 1);
    return true;
  };

  const ref = flag('--ref');
  const token = flag('--token') ?? process.env['GITHUB_TOKEN'];
  const kinds = parseList(flag('--kinds'), [
    'sast',
    'dependencies',
    'secrets',
    'container',
    'iac',
    'license',
    'sbom',
    'config',
    'ai-security',
  ] as const);
  const formats = parseList(flag('--format'), EXPORT_FORMATS) ?? [];
  const outputDir = flag('--output');
  const failOn = parseList(flag('--fail-on'), SEVERITIES)?.[0];
  const minSeverity = parseList(flag('--min-severity'), SEVERITIES)?.[0];
  const concurrency = flag('--concurrency');
  const maxFindings = flag('--max-findings');

  const listScanners = bool('--list-scanners');
  const allowNetwork = bool('--network');
  const noExplain = bool('--no-explain');
  const explicitExplain = bool('--explain');
  const quiet = bool('--quiet');
  const json = bool('--json');

  const positional = args.filter((arg) => !arg.startsWith('-'));
  const input = positional[0] ?? '.';

  if (formats.length && !outputDir) {
    throw new Error('--format requires --output to say where reports should be written');
  }

  return {
    target: await resolveTarget(input, ref, token),
    ...(kinds ? { kinds } : {}),
    formats,
    ...(outputDir ? { outputDir } : {}),
    ...(failOn ? { failOn } : {}),
    ...(minSeverity ? { minSeverity } : {}),
    allowNetwork,
    explain: explicitExplain || !noExplain,
    quiet: quiet || json,
    json,
    maxFindings: maxFindings ? Number(maxFindings) : 100,
    ...(concurrency ? { concurrency: Number(concurrency) } : {}),
    listScanners,
  };
}

function bar(score: number, width = 24): string {
  const filled = Math.round((score / 100) * width);
  const color = score >= 80 ? C.green : score >= 60 ? C.yellow : C.red;
  return c(color, '█'.repeat(filled)) + c(C.grey, '░'.repeat(Math.max(0, width - filled)));
}

export function renderSummary(scan: EnrichedScan, options: CliOptions): string {
  const { result, summary, priorities } = scan;
  const out: string[] = [''];

  if (result.status === 'failed') {
    out.push(c(C.red, `✗ Scan failed: ${result.error ?? 'unknown error'}`), '');
    return out.join('\n');
  }

  const priorityById = new Map(priorities.map((p) => [p.findingId, p]));
  const gradeColor =
    result.scores.grade === 'A' || result.scores.grade === 'B'
      ? C.green
      : result.scores.grade === 'C'
        ? C.yellow
        : C.red;

  out.push(c(C.bold, `  ${result.repository.name}`));
  out.push(
    c(
      C.grey,
      `  ${result.repository.fileCount} files · ${result.repository.languages
        .slice(0, 4)
        .map((l) => `${l.language} ${l.percent}%`)
        .join(' · ')} · ${(result.durationMs / 1000).toFixed(1)}s`,
    ),
  );
  out.push('');
  out.push(
    `  ${bar(result.scores.overall)}  ${c(C.bold, String(result.scores.overall))}${c(C.grey, '/100')}  ${c(gradeColor, `Grade ${result.scores.grade}`)}  ${c(C.grey, result.scores.riskLevel)}`,
  );
  out.push('');

  /* Severity counts */
  const counts = result.scores.counts;
  const chips = (['critical', 'high', 'medium', 'low', 'info'] as const)
    .filter((s) => counts[s] > 0)
    .map((s) => c(SEVERITY_COLOR[s], `${counts[s]} ${s}`));
  out.push(`  ${chips.length ? chips.join(c(C.grey, '  ·  ')) : c(C.green, 'No findings')}`);
  out.push('');

  /* Category scores */
  for (const category of result.scores.categories) {
    const label = category.category.padEnd(15);
    if (!category.analyzed) {
      out.push(`  ${c(C.grey, label)} ${c(C.grey, 'not analyzed')}`);
      continue;
    }
    out.push(
      `  ${label} ${bar(category.score, 16)} ${String(category.score).padStart(3)}  ${c(C.grey, category.rationale)}`,
    );
  }
  out.push('');

  /* Top findings */
  const top = [...result.findings]
    .filter((f) => !f.suppressed)
    .sort(
      (a, b) =>
        (priorityById.get(b.id)?.priorityScore ?? 0) - (priorityById.get(a.id)?.priorityScore ?? 0),
    )
    .slice(0, 10);

  if (top.length) {
    out.push(c(C.bold, `  Top findings`));
    out.push('');
    for (const finding of top) {
      const priority = priorityById.get(finding.id);
      out.push(
        `  ${c(SEVERITY_COLOR[finding.severity], finding.severity.padEnd(8))} ${finding.title.slice(0, 78)}`,
      );
      out.push(
        c(
          C.grey,
          `           ${finding.location ? `${finding.location.path}:${finding.location.startLine}` : finding.component ? `${finding.component.name}@${finding.component.version}` : ''}${priority ? `  ·  priority #${priority.rank}` : ''}`,
        ),
      );
      if (finding.explanation?.suggestedFixes[0]) {
        out.push(c(C.cyan, `           → ${finding.explanation.suggestedFixes[0].title}`));
      }
      out.push('');
    }
  }

  /* Coverage — never let a gap be silent */
  const failed = result.scannerRuns.filter((r) => r.status === 'failed');
  const skipped = result.scannerRuns.filter((r) => r.status === 'skipped');
  const ok = result.scannerRuns.filter((r) => r.status === 'ok');

  out.push(c(C.bold, '  Coverage'));
  out.push(
    c(
      C.grey,
      `  ${ok.length} scanner(s) ran · ${skipped.length} skipped · ${failed.length} failed`,
    ),
  );
  for (const run of failed) {
    out.push(c(C.red, `  ✗ ${run.scanner}: ${run.reason ?? 'unknown error'}`));
  }
  out.push('');

  if (summary.caveats.length && !options.quiet) {
    out.push(c(C.bold, '  Caveats'));
    for (const caveat of summary.caveats) out.push(c(C.grey, `  · ${caveat}`));
    out.push('');
  }

  return out.join('\n');
}

async function writeReports(scan: EnrichedScan, options: CliOptions): Promise<string[]> {
  if (!options.formats.length || !options.outputDir) return [];

  const written: string[] = [];
  await mkdir(options.outputDir, { recursive: true });

  for (const format of options.formats) {
    const report = exportReport(scan.result, format, {
      summary: scan.summary,
      priorities: scan.priorities,
      maxFindings: options.maxFindings,
      frameworks: ['owasp-top-10-2021', 'owasp-llm-top-10-2025', 'nist-ssdf-1.1'],
      ...(scan.result.repository.url
        ? {
            repoUrlBase: `${scan.result.repository.url}/blob/${scan.result.repository.ref ?? 'main'}`,
          }
        : {}),
    });

    const path = resolve(options.outputDir, report.filename);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, report.body);
    written.push(path);
  }

  return written;
}

/** Read the lines around a finding so explanations can cite real code. */
function makeContextReader(result: ScanResult, root: string) {
  const cache = new Map<string, Promise<string[]>>();

  return async (
    finding: Parameters<NonNullable<Parameters<typeof enrichScanResult>[1]['readContext']>>[0],
  ) => {
    const path = finding.location?.path;
    if (!path || result.target.type !== 'local') return undefined;

    let pending = cache.get(path);
    if (!pending) {
      pending = readFile(resolve(root, path), 'utf8')
        .then((content) => content.split('\n'))
        .catch(() => []);
      cache.set(path, pending);
    }

    const lines = await pending;
    if (!lines.length) return undefined;

    const start = Math.max(0, (finding.location?.startLine ?? 1) - 8);
    return lines.slice(start, start + 20).join('\n');
  };
}

export async function run(argv: readonly string[]): Promise<number> {
  let options: CliOptions | 'help';
  try {
    options = await parseArgs(argv);
  } catch (error) {
    process.stderr.write(`${c(C.red, 'Error:')} ${(error as Error).message}\n`);
    return 2;
  }

  if (options === 'help') {
    process.stdout.write(HELP);
    return 0;
  }

  const logger = options.quiet ? silentLogger : createLogger({ name: 'sentinel', level: 'warn' });

  /* --- Scanner catalog --- */
  if (options.listScanners) {
    const ctx = {
      scanId: 'probe',
      root: process.cwd(),
      target: options.target,
      options: { maxFiles: 0, maxFileSizeBytes: 0, concurrency: 1, allowNetwork: false },
      files: [],
      logger: silentLogger,
      readFile: async () => '',
    } as unknown as ScanContext;

    const catalog = await scannerCatalog(ctx);
    process.stdout.write(`\n${c(C.bold, '  Available scanners')}\n\n`);
    for (const entry of catalog) {
      const mark = entry.availability.available ? c(C.green, '●') : c(C.grey, '○');
      process.stdout.write(
        `  ${mark} ${entry.id.padEnd(22)} ${c(C.grey, entry.origin.padEnd(9))} ${
          entry.availability.available
            ? c(C.grey, entry.availability.version ?? 'ready')
            : c(C.grey, entry.availability.reason ?? 'unavailable')
        }\n`,
      );
    }
    process.stdout.write('\n');
    return 0;
  }

  /* --- Scan --- */
  if (!options.quiet) {
    process.stdout.write(`\n  ${c(C.cyan, '◆')} Scanning…\n`);
  }

  const result = await runScan({
    target: options.target,
    logger,
    options: {
      ...(options.kinds ? { kinds: options.kinds } : {}),
      allowNetwork: options.allowNetwork,
      ...(options.concurrency ? { concurrency: options.concurrency } : {}),
      ...(options.failOn ? { failOn: options.failOn } : {}),
    },
    // Carriage-return progress only makes sense on a terminal; in a CI log it
    // produces one unreadable concatenated line.
    ...(options.quiet || !process.stdout.isTTY
      ? {}
      : {
          onProgress: (progress) => {
            if (progress.status === 'running') {
              process.stdout.write(
                `\r  ${c(C.cyan, '◆')} ${String(progress.percent).padStart(3)}%  ${(progress.message ?? progress.phase).slice(0, 60).padEnd(62)}`,
              );
            }
          },
        }),
  });

  if (!options.quiet && process.stdout.isTTY) process.stdout.write(`\r${' '.repeat(80)}\r`);

  /* --- Enrich --- */
  const analyst = createAnalyst({ logger });
  const scan = await enrichScanResult(result, {
    analyst,
    logger,
    maxExplanations: options.explain ? 50 : 0,
    ...(options.minSeverity ? { minSeverity: options.minSeverity } : {}),
    ...(result.target.type === 'local'
      ? { readContext: makeContextReader(result, result.target.path) }
      : {}),
  });

  /* --- Output --- */
  const written = await writeReports(scan, options);

  if (options.json) {
    process.stdout.write(
      `${JSON.stringify(
        {
          scan: {
            id: scan.result.id,
            status: scan.result.status,
            scores: scan.result.scores,
            findingCount: scan.result.findings.length,
          },
          summary: scan.summary,
          reports: written,
        },
        null,
        2,
      )}\n`,
    );
  } else {
    process.stdout.write(renderSummary(scan, options));
    if (written.length) {
      process.stdout.write(c(C.bold, '  Reports\n'));
      for (const path of written) process.stdout.write(c(C.grey, `  · ${path}\n`));
      process.stdout.write('\n');
    }
  }

  /* --- Exit code --- */
  if (result.status === 'failed') return 2;
  if (options.failOn) {
    const breaching = result.findings.filter(
      (finding) => !finding.suppressed && isAtLeast(finding.severity, options.failOn!),
    );
    if (breaching.length) {
      if (!options.quiet) {
        process.stderr.write(
          `${c(C.red, `✗ ${breaching.length} finding(s) at or above ${options.failOn}`)}\n\n`,
        );
      }
      return 1;
    }
  }

  return 0;
}
