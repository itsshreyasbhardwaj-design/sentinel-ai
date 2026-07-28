import type {
  Language,
  Logger,
  RawFinding,
  ScanKind,
  ScanOptions,
  ScanTarget,
} from '@sentinel/core';

/** A file that survived the ignore filters and is small enough to analyze. */
export interface FileEntry {
  /** Repository-relative POSIX path. */
  path: string;
  /** Absolute path on disk. Never leaves the scanner layer. */
  absolutePath: string;
  size: number;
  language: Language;
  /** Content hash, used for incremental caching. */
  digest: string;
}

/**
 * The materialized repository plus everything a scanner needs to do its job.
 * Scanners receive this and return findings; they never reach outside `root`.
 */
export interface ScanContext {
  scanId: string;
  /** Absolute path to the materialized repository. */
  root: string;
  target: ScanTarget;
  options: Required<
    Pick<ScanOptions, 'maxFiles' | 'maxFileSizeBytes' | 'concurrency' | 'allowNetwork'>
  > &
    ScanOptions;
  files: FileEntry[];
  logger: Logger;
  /** Cooperative cancellation — long scans must be abortable. */
  signal?: AbortSignal;
  /** Lazily read and memoize a file's text content. */
  readFile(entry: FileEntry): Promise<string>;
  /** Report incremental progress from inside a long-running scanner. */
  onProgress?(message: string, percent?: number): void;
}

export interface ScannerAvailability {
  available: boolean;
  /** Version string when the scanner is an external binary. */
  version?: string;
  /** Why it is unavailable — surfaced in the UI so coverage gaps are explicit. */
  reason?: string;
}

/**
 * The extension point of the whole platform.
 *
 * Adding a scanner means implementing this interface and registering it; nothing
 * else in the system needs to change.
 */
export interface Scanner {
  /** Stable identifier, e.g. `native-sast` or `semgrep`. */
  id: string;
  name: string;
  kind: ScanKind;
  /** `native` scanners ship with Sentinel; `external` shell out to a binary. */
  origin: 'native' | 'external';
  description: string;
  /** Languages the scanner understands. Empty means language-agnostic. */
  languages?: Language[];
  /**
   * When an external scanner is available and covers the same ground, the
   * native fallback with the same `supersededBy` id steps aside.
   */
  supersedes?: string[];
  isAvailable(ctx: ScanContext): Promise<ScannerAvailability>;
  scan(ctx: ScanContext): Promise<RawFinding[]>;
}

/** A single detection rule in the native pattern engine. */
export interface Rule {
  id: string;
  title: string;
  description: string;
  severity: RawFinding['severity'];
  kind: ScanKind;
  confidence?: RawFinding['confidence'];
  /** Empty means "any language". */
  languages?: Language[];
  /** Restrict to files whose path matches one of these globs. */
  pathPatterns?: string[];
  /** A match on any pattern raises the finding. */
  patterns: RegExp[];
  /** If any of these also match the same line, the finding is suppressed. */
  excludePatterns?: RegExp[];
  /**
   * Extra check with access to the whole file — used to cut false positives
   * that a single line cannot resolve (e.g. "is this value a literal?").
   */
  validate?: (match: RuleMatch) => boolean;
  taxonomy?: RawFinding['taxonomy'];
  remediationHint?: string;
}

export interface RuleMatch {
  rule: Rule;
  file: FileEntry;
  line: string;
  lineNumber: number;
  column: number;
  matchText: string;
  lines: string[];
}

export interface RegistryOptions {
  /** Prefer external binaries over the bundled equivalents. */
  preferExternal?: boolean;
  /** Only these kinds are eligible. */
  kinds?: ScanKind[];
}
