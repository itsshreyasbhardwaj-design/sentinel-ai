/**
 * Canonical domain model for Sentinel AI.
 *
 * Every scanner — native or third-party — is normalized into these shapes so the
 * rest of the platform (scoring, AI analysis, compliance, export) never has to
 * know which tool produced a finding.
 */

/** Ordered from least to most urgent. The order is load-bearing: see `severityRank`. */
export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;
export type Severity = (typeof SEVERITIES)[number];

/**
 * Analysis domains. Each maps to one dimension of the repository health score.
 */
export const SCAN_KINDS = [
  'sast',
  'dependencies',
  'secrets',
  'container',
  'iac',
  'license',
  'sbom',
  'config',
  'ai-security',
] as const;
export type ScanKind = (typeof SCAN_KINDS)[number];

export const SCORE_CATEGORIES = [
  'code',
  'dependencies',
  'infrastructure',
  'secrets',
  'aiSafety',
  'configuration',
] as const;
export type ScoreCategory = (typeof SCORE_CATEGORIES)[number];

export const LANGUAGES = [
  'typescript',
  'javascript',
  'python',
  'java',
  'go',
  'rust',
  'csharp',
  'php',
  'ruby',
  'other',
] as const;
export type Language = (typeof LANGUAGES)[number];

export type FindingStatus = 'open' | 'triaged' | 'fixed' | 'accepted-risk' | 'false-positive';

export type Confidence = 'low' | 'medium' | 'high';

/** A precise pointer into source code. */
export interface CodeLocation {
  /** Repository-relative POSIX path. Never absolute — absolute paths leak host layout. */
  path: string;
  startLine: number;
  endLine?: number;
  startColumn?: number;
  endColumn?: number;
  /** The offending line(s), trimmed and secret-redacted. */
  snippet?: string;
  /** Lines immediately before/after `snippet`, for UI context. */
  contextBefore?: string[];
  contextAfter?: string[];
}

/** External standards a finding maps to. Drives the compliance engine. */
export interface Taxonomy {
  /** e.g. `CWE-89` */
  cwe?: string[];
  /** e.g. `A03:2021-Injection` */
  owaspTop10?: string[];
  /** e.g. `LLM01:2025-Prompt Injection` */
  owaspLlmTop10?: string[];
  /** e.g. `CVE-2024-1234` / `GHSA-xxxx` */
  cve?: string[];
  /** Free-form references (docs, advisories, standards). */
  references?: Reference[];
}

export interface Reference {
  title: string;
  url: string;
}

/**
 * What a scanner emits. Deliberately loose — the normalizer fills in the rest.
 */
export interface RawFinding {
  ruleId: string;
  title: string;
  description?: string;
  severity: Severity;
  kind: ScanKind;
  location?: CodeLocation;
  taxonomy?: Taxonomy;
  confidence?: Confidence;
  /** Scanner-specific extras preserved for debugging and export fidelity. */
  metadata?: Record<string, unknown>;
  /** Package coordinates when the finding is about a dependency. */
  component?: ComponentRef;
  remediationHint?: string;
}

export interface ComponentRef {
  name: string;
  version?: string;
  /** Package URL, e.g. `pkg:npm/lodash@4.17.20`. */
  purl?: string;
  ecosystem?: string;
  /** Whether the package is a direct or transitive dependency. */
  scope?: 'direct' | 'transitive';
  /** Dependency type from the manifest. */
  dependencyType?: 'runtime' | 'development' | 'optional' | 'peer';
  licenses?: string[];
  path?: string;
}

/** AI-generated (or knowledge-base-generated) narrative attached to a finding. */
export interface FindingExplanation {
  /** Non-specialist summary. */
  plainEnglish: string;
  businessImpact: string;
  technicalImpact: string;
  /** Mechanism: how the flaw actually arises in this code. */
  howItHappens: string;
  suggestedFixes: SuggestedFix[];
  /** 0..1. Reflects analyzer certainty, not exploit likelihood. */
  confidenceScore: number;
  /** Which analyzer produced this narrative. */
  provider: string;
  model?: string;
  generatedAt: string;
}

export interface SuggestedFix {
  title: string;
  description: string;
  /** Language identifier for syntax highlighting. */
  language?: string;
  /** Illustrative safer implementation. */
  code?: string;
  /** Unified diff when the fix is mechanically derivable. */
  patch?: string;
  kind: 'code' | 'configuration' | 'dependency-upgrade' | 'migration' | 'process';
  effort: 'trivial' | 'small' | 'medium' | 'large';
  /** True when the patch can be applied without human judgement. */
  autoApplicable: boolean;
}

/** A fully normalized, deduplicated, enriched finding. */
export interface Finding extends RawFinding {
  /** Stable across scans of the same issue — used for trend and diffing. */
  id: string;
  fingerprint: string;
  scanId: string;
  /** Which scanner adapter produced it. */
  scanner: string;
  /** Was this produced by a bundled scanner or an external binary? */
  scannerKind: 'native' | 'external';
  confidence: Confidence;
  status: FindingStatus;
  /** Computed 0..100. Blends severity, confidence, reachability and context. */
  riskScore: number;
  explanation?: FindingExplanation;
  firstSeenAt: string;
  lastSeenAt: string;
  /** Set when a suppression rule matched. */
  suppressed?: boolean;
  suppressionReason?: string;
}

/* ------------------------------------------------------------------ */
/* Targets                                                             */
/* ------------------------------------------------------------------ */

export type ScanTarget =
  | { type: 'local'; path: string; ref?: string }
  | { type: 'github'; owner: string; repo: string; ref?: string; token?: string }
  | { type: 'archive'; archivePath: string; originalName?: string };

export interface ScanOptions {
  /** Restrict to these analysis domains. Defaults to all. */
  kinds?: ScanKind[];
  /** Glob patterns to exclude, merged with sensible defaults. */
  exclude?: string[];
  include?: string[];
  /** Hard ceiling on files analyzed. Protects against pathological repos. */
  maxFiles?: number;
  /** Skip files above this size (bytes). Minified bundles are noise. */
  maxFileSizeBytes?: number;
  /** Run AI explanation over findings. */
  explain?: boolean;
  /** Only explain findings at or above this severity — controls token spend. */
  explainMinSeverity?: Severity;
  /** Allow scanners to reach the network (e.g. OSV.dev advisory lookups). */
  allowNetwork?: boolean;
  /** Prefer external binaries when present. */
  preferExternalScanners?: boolean;
  /** Reuse cached scanner output where the file digest is unchanged. */
  incremental?: boolean;
  /** Concurrency for file-level analysis. */
  concurrency?: number;
  /** Fail the run when findings at/above this severity exist (CI gate). */
  failOn?: Severity;
  timeoutMs?: number;
}

export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';

export interface ScanProgress {
  scanId: string;
  status: ScanStatus;
  /** 0..100 */
  percent: number;
  phase: string;
  message?: string;
  completedScanners: string[];
  totalScanners: number;
  findingsSoFar: number;
  startedAt: string;
  updatedAt: string;
}

export interface RepositoryInfo {
  name: string;
  /** Present for github/local-git targets. */
  url?: string;
  ref?: string;
  commit?: string;
  defaultBranch?: string;
  languages: LanguageBreakdown[];
  fileCount: number;
  totalBytes: number;
  linesOfCode: number;
}

export interface LanguageBreakdown {
  language: Language;
  files: number;
  bytes: number;
  /** 0..100 */
  percent: number;
}

export interface ScannerRun {
  scanner: string;
  kind: ScanKind;
  scannerKind: 'native' | 'external';
  status: 'ok' | 'skipped' | 'failed';
  durationMs: number;
  findingCount: number;
  /** Why a scanner was skipped — surfaced in the UI so gaps are never silent. */
  reason?: string;
  version?: string;
}

export interface ScanResult {
  id: string;
  projectId: string;
  status: ScanStatus;
  target: ScanTarget;
  options: ScanOptions;
  repository: RepositoryInfo;
  findings: Finding[];
  scannerRuns: ScannerRun[];
  scores: HealthScores;
  sbom?: Sbom;
  startedAt: string;
  completedAt?: string;
  durationMs: number;
  error?: string;
  /** Deltas versus the previous scan of the same project. */
  diff?: ScanDiff;
}

export interface ScanDiff {
  previousScanId: string;
  introduced: string[];
  resolved: string[];
  unchanged: number;
  scoreDelta: number;
}

/* ------------------------------------------------------------------ */
/* Scoring                                                             */
/* ------------------------------------------------------------------ */

export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';

export interface CategoryScore {
  category: ScoreCategory;
  /** 0..100, higher is safer. */
  score: number;
  grade: Grade;
  findingCount: number;
  counts: SeverityCounts;
  /** Null when the category was not analyzed in this scan. */
  analyzed: boolean;
  /** Short human explanation of what pulled the score down. */
  rationale: string;
}

export type SeverityCounts = Record<Severity, number>;

export interface HealthScores {
  overall: number;
  grade: Grade;
  riskLevel: 'minimal' | 'low' | 'moderate' | 'elevated' | 'severe';
  categories: CategoryScore[];
  counts: SeverityCounts;
  totalFindings: number;
  computedAt: string;
}

export interface ScoreHistoryPoint {
  scanId: string;
  timestamp: string;
  overall: number;
  categories: Record<ScoreCategory, number>;
  counts: SeverityCounts;
}

/* ------------------------------------------------------------------ */
/* SBOM                                                                */
/* ------------------------------------------------------------------ */

export interface Sbom {
  format: 'cyclonedx-1.5';
  specVersion: string;
  serialNumber: string;
  generatedAt: string;
  components: SbomComponent[];
  dependencies: SbomDependency[];
}

export interface SbomComponent {
  'bom-ref': string;
  type: 'library' | 'application' | 'framework';
  name: string;
  version: string;
  purl?: string;
  licenses?: { license: { id?: string; name?: string } }[];
  scope?: 'required' | 'optional' | 'excluded';
  properties?: { name: string; value: string }[];
}

export interface SbomDependency {
  ref: string;
  dependsOn: string[];
}

/* ------------------------------------------------------------------ */
/* Compliance                                                          */
/* ------------------------------------------------------------------ */

export interface ComplianceControl {
  id: string;
  title: string;
  description: string;
  /** Rule ids / taxonomy tags that satisfy or violate this control. */
  mappedTaxonomy: string[];
}

export interface ComplianceFramework {
  id: string;
  name: string;
  version: string;
  description: string;
  url?: string;
  controls: ComplianceControl[];
}

export interface ControlAssessment {
  controlId: string;
  title: string;
  status: 'pass' | 'fail' | 'not-applicable' | 'needs-review';
  findingIds: string[];
  /** Highest severity among mapped findings. */
  worstSeverity?: Severity;
  evidence: string;
}

export interface ComplianceReport {
  frameworkId: string;
  frameworkName: string;
  frameworkVersion: string;
  scanId: string;
  generatedAt: string;
  /** 0..100 share of applicable controls passing. */
  coveragePercent: number;
  passed: number;
  failed: number;
  notApplicable: number;
  needsReview: number;
  assessments: ControlAssessment[];
}

/* ------------------------------------------------------------------ */
/* Projects                                                            */
/* ------------------------------------------------------------------ */

export interface Project {
  id: string;
  name: string;
  slug: string;
  ownerId: string;
  target: ScanTarget;
  description?: string;
  createdAt: string;
  updatedAt: string;
  lastScanId?: string;
  defaultOptions?: ScanOptions;
}

export interface ProjectSummary extends Project {
  latestScores?: HealthScores;
  openFindings: number;
  criticalFindings: number;
  lastScannedAt?: string;
  trend: ScoreHistoryPoint[];
}
