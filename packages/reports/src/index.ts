import { errors, type ScanResult } from '@sentinel/core';
import type { ExecutiveSummary, PrioritizedFinding } from '@sentinel/ai';
import { toSarif } from './sarif.js';
import { toMarkdown, toPullRequestComment } from './markdown.js';
import { toHtml } from './html.js';
import { toCsv, toJson, toStatistics } from './tabular.js';
import { toPdf } from './pdf.js';

export * from './sarif.js';
export * from './markdown.js';
export * from './html.js';
export * from './tabular.js';
export * from './pdf.js';

export type ExportFormat = 'json' | 'csv' | 'markdown' | 'html' | 'sarif' | 'pdf';

export interface ExportOptions {
  summary?: ExecutiveSummary;
  priorities?: PrioritizedFinding[];
  frameworks?: string[];
  maxFindings?: number;
  repoUrlBase?: string;
}

export interface ExportedReport {
  format: ExportFormat;
  contentType: string;
  filename: string;
  body: string | Buffer;
}

const CONTENT_TYPE: Record<ExportFormat, string> = {
  json: 'application/json; charset=utf-8',
  csv: 'text/csv; charset=utf-8',
  markdown: 'text/markdown; charset=utf-8',
  html: 'text/html; charset=utf-8',
  // The SARIF media type registered with GitHub code scanning.
  sarif: 'application/sarif+json; charset=utf-8',
  pdf: 'application/pdf',
};

const EXTENSION: Record<ExportFormat, string> = {
  json: 'json',
  csv: 'csv',
  markdown: 'md',
  html: 'html',
  sarif: 'sarif',
  pdf: 'pdf',
};

/**
 * Filenames reach a `Content-Disposition` header and may be written to disk by
 * the client, so the repository name — which for an archive upload is entirely
 * attacker-supplied — is reduced to a conservative character set. Dot runs are
 * collapsed as well as slashes: `..` in a download filename is a traversal
 * primitive on some clients.
 */
function safeFilename(result: ScanResult, format: ExportFormat): string {
  const name =
    result.repository.name
      .replace(/[^a-zA-Z0-9._-]+/g, '-')
      .replace(/\.{2,}/g, '-')
      .replace(/^[-.]+|[-.]+$/g, '')
      .slice(0, 64) || 'report';
  const date = (result.completedAt ?? result.startedAt).slice(0, 10);
  return `sentinel-${name}-${date}.${EXTENSION[format]}`;
}

/**
 * Render a scan result in the requested format.
 *
 * One entry point so the API route, the CLI and the GitHub integration all
 * produce byte-identical output for the same input.
 */
export function exportReport(
  result: ScanResult,
  format: ExportFormat,
  options: ExportOptions = {},
): ExportedReport {
  const base = {
    format,
    contentType: CONTENT_TYPE[format],
    filename: safeFilename(result, format),
  };

  switch (format) {
    case 'json':
      return {
        ...base,
        body: toJson(result, {
          ...(options.summary ? { summary: options.summary } : {}),
          ...(options.priorities ? { priorities: options.priorities } : {}),
        }),
      };
    case 'sarif':
      return { ...base, body: JSON.stringify(toSarif(result), null, 2) };
    case 'csv':
      return { ...base, body: toCsv(result, options.priorities ?? []) };
    case 'markdown':
      return { ...base, body: toMarkdown(result, options) };
    case 'html':
      return { ...base, body: toHtml(result, options) };
    case 'pdf':
      return { ...base, body: toPdf(result, options) };
    default:
      throw errors.validation(`Unsupported export format: ${String(format)}`);
  }
}

export const EXPORT_FORMATS: ExportFormat[] = ['json', 'sarif', 'csv', 'markdown', 'html', 'pdf'];

export { toStatistics, toPullRequestComment };
