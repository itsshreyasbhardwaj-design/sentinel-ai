import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import type { Grade, ScanKind, Severity } from '@sentinel/core';

/** Merge class names, letting later Tailwind utilities win conflicts. */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

/**
 * Severity presentation.
 *
 * Colour is never the sole carrier of meaning — every severity chip also shows
 * its label, so the interface still works for colour-blind users and in
 * grayscale print.
 */
export const SEVERITY_STYLE: Record<
  Severity,
  { text: string; bg: string; border: string; dot: string }
> = {
  critical: {
    text: 'text-[var(--color-critical)]',
    bg: 'bg-[var(--color-critical)]/10',
    border: 'border-[var(--color-critical)]/30',
    dot: 'bg-[var(--color-critical)]',
  },
  high: {
    text: 'text-[var(--color-high)]',
    bg: 'bg-[var(--color-high)]/10',
    border: 'border-[var(--color-high)]/30',
    dot: 'bg-[var(--color-high)]',
  },
  medium: {
    text: 'text-[var(--color-medium)]',
    bg: 'bg-[var(--color-medium)]/10',
    border: 'border-[var(--color-medium)]/30',
    dot: 'bg-[var(--color-medium)]',
  },
  low: {
    text: 'text-[var(--color-low)]',
    bg: 'bg-[var(--color-low)]/10',
    border: 'border-[var(--color-low)]/30',
    dot: 'bg-[var(--color-low)]',
  },
  info: {
    text: 'text-[var(--color-info)]',
    bg: 'bg-[var(--color-info)]/10',
    border: 'border-[var(--color-info)]/30',
    dot: 'bg-[var(--color-info)]',
  },
};

export const GRADE_STYLE: Record<Grade, { text: string; bg: string }> = {
  A: { text: 'text-[var(--color-success)]', bg: 'bg-[var(--color-success)]' },
  B: { text: 'text-[var(--color-success)]', bg: 'bg-[var(--color-success)]' },
  C: { text: 'text-[var(--color-medium)]', bg: 'bg-[var(--color-medium)]' },
  D: { text: 'text-[var(--color-high)]', bg: 'bg-[var(--color-high)]' },
  F: { text: 'text-[var(--color-critical)]', bg: 'bg-[var(--color-critical)]' },
};

export const KIND_LABEL: Record<ScanKind, string> = {
  sast: 'Code',
  dependencies: 'Dependencies',
  secrets: 'Secrets',
  container: 'Containers',
  iac: 'Infrastructure',
  license: 'Licenses',
  sbom: 'SBOM',
  config: 'Configuration',
  'ai-security': 'AI Security',
};

export const CATEGORY_LABEL: Record<string, string> = {
  code: 'Code',
  dependencies: 'Dependencies',
  infrastructure: 'Infrastructure',
  secrets: 'Secrets',
  aiSafety: 'AI Safety',
  configuration: 'Configuration',
};

export function scoreColor(score: number): string {
  if (score >= 90) return 'var(--color-success)';
  if (score >= 80) return 'oklch(0.75 0.16 130)';
  if (score >= 65) return 'var(--color-medium)';
  if (score >= 50) return 'var(--color-high)';
  return 'var(--color-critical)';
}

/** Compact, locale-independent relative time. */
export function relativeTime(iso: string): string {
  const delta = Date.now() - new Date(iso).getTime();
  const seconds = Math.round(delta / 1000);
  if (seconds < 60) return 'just now';

  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;

  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;

  const days = Math.round(hours / 24);
  if (days < 30) return `${days}d ago`;

  const months = Math.round(days / 30);
  if (months < 12) return `${months}mo ago`;

  return `${Math.round(months / 12)}y ago`;
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  const minutes = Math.floor(ms / 60_000);
  return `${minutes}m ${Math.round((ms % 60_000) / 1000)}s`;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
}

export function formatNumber(value: number): string {
  return new Intl.NumberFormat('en-US').format(value);
}

/** Shorten a path from the left, keeping the filename readable. */
export function truncatePath(path: string, maxLength = 48): string {
  if (path.length <= maxLength) return path;
  const parts = path.split('/');
  const filename = parts.pop() ?? '';
  if (filename.length >= maxLength - 3) return `…${filename.slice(-(maxLength - 1))}`;

  let result = filename;
  for (let i = parts.length - 1; i >= 0; i -= 1) {
    const candidate = `${parts[i]}/${result}`;
    if (candidate.length > maxLength - 2) return `…/${result}`;
    result = candidate;
  }
  return result;
}
