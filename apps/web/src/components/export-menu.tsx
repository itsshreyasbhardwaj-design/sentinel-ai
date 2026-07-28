'use client';

import { useState } from 'react';
import { Check, Download } from 'lucide-react';
import { cn } from '@/lib/ui';

const FORMATS = [
  { id: 'pdf', label: 'PDF report', hint: 'Formatted for sharing' },
  { id: 'html', label: 'HTML report', hint: 'Self-contained page' },
  { id: 'markdown', label: 'Markdown', hint: 'For pull requests' },
  { id: 'sarif', label: 'SARIF', hint: 'GitHub code scanning' },
  { id: 'json', label: 'JSON', hint: 'Full result' },
  { id: 'csv', label: 'CSV', hint: 'Spreadsheet triage' },
] as const;

/**
 * Export menu.
 *
 * Downloads go through a normal anchor rather than fetch-and-blob so the
 * browser handles the file, the server sets `Content-Disposition`, and large
 * PDFs never have to be held in memory on the client.
 */
export function ExportMenu({ scanId }: { scanId: string }) {
  const [open, setOpen] = useState(false);
  const [downloaded, setDownloaded] = useState<string | undefined>();

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        aria-haspopup="menu"
        className="inline-flex h-9 items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3.5 text-[13px] font-medium transition-colors hover:bg-[var(--color-surface-hover)]"
      >
        <Download className="h-3.5 w-3.5" aria-hidden="true" />
        Export
      </button>

      {open && (
        <>
          {/* Click-away layer; keeps the menu dismissible without a global listener. */}
          <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} aria-hidden="true" />
          <div
            role="menu"
            className="absolute right-0 z-20 mt-2 w-60 overflow-hidden rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] shadow-2xl"
          >
            {FORMATS.map((format) => (
              <a
                key={format.id}
                role="menuitem"
                href={`/api/scans/${scanId}/export?format=${format.id}`}
                download
                onClick={() => {
                  setDownloaded(format.id);
                  setTimeout(() => setOpen(false), 400);
                }}
                className={cn(
                  'flex items-center gap-3 px-3.5 py-2.5 text-[13px] transition-colors hover:bg-[var(--color-surface-raised)]',
                  'border-b border-[var(--color-border)] last:border-0',
                )}
              >
                <div className="min-w-0 flex-1">
                  <div className="font-medium">{format.label}</div>
                  <div className="text-[11.5px] text-[var(--color-fg-subtle)]">{format.hint}</div>
                </div>
                {downloaded === format.id && (
                  <Check className="h-3.5 w-3.5 text-[var(--color-success)]" aria-hidden="true" />
                )}
              </a>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
