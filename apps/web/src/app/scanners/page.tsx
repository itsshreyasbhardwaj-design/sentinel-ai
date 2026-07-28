import { CheckCircle2, Circle } from 'lucide-react';
import { silentLogger } from '@sentinel/core';
import { scannerCatalog, type ScanContext } from '@sentinel/scanners';
import { Badge, Card, CardContent } from '@/components/primitives';
import { KIND_LABEL } from '@/lib/ui';

export const dynamic = 'force-dynamic';

export const metadata = { title: 'Scanners' };

/**
 * Scanner inventory.
 *
 * Shows exactly which engines this installation can run. Making coverage
 * visible is the point: a security tool that quietly analyzes less than the
 * user assumes is worse than one that analyzes nothing.
 */
export default async function ScannersPage() {
  const probeContext = {
    scanId: 'probe',
    root: process.cwd(),
    target: { type: 'local', path: process.cwd() },
    options: { maxFiles: 0, maxFileSizeBytes: 0, concurrency: 1, allowNetwork: false },
    files: [],
    logger: silentLogger,
    readFile: async () => '',
  } as unknown as ScanContext;

  const catalog = await scannerCatalog(probeContext);
  const native = catalog.filter((entry) => entry.origin === 'native');
  const external = catalog.filter((entry) => entry.origin === 'external');

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Scanners</h1>
        <p className="mt-1 max-w-2xl text-sm text-[var(--color-fg-subtle)]">
          Sentinel ships its own analysis engines so a scan works with nothing installed, and defers
          to best-in-class open-source tools when they are available on the host.
        </p>
      </div>

      <Section
        title="Bundled"
        description="Always available. No binaries, no network, no configuration."
        entries={native}
      />
      <Section
        title="External integrations"
        description="Detected on PATH. When one of these is installed it supersedes the bundled equivalent for that domain."
        entries={external}
      />
    </div>
  );
}

function Section({
  title,
  description,
  entries,
}: {
  title: string;
  description: string;
  entries: Awaited<ReturnType<typeof scannerCatalog>>;
}) {
  return (
    <section>
      <h2 className="text-sm font-medium text-[var(--color-fg-muted)]">{title}</h2>
      <p className="mb-3 mt-0.5 text-[12.5px] text-[var(--color-fg-subtle)]">{description}</p>

      <div className="grid gap-2">
        {entries.map((entry) => (
          <Card key={entry.id}>
            <CardContent className="flex items-start gap-3 pt-4">
              {entry.availability.available ? (
                <CheckCircle2
                  className="mt-0.5 h-4 w-4 shrink-0 text-[var(--color-success)]"
                  aria-label="Available"
                />
              ) : (
                <Circle
                  className="mt-0.5 h-4 w-4 shrink-0 text-[var(--color-fg-subtle)]"
                  aria-label="Not installed"
                />
              )}

              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[14px] font-medium">{entry.name}</span>
                  <Badge>{KIND_LABEL[entry.kind] ?? entry.kind}</Badge>
                  {entry.availability.version && (
                    <span className="font-mono text-[11px] text-[var(--color-fg-subtle)]">
                      {entry.availability.version.slice(0, 40)}
                    </span>
                  )}
                </div>
                <p className="mt-1 text-[12.5px] leading-relaxed text-[var(--color-fg-subtle)]">
                  {entry.description}
                </p>
                {!entry.availability.available && entry.availability.reason && (
                  <p className="mt-1.5 text-[12px] text-[var(--color-fg-subtle)]">
                    {entry.availability.reason}
                  </p>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </section>
  );
}
