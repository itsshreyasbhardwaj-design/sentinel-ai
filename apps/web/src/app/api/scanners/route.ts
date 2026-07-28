import { scannerCatalog, type ScanContext } from '@sentinel/scanners';
import { silentLogger } from '@sentinel/core';
import { cacheKeys } from '@sentinel/platform';
import { handle, json } from '@/lib/api';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

interface CatalogEntry {
  id: string;
  name: string;
  kind: string;
  origin: string;
  description: string;
  availability: { available: boolean; version?: string; reason?: string };
}

/**
 * GET /api/scanners
 *
 * Which analysis engines this installation can actually run. Probing external
 * binaries means spawning processes, so the answer is cached — it changes only
 * when someone installs a tool on the host.
 */
export const GET = handle(
  async ({ platform }) => {
    const cached = await platform.cache.get<CatalogEntry[]>(cacheKeys.scannerCatalog());
    if (cached) return json({ scanners: cached, cached: true });

    const probeContext = {
      scanId: 'probe',
      root: process.cwd(),
      target: { type: 'local', path: process.cwd() },
      options: { maxFiles: 0, maxFileSizeBytes: 0, concurrency: 1, allowNetwork: false },
      files: [],
      logger: silentLogger,
      readFile: async () => '',
    } as unknown as ScanContext;

    const catalog = (await scannerCatalog(probeContext)) as CatalogEntry[];
    await platform.cache.set(cacheKeys.scannerCatalog(), catalog, 300);

    return json({
      scanners: catalog,
      cached: false,
      summary: {
        available: catalog.filter((s) => s.availability.available).length,
        total: catalog.length,
        external: catalog.filter((s) => s.origin === 'external' && s.availability.available).length,
      },
    });
  },
  { rateLimit: 'read' },
);
