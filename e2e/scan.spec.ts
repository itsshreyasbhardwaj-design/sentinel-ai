import { expect, test, type APIRequestContext, type Page } from '@playwright/test';
import { resolve } from 'node:path';

/**
 * End-to-end journey.
 *
 * Runs a real scan of the bundled vulnerable fixture through the browser and
 * asserts on the rendered report. Nothing is stubbed, so a green run is
 * evidence the product actually works rather than that its mocks agree.
 */

const FIXTURE = resolve(process.cwd(), 'fixtures/vulnerable-app');

/** Start a scan via the API and wait for it to finish; faster than the UI path. */
async function scanFixture(request: APIRequestContext): Promise<string> {
  const created = await request.post('/api/scans', {
    data: {
      target: { type: 'local', path: FIXTURE },
      options: { allowNetwork: false },
    },
  });
  expect(created.status()).toBe(202);
  const { jobId } = (await created.json()) as { jobId: string };

  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    const poll = await request.get(`/api/scans?jobId=${jobId}`);
    const job = (await poll.json()) as {
      status: string;
      result?: { scanId?: string };
      error?: string;
    };

    if (job.status === 'completed' && job.result?.scanId) return job.result.scanId;
    if (job.status === 'failed') throw new Error(`Scan failed: ${job.error}`);
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error('Scan did not complete within the timeout');
}

test.describe('health and configuration', () => {
  test('reports which components are wired up', async ({ request }) => {
    const response = await request.get('/api/health');
    expect(response.ok()).toBeTruthy();

    const body = await response.json();
    expect(body.status).toBe('ok');
    expect(body.components.storage).toBeTruthy();
    expect(body.components.queue).toBeTruthy();
    // The endpoint must be explicit when auth is not enforced.
    expect(Array.isArray(body.warnings)).toBe(true);
  });

  test('lists available scanners', async ({ request }) => {
    const response = await request.get('/api/scanners');
    const body = await response.json();

    expect(body.scanners.length).toBeGreaterThan(8);
    // The nine bundled scanners must always be available, with no binaries.
    const native = body.scanners.filter(
      (s: { origin: string; availability: { available: boolean } }) =>
        s.origin === 'native' && s.availability.available,
    );
    expect(native.length).toBe(9);
  });
});

test.describe('scan lifecycle', () => {
  test('scans the vulnerable fixture and renders a full report', async ({ page, request }) => {
    const scanId = await scanFixture(request);
    await page.goto(`/scans/${scanId}`);

    // Header and score.
    await expect(page.getByRole('heading', { name: 'vulnerable-app' })).toBeVisible();
    await expect(page.getByRole('img', { name: /Security score \d+ out of 100/ })).toBeVisible();

    // The AI summary must be present, not just the raw counts.
    await expect(page.getByText(/critical issues requiring immediate attention/i)).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Recommended actions' })).toBeVisible();
    await expect(page.getByText(/Rotate \d+ exposed credentials/i)).toBeVisible();

    // Every score category is rendered.
    await expect(page.getByRole('heading', { name: 'Repository health' })).toBeVisible();
    for (const category of ['Code', 'Dependencies', 'Infrastructure', 'Secrets', 'AI Safety']) {
      await expect(page.getByText(category, { exact: true }).first()).toBeVisible();
    }

    // Compliance and coverage sections.
    await expect(page.getByRole('heading', { name: 'Compliance' })).toBeVisible();
    await expect(page.getByText('OWASP Top 10 for LLM Applications')).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Scanner coverage' })).toBeVisible();

    // Coverage limits must always be stated.
    await expect(page.getByRole('heading', { name: /Caveats/ })).toBeVisible();
  });

  test('findings can be filtered and expanded', async ({ page, request }) => {
    const scanId = await scanFixture(request);
    await page.goto(`/scans/${scanId}`);

    const search = page.getByRole('searchbox', { name: 'Search findings' });
    await expect(search).toBeVisible();

    // Expand the highest-priority finding and check the explanation renders.
    const firstFinding = page
      .locator('button[aria-expanded]')
      .filter({ hasText: /critical/i })
      .first();
    await firstFinding.click();

    await expect(page.getByText('Business impact').first()).toBeVisible();
    await expect(page.getByText('How it happens').first()).toBeVisible();
    await expect(page.getByText('How to fix').first()).toBeVisible();

    // Filtering narrows the list.
    await search.fill('agent.py');
    await expect(page.getByText(/Showing \d+ of \d+/)).toBeVisible();

    await search.fill('zzz-no-such-finding');
    await expect(page.getByText('No findings match these filters')).toBeVisible();
  });

  test('detects AI-specific weaknesses', async ({ page, request }) => {
    const scanId = await scanFixture(request);
    await page.goto(`/scans/${scanId}`);

    // The AI Security domain filter should exist with a non-zero count.
    const aiFilter = page.getByRole('button').filter({ hasText: /^AI Security/ });
    await expect(aiFilter).toBeVisible();
    await aiFilter.click();

    // Prompt-injection findings are the signature AI-security detection.
    await expect(page.getByText(/prompt/i).first()).toBeVisible();
  });
});

test.describe('exports', () => {
  const formats = ['json', 'sarif', 'csv', 'markdown', 'html', 'pdf'] as const;

  for (const format of formats) {
    test(`exports ${format}`, async ({ request }) => {
      const scanId = await scanFixture(request);
      const response = await request.get(`/api/scans/${scanId}/export?format=${format}`);

      expect(response.status()).toBe(200);
      expect(response.headers()['content-disposition']).toContain('attachment');

      const body = await response.body();
      expect(body.length).toBeGreaterThan(500);

      if (format === 'pdf') expect(body.subarray(0, 5).toString()).toBe('%PDF-');
      if (format === 'sarif') {
        const sarif = JSON.parse(body.toString());
        expect(sarif.version).toBe('2.1.0');
        expect(sarif.runs[0].results.length).toBeGreaterThan(0);
      }
    });
  }

  test('rejects an unknown format', async ({ request }) => {
    const scanId = await scanFixture(request);
    const response = await request.get(`/api/scans/${scanId}/export?format=docx`);
    expect(response.status()).toBe(400);
  });
});

test.describe('API contract', () => {
  test('rejects a malformed scan request', async ({ request }) => {
    const response = await request.post('/api/scans', {
      data: { target: { type: 'github', owner: '', repo: '' } },
    });
    expect(response.status()).toBe(400);
    const body = await response.json();
    expect(body.error.code).toBe('VALIDATION_ERROR');
  });

  test('rejects a git ref that could be read as a flag', async ({ request }) => {
    const response = await request.post('/api/scans', {
      data: {
        target: { type: 'github', owner: 'acme', repo: 'web', ref: '--upload-pack=touch /tmp/pwn' },
      },
    });
    expect(response.status()).toBe(400);
  });

  test('returns 404 for an unknown scan', async ({ request }) => {
    const response = await request.get('/api/scans/scan_doesnotexist/stats');
    expect(response.status()).toBe(404);
  });

  test('serves statistics and compliance for a real scan', async ({ request }) => {
    const scanId = await scanFixture(request);

    const stats = await (await request.get(`/api/scans/${scanId}/stats`)).json();
    expect(stats.totalFindings).toBeGreaterThan(20);
    expect(stats.coverage.scannersRun).toBeGreaterThan(5);

    const compliance = await (
      await request.get(`/api/scans/${scanId}/compliance?framework=owasp-top-10-2021`)
    ).json();
    expect(compliance.reports[0].assessments.length).toBe(10);
  });

  test('sets security headers on API responses', async ({ request }) => {
    const response = await request.get('/api/health');
    const headers = response.headers();
    expect(headers['x-content-type-options']).toBe('nosniff');
    expect(headers['content-security-policy']).toContain("frame-ancestors 'none'");
  });
});

test.describe('accessibility and navigation', () => {
  test('has a skip link and reachable navigation', async ({ page }) => {
    await page.goto('/');

    await page.keyboard.press('Tab');
    await expect(page.getByRole('link', { name: 'Skip to content' })).toBeFocused();

    const nav = page.getByRole('navigation', { name: 'Main' });
    await nav.getByRole('link', { name: 'New scan' }).click();
    await expect(page.getByRole('heading', { name: 'New scan' })).toBeVisible();

    await nav.getByRole('link', { name: 'Scanners' }).click();
    await expect(page.getByRole('heading', { name: 'Scanners' })).toBeVisible();
  });

  test('the scan form is operable and labelled', async ({ page }) => {
    await page.goto('/scan');

    const group = page.getByRole('radiogroup', { name: 'Scan source type' });
    await expect(group).toBeVisible();

    await page.getByRole('radio', { name: 'Local path' }).click();
    await expect(page.getByRole('radio', { name: 'Local path' })).toHaveAttribute(
      'aria-checked',
      'true',
    );

    // Submitting an empty path must surface a validation message, not a crash.
    await page.getByRole('button', { name: 'Start scan' }).click();
    // Next's dev overlay also publishes role="alert", so scope to the form's own.
    await expect(page.locator('form').getByRole('alert')).toContainText(/absolute path/i);
  });

  test('renders a not-found page for an unknown route', async ({ page }: { page: Page }) => {
    const response = await page.goto('/scans/scan_definitely_missing');
    expect(response?.status()).toBe(404);
    await expect(page.getByText('Not found')).toBeVisible();
  });
});
