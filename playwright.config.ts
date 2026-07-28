import { defineConfig, devices } from '@playwright/test';

/**
 * End-to-end configuration.
 *
 * The suite drives a real dev server against the bundled vulnerable fixture, so
 * it exercises the same path a user takes: submit a scan, watch it stream,
 * read the report. Nothing is mocked — a passing run means the product works.
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  // Scans are stateful and share one in-process queue; parallel workers would
  // contend for it and make failures non-reproducible.
  workers: 1,
  reporter: process.env.CI ? [['github'], ['html', { open: 'never' }]] : [['list']],
  timeout: 120_000,
  expect: { timeout: 15_000 },

  use: {
    baseURL: process.env.E2E_BASE_URL ?? 'http://localhost:3100',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },

  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],

  webServer: process.env.E2E_BASE_URL
    ? undefined
    : {
        command: 'pnpm --filter @sentinel/web dev --port 3100',
        url: 'http://localhost:3100/api/health',
        reuseExistingServer: !process.env.CI,
        timeout: 180_000,
        env: {
          NODE_ENV: 'development',
          // An isolated database per run so e2e never touches developer data.
          SQLITE_PATH: '.sentinel/e2e.db',
          ALLOW_NETWORK_SCANNERS: 'false',
          LOG_LEVEL: 'warn',
          // The suite starts a scan per test; the shipped default of 10/hour is
          // a production policy, not a test constraint.
          RATE_LIMIT_SCAN_MAX: '500',
          RATE_LIMIT_MAX_REQUESTS: '5000',
        },
      },
});
