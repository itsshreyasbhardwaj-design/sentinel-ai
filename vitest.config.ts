import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: false,
    environment: 'node',
    include: ['packages/**/*.test.ts', 'apps/**/*.test.ts', 'apps/**/*.test.tsx'],
    exclude: ['**/node_modules/**', '**/dist/**', '**/.next/**', 'e2e/**'],
    testTimeout: 30_000,
    server: {
      deps: {
        // Node built-ins must stay external: Vite otherwise tries to resolve
        // `node:sqlite` from node_modules and fails.
        external: [/^node:/],
      },
    },
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'html'],
      reportsDirectory: './coverage',
      include: ['packages/*/src/**/*.ts'],
      exclude: ['**/*.test.ts', '**/index.ts', '**/types.ts'],
      thresholds: {
        statements: 55,
        branches: 70,
        functions: 60,
        lines: 55,
      },
    },
  },
  resolve: {
    alias: {
      '@sentinel/core': new URL('./packages/core/src/index.ts', import.meta.url).pathname,
      '@sentinel/scanners': new URL('./packages/scanners/src/index.ts', import.meta.url).pathname,
      '@sentinel/ai': new URL('./packages/ai/src/index.ts', import.meta.url).pathname,
      '@sentinel/reports': new URL('./packages/reports/src/index.ts', import.meta.url).pathname,
      '@sentinel/platform': new URL('./packages/platform/src/index.ts', import.meta.url).pathname,
    },
  },
});
