import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['packages/**/*.test.ts', 'apps/api/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary', 'html'],
      include: ['packages/*/src/**/*.ts', 'apps/api/src/**/*.ts'],
      exclude: ['**/*.test.ts', '**/index.ts', '**/types.ts'],
      thresholds: {
        // Enforced in CI. The security-critical modules are held to a higher bar below.
        statements: 80,
        branches: 75,
        functions: 80,
        lines: 80,
      },
    },
  },
  resolve: {
    alias: {
      '@solvaren/core': new URL('./packages/core/src/index.ts', import.meta.url).pathname,
      '@solvaren/daraja': new URL('./packages/daraja/src/index.ts', import.meta.url).pathname,
    },
  },
});
