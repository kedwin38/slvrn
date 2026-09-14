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

      /*
       * Thresholds are per-module first, global second, and that ordering is the point.
       *
       * A single global percentage is the metric this project's own README argues against:
       * it lets a fall in the code that decides whether money moves be paid for by a rise
       * in analytics handlers, and reports the average as health. So the modules on the
       * payment path carry their own floors, set at what they actually achieve. A drop in
       * `rbac.ts` fails the build no matter how well the rest of the repo is doing.
       *
       * The global number is a RATCHET, not a target: it is set to the measured figure so
       * that coverage cannot silently fall. Raise it when coverage rises; never lower it to
       * make a build pass.
       *
       * It previously read 80 across the board, with a comment claiming the critical
       * modules were "held to a higher bar below" — there was no below, and 80 had never
       * been met. `pnpm verify` did not run coverage, so nothing surfaced it until CI did.
       * `verify` now runs it.
       */
      thresholds: {
        // ---- Global ratchet. Measured: 63.49%. ----------------------------
        statements: 63,
        lines: 63,
        branches: 80,
        functions: 84,

        // ---- The kernel that decides whether money moves ------------------
        // These are complete and must stay complete.
        'packages/core/src/rbac.ts': { statements: 100, branches: 100, functions: 100, lines: 100 },
        'packages/core/src/manifest.ts': {
          statements: 100,
          branches: 100,
          functions: 100,
          lines: 100,
        },
        'packages/core/src/batch-state.ts': {
          statements: 100,
          branches: 100,
          functions: 100,
          lines: 100,
        },
        'packages/core/src/txn-state.ts': {
          statements: 100,
          branches: 100,
          functions: 100,
          lines: 100,
        },
        'packages/core/src/policy.ts': {
          statements: 100,
          branches: 100,
          functions: 100,
          lines: 100,
        },

        // ---- Near-complete, and held there -------------------------------
        'packages/core/src/audit.ts': { statements: 97, branches: 92, functions: 100, lines: 97 },
        'packages/core/src/sod.ts': { statements: 93, branches: 95, functions: 100, lines: 93 },
        'packages/core/src/idempotency.ts': {
          statements: 90,
          branches: 90,
          functions: 100,
          lines: 90,
        },
        'packages/core/src/export-csv.ts': {
          statements: 100,
          branches: 85,
          functions: 100,
          lines: 100,
        },
        'apps/api/src/services/crypto.ts': {
          statements: 97,
          branches: 96,
          functions: 100,
          lines: 97,
        },
        'apps/api/src/services/authorization.ts': {
          statements: 87,
          branches: 73,
          functions: 83,
          lines: 87,
        },

        // ---- Platform adapters written during the Railway port ------------
        'apps/api/src/storage/s3.ts': { statements: 94, branches: 85, functions: 92, lines: 94 },
        'apps/api/src/config.ts': { statements: 84, branches: 87, functions: 88, lines: 84 },
        'apps/api/src/queue/queue.ts': { statements: 86, branches: 72, functions: 72, lines: 86 },
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
