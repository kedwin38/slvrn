// @ts-check
/**
 * SOLVAREN lint configuration.
 *
 * The rules here are chosen for one reason: each corresponds to a bug class that would be
 * expensive on a payment platform. This is not a style configuration — Prettier owns style,
 * and stylistic rules are deliberately absent so the two never disagree.
 *
 * Type-aware linting is enabled because the failure that matters most cannot be seen
 * syntactically: a dropped `await` on an audit write or a state transition compiles, passes
 * review, and loses the record of a payment. `no-floating-promises` is the single highest
 * value rule in this file.
 */

import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    // Build output, dependencies and generated assets are not ours to lint.
    ignores: [
      '**/dist/**',
      '**/node_modules/**',
      '**/coverage/**',
      '**/.wrangler/**',
      'apps/web/dist/**',
    ],
  },

  eslint.configs.recommended,

  // ---- TypeScript sources: type-aware ------------------------------------
  {
    files: ['**/*.ts', '**/*.tsx'],
    extends: [...tseslint.configs.recommended, ...tseslint.configs.recommendedTypeChecked],
    languageOptions: {
      parserOptions: {
        project: './tsconfig.eslint.json',
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // A promise that is never awaited is how an audit record goes missing.
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-misused-promises': 'error',

      // `catch (e) { }` on a payment path hides the outcome we most need to see.
      'no-empty': ['error', { allowEmptyCatch: false }],

      // Loose equality against a status string or a provider code is a silent defect.
      eqeqeq: ['error', 'always', { null: 'ignore' }],

      // Unused bindings are permitted only when named deliberately with a leading
      // underscore, which makes "this is intentionally discarded" reviewable.
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
        },
      ],

      // These fire constantly on correct code that touches `unknown` request bodies and
      // database rows, where the value genuinely is unknown until it is validated. The
      // validation is the control; the lint rule here would only teach people to silence it.
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
      '@typescript-eslint/no-unsafe-return': 'off',
      '@typescript-eslint/no-explicit-any': 'off',

      // Template literals over numbers and dates are ordinary and safe here.
      '@typescript-eslint/restrict-template-expressions': 'off',

      // Off deliberately, after reviewing every one of its 24 findings in this repository:
      // all of them were `async` functions required to be async by an interface they
      // implement — Hono route handlers, the Workers `ExportedHandler.scheduled` hook whose
      // body is `ctx.waitUntil(...)` by design, and scripted `fetch` mocks. It found no
      // missing await. Leaving it on would mean two dozen inline disables, which teaches
      // people to silence lint rather than read them.
      //
      // The rule that actually catches a missing await is `no-floating-promises`, above,
      // and that one is on.
      '@typescript-eslint/require-await': 'off',
    },
  },

  // ---- The console -------------------------------------------------------
  {
    files: ['apps/web/**/*.tsx'],
    rules: {
      // `onClick={async () => …}` is the ordinary React idiom and every such handler here
      // resolves its own errors into component state rather than rejecting. The rest of
      // `no-misused-promises` — a promise passed where a condition or a void return is
      // expected in non-JSX positions — stays on, because that one hides real bugs.
      '@typescript-eslint/no-misused-promises': [
        'error',
        { checksVoidReturn: { attributes: false } },
      ],
    },
  },

  // ---- Tests -------------------------------------------------------------
  {
    files: ['**/*.test.ts', '**/test-harness.ts', 'db/**', 'scripts/**'],
    rules: {
      // A test may deliberately construct a malformed value to prove it is refused.
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/unbound-method': 'off',
    },
  },

  // ---- Plain JavaScript tooling -----------------------------------------
  {
    files: ['**/*.mjs', '**/*.js'],
    extends: [tseslint.configs.disableTypeChecked],
    languageOptions: {
      globals: {
        process: 'readonly',
        console: 'readonly',
        Buffer: 'readonly',
        URL: 'readonly',
        // Node 18+ web globals. scripts/deploy-check.mjs calls a live deployment over
        // HTTP, with a timeout, using the runtime's own fetch rather than a dependency.
        fetch: 'readonly',
        AbortController: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        // scripts/ui-check.mjs passes functions to Playwright's `page.evaluate`, which
        // serialises them and runs them in the browser. Those bodies legitimately
        // reference the DOM even though the file itself executes in Node.
        document: 'readonly',
        window: 'readonly',
        getComputedStyle: 'readonly',
      },
    },
    rules: {
      '@typescript-eslint/no-unused-vars': 'off',
      'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    },
  },
  {
    /*
     * apps/web/public is served verbatim to the browser: no bundler, no imports, no TypeScript.
     * theme.js runs from <head> before the bundle exists, so it is a plain classic script and
     * needs the browser globals declared rather than the Node ones the repo defaults to.
     */
    files: ['apps/web/public/**/*.js'],
    languageOptions: {
      sourceType: 'script',
      globals: {
        window: 'readonly',
        document: 'readonly',
        localStorage: 'readonly',
      },
    },
  },
);
