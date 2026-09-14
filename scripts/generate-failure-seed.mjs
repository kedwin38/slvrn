/**
 * Generates db/migrations/0005_seed_failure_reasons.sql from the compiled dictionary in
 * @solvaren/core, so the database seed and the application fallback can never disagree.
 * Run via `pnpm db:generate-seed`; CI re-runs it and fails if the output differs.
 */
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const { listFailureReasons, FAILURE_DICTIONARY_VERSION } =
  await import('../packages/core/src/failure-reasons.ts');

const sqlEscape = (s) => s.replace(/'/g, "''");
const entries = listFailureReasons().filter((e) => e.code !== '0');

const rows = entries
  .map(
    (e) =>
      `    (NULL, '${sqlEscape(e.code)}', '${sqlEscape(e.reason)}', '${e.class}', '${sqlEscape(
        e.operatorAction,
      )}', ${e.transient}, '${FAILURE_DICTIONARY_VERSION}')`,
  )
  .join(',\n');

const sql = `-- ============================================================================
-- SOLVAREN Payment Solutions — 0005 Failure reason dictionary seed
--
-- GENERATED FILE — do not edit by hand.
-- Source: packages/core/src/failure-reasons.ts (dictionary version ${FAILURE_DICTIONARY_VERSION})
-- Regenerate with: pnpm db:generate-seed
--
-- These rows are the platform default scope (organization_id IS NULL). An administrator
-- may add an organisation-scoped override for any code without a deploy (TRK-009); the
-- override wins, this table is the next fallback, and the compiled dictionary in
-- @solvaren/core is the last resort if the database is unreachable.
-- ============================================================================

INSERT INTO failure_reason_map
    (organization_id, provider_code, reason, failure_class, operator_action, transient, dictionary_version)
VALUES
${rows}
ON CONFLICT (organization_id, provider_code) DO UPDATE
    SET reason             = EXCLUDED.reason,
        failure_class      = EXCLUDED.failure_class,
        operator_action    = EXCLUDED.operator_action,
        transient          = EXCLUDED.transient,
        dictionary_version = EXCLUDED.dictionary_version;
`;

const here = dirname(fileURLToPath(import.meta.url));
const target = join(here, '..', 'db', 'migrations', '0005_seed_failure_reasons.sql');
writeFileSync(target, sql);
console.log(`Wrote ${entries.length} failure reason mappings to ${target}`);
