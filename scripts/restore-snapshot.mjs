/**
 * Restore a SOLVAREN logical snapshot into a database.
 *
 * This is the other half of the backup system. A backup that cannot be restored is a file,
 * not a backup, and the only way to know which you have is to run this.
 *
 * Two things about it are deliberate and worth understanding before you use it:
 *
 *  1. **It disables the immutability triggers for the duration of the load.** Those
 *     triggers exist to stop the *application* rewriting history. A restore is the one
 *     legitimate reason to insert historical rows, and it is performed by a human with
 *     database ownership, out of band — not by the application. The script re-enables them
 *     before exiting and fails loudly if it cannot, because a database left with its
 *     immutability guarantees switched off is far worse than a failed restore.
 *
 *  2. **It refuses to run against a database that already has payment data**, unless
 *     `--force` is given. Restoring over a live ledger is not a recovery, it is a second
 *     disaster.
 *
 * Usage:
 *   node --experimental-strip-types scripts/restore-snapshot.mjs \
 *     --snapshot /tmp/snapshot.json \
 *     --database postgres://localhost/solvaren_restore_test
 */

import postgres from 'postgres';
import { readFileSync } from 'node:fs';

/** Insert order matters: a child row cannot reference a parent that is not there yet. */
const RESTORE_ORDER = [
  'organizations',
  'policies',
  'users',
  'webauthn_credentials',
  'trusted_devices',
  'recovery_codes',
  'conflict_registrations',
  'departments',
  'recipients',
  'payment_batches',
  'payment_instructions',
  'approvals',
  'batch_editors',
  'authorization_challenges',
  'idempotency_claims',
  'transactions',
  'provider_callbacks',
  'reconciliation_cases',
  'risk_findings',
  'account_balance_snapshots',
  'audit_events',
  'daraja_configurations',
  'failure_reason_map',
  'backup_configurations',
  'backup_attempts',
  'export_records',
  'batch_templates',
  'payment_calendar',
  'ai_interactions',
  'security_events',
];

/**
 * Triggers that must be suspended during a load.
 *
 * `audit_events_seal` is included because it assigns the sequence number and verifies the
 * chain link against the current tail — correct behaviour for an appending application,
 * wrong for a restore, which must preserve the original sequence exactly or the chain will
 * not verify afterwards.
 */
const TRIGGERS_TO_SUSPEND = [
  ['audit_events', 'audit_events_no_update'],
  ['audit_events', 'audit_events_no_delete'],
  ['audit_events', 'audit_events_seal'],
  ['approvals', 'approvals_no_update'],
  ['approvals', 'approvals_no_delete'],
  ['transactions', 'transactions_guard_update'],
  ['transactions', 'transactions_no_delete'],
  ['transactions', 'transactions_updated_at'],
  ['payment_instructions', 'instructions_guard_update'],
  ['payment_instructions', 'instructions_guard_delete'],
  ['payment_instructions', 'instructions_refresh_totals'],
  ['payment_instructions', 'instructions_updated_at'],
  ['payment_batches', 'batches_guard_update'],
  ['authorization_challenges', 'challenges_guard_update'],
  ['authorization_challenges', 'challenges_no_delete'],
  ['provider_callbacks', 'provider_callbacks_no_delete'],
  ['backup_attempts', 'backup_attempts_guard_update'],
  ['backup_attempts', 'backup_attempts_no_delete'],
  ['export_records', 'export_records_no_delete'],
];

/**
 * Credential placeholders for restored users.
 *
 * The snapshot deliberately excludes password hashes, authorization PINs and recovery
 * codes (spec §13.7 — credential material does not travel to object storage). But
 * `users.password_hash` is NOT NULL, so a restore has to supply *something*, and that
 * something must be provably unusable.
 *
 * This sentinel is not a valid Argon2 encoding. `argon2Verify` throws on it, and
 * `verifyPassword` catches and returns false — a behaviour that is directly asserted in
 * services/crypto.test.ts ("fails closed on a malformed stored hash"). So no password can
 * ever match it.
 *
 * Restored accounts are additionally set to PENDING_ENROLMENT, which blocks sign-in
 * regardless of credentials. Recovering from a real disaster therefore includes a
 * deliberate, audited re-enrolment — see docs/runbooks/backup-restore.md.
 */
const RESTORED_CREDENTIAL_SENTINEL = '$solvaren-restored$credential-must-be-re-enrolled';

/**
 * Supply the columns the snapshot deliberately omits, so the row can be inserted at all.
 * Applied to every user: a restored account cannot sign in until its credentials are
 * re-enrolled, which is the intended recovery posture rather than a limitation.
 */
function withRestoredCredentials(table, row) {
  if (table !== 'users') return row;
  return {
    ...row,
    password_hash: RESTORED_CREDENTIAL_SENTINEL,
    authorization_pin_hash: null,
    status: 'PENDING_ENROLMENT',
  };
}

/**
 * Column type map for a table.
 *
 * A restore binds values into typed columns, and JSONB is the case that goes wrong
 * silently. postgres.js types a string parameter as JSONB when the target column is JSONB,
 * so `JSON.stringify(value)` is stored as a JSONB *string* — `"{\"state\":\"A\"}"` rather
 * than `{"state":"A"}`. An explicit `::jsonb` cast does not help, because the parameter was
 * already sent with the JSONB type. The rows load, nothing errors, and every JSONB column
 * in the database is subtly wrong.
 *
 * The audit hash chain then fails to verify, which is exactly how this was found — and is
 * a good argument for hash-chaining the audit log in the first place.
 *
 * The mechanism that is correct is `sql.json(value)`, so the loader asks PostgreSQL what
 * each column is and wraps accordingly.
 */
async function columnTypes(sql, table) {
  const rows = await sql`
    SELECT column_name, data_type
      FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = ${table}
  `;
  return new Map(rows.map((row) => [row.column_name, row.data_type]));
}

/** Prepare a row for insertion, wrapping JSONB values so they are stored as JSON, not text. */
function prepareRow(sql, types, row) {
  const prepared = {};
  for (const [column, value] of Object.entries(row)) {
    const type = types.get(column);
    prepared[column] = type === 'jsonb' || type === 'json' ? sql.json(value) : value;
  }
  return prepared;
}

function parseArguments(argv) {
  const options = {};
  for (let i = 2; i < argv.length; i++) {
    const token = argv[i];
    if (!token?.startsWith('--')) continue;
    const key = token.replace(/^--/, '');
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) {
      options[key] = true;
    } else {
      options[key] = next;
      i++;
    }
  }
  return options;
}

const options = parseArguments(process.argv);
if (!options.snapshot || !options.database) {
  console.error('Usage: restore-snapshot.mjs --snapshot <file.json> --database <url> [--force]');
  process.exit(1);
}

const snapshot = JSON.parse(readFileSync(options.snapshot, 'utf8'));
if (!snapshot.metadata || !snapshot.data) {
  console.error('That file is not a SOLVAREN snapshot: no metadata or data section.');
  process.exit(1);
}

console.log('');
console.log('  SOLVAREN snapshot restore');
console.log('  ─────────────────────────────────────────────');
console.log(`  Taken at       ${snapshot.metadata.takenAt}`);
console.log(`  Organization   ${snapshot.metadata.organizationId}`);
console.log(`  Rows           ${snapshot.metadata.totalRows}`);
console.log(`  Schema         ${snapshot.metadata.solvarenVersion}`);
console.log('');

const sql = postgres(options.database, { max: 1, onnotice: () => {} });
let triggersSuspended = false;

/** Re-enable every suspended trigger. Must run even on failure. */
async function restoreTriggers() {
  if (!triggersSuspended) return;
  let failures = 0;
  for (const [table, trigger] of TRIGGERS_TO_SUSPEND) {
    try {
      await sql.unsafe(`ALTER TABLE ${table} ENABLE TRIGGER ${trigger}`);
    } catch (error) {
      failures++;
      console.error(`  !! Could not re-enable ${table}.${trigger}: ${error.message}`);
    }
  }
  triggersSuspended = false;
  if (failures > 0) {
    console.error('');
    console.error('  ***********************************************************');
    console.error('  * IMMUTABILITY TRIGGERS ARE STILL DISABLED.               *');
    console.error('  * This database does NOT currently protect its audit log  *');
    console.error('  * or its payment ledger. Re-enable them before any        *');
    console.error('  * application connects to it.                             *');
    console.error('  ***********************************************************');
    process.exitCode = 1;
  } else {
    console.log('  Immutability triggers re-enabled.');
  }
}

process.on('SIGINT', async () => {
  console.error('\n  Interrupted — restoring triggers before exit.');
  await restoreTriggers();
  await sql.end({ timeout: 5 });
  process.exit(130);
});

try {
  // ---- Refuse to overwrite a live ledger --------------------------------
  const existing = await sql`SELECT COUNT(*)::int AS count FROM transactions`;
  if (existing[0].count > 0 && !options.force) {
    console.error(`  This database already contains ${existing[0].count} transactions.`);
    console.error('  Restoring over a live payment ledger is not a recovery.');
    console.error('  Restore into a scratch database, or pass --force if you are certain.');
    process.exit(1);
  }

  // ---- Suspend the immutability triggers --------------------------------
  console.log('  Suspending immutability triggers for the load…');
  for (const [table, trigger] of TRIGGERS_TO_SUSPEND) {
    await sql.unsafe(`ALTER TABLE ${table} DISABLE TRIGGER ${trigger}`).catch((error) => {
      // A trigger that does not exist in this schema version is not fatal; a permission
      // error is, and will surface on the load itself.
      if (!/does not exist/.test(error.message)) throw error;
    });
  }
  triggersSuspended = true;

  // ---- Load ---------------------------------------------------------------
  let restored = 0;
  for (const table of RESTORE_ORDER) {
    const rows = snapshot.data[table];
    if (!Array.isArray(rows) || rows.length === 0) continue;

    const types = await columnTypes(sql, table);

    for (const original of rows) {
      const row = prepareRow(sql, types, withRestoredCredentials(table, original));
      const columns = Object.keys(row);

      // postgres.js's dynamic-insert helper, which handles column quoting, array encoding
      // and — critically — `sql.json()` values.
      await sql`
        INSERT INTO ${sql(table)} ${sql(row, ...columns)}
        ON CONFLICT DO NOTHING
      `;
      restored++;
    }
    console.log(`    ${table.padEnd(28)} ${rows.length}`);
  }

  console.log('');
  console.log(`  Loaded ${restored} rows.`);
} catch (error) {
  console.error('');
  console.error(`  Restore failed: ${error.message}`);
  process.exitCode = 1;
} finally {
  await restoreTriggers();
  await sql.end({ timeout: 10 });
}

console.log('');
console.log('  Next: verify the restore is usable, not merely loaded.');
console.log('  See docs/runbooks/backup-restore.md section 5 — audit chain contiguity,');
console.log('  batch totals against instruction rows, and settled-transaction evidence.');
console.log('');
console.log('  Note: password hashes, authorization PINs, recovery codes and sessions are');
console.log('  deliberately NOT in the snapshot. Restored users cannot sign in until their');
console.log('  credentials are re-enrolled. That is by design (spec §13.7).');
console.log('');
