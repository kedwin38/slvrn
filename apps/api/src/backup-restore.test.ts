/**
 * Backup and restore round-trip (spec §13, AC-10/12/13).
 *
 * The backup system's whole value rests on one claim: that the object it writes can be
 * turned back into a working database. A test that only asserts "an object was created"
 * proves nothing about that, so this suite runs the real backup worker, takes the real
 * object out of storage, loads it into a fresh database through the documented restore
 * path, and then verifies the properties that actually matter — the audit chain still
 * verifies, batch totals still reconcile against their instruction rows, and settled
 * transactions still carry their evidence.
 *
 * It also verifies the failure behaviour, because §13.7 is explicit that a failed backup
 * must never be presented as successful.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import postgres from 'postgres';
import { createTestEnvironment, type TestEnvironment } from './test-harness.js';
import { runBackup, enforceRetention } from './queues/backup-worker.js';
import { verifyChain, GENESIS_HASH, type AuditEvent } from '@solvaren/core';
import { writeAuditEvent } from './db/audit-writer.js';
import { inTransaction } from './db/client.js';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const DATABASE_AVAILABLE = Boolean(process.env.SOLVAREN_TEST_DATABASE_URL);
const suite = DATABASE_AVAILABLE ? describe : describe.skip;

const ORG = '00000000-0000-0000-0000-0000000ba001';
const USER = '00000000-0000-0000-0000-0000000ba002';

suite('backup and restore', () => {
  let harness: TestEnvironment;

  beforeAll(async () => {
    harness = await createTestEnvironment({
      databaseUrl: process.env.SOLVAREN_TEST_DATABASE_URL,
      databaseName: `solvaren_bak_${process.pid}`,
    });

    const { sql } = harness;
    await sql`INSERT INTO organizations (id, name, slug) VALUES (${ORG}, 'Backup Test Co', 'backup-test')`;
    await sql`INSERT INTO policies (organization_id) VALUES (${ORG})`;
    await sql`
      INSERT INTO users (id, organization_id, email, full_name, authority_level,
                         password_hash, authorization_pin_hash)
      VALUES (${USER}, ${ORG}, 'admin@backup.test', 'Backup Admin', 'L3',
              '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$hash',
              '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$pin')
    `;

    // Real payment data, so the restore has something meaningful to verify.
    const departments = await sql<{ id: string }[]>`
      INSERT INTO departments (organization_id, name) VALUES (${ORG}, 'Engineering') RETURNING id
    `;
    const recipients = await sql<{ id: string }[]>`
      INSERT INTO recipients (organization_id, full_name, msisdn, department_id)
      VALUES (${ORG}, 'Jane Wanjiku', '254712345678', ${departments[0]!.id})
      RETURNING id
    `;
    const batches = await sql<{ id: string }[]>`
      INSERT INTO payment_batches (organization_id, batch_reference, purpose, created_by_user_id, state)
      VALUES (${ORG}, 'SLV-BAK-0001', 'September payroll', ${USER}, 'SUCCESS')
      RETURNING id
    `;
    const instructions = await sql<{ id: string }[]>`
      INSERT INTO payment_instructions (organization_id, batch_id, recipient_id,
                                        recipient_name_snapshot, msisdn_snapshot, amount_cents)
      VALUES (${ORG}, ${batches[0]!.id}, ${recipients[0]!.id}, 'Jane Wanjiku', '254712345678', 4500000)
      RETURNING id
    `;
    await sql`
      INSERT INTO transactions (organization_id, instruction_id, batch_id, status,
                                originator_conversation_id, request_fingerprint, amount_cents,
                                mpesa_receipt_number, status_source, completed_at)
      VALUES (${ORG}, ${instructions[0]!.id}, ${batches[0]!.id}, 'SUCCESS',
              '600992-BAK-0001', 'fp-bak-1', 4500000, 'SG632NMUAB', 'CALLBACK', now())
    `;

    // A short audit chain, which is the hardest thing to restore correctly: the sequence
    // and the hash links have to survive exactly.
    for (let i = 0; i < 5; i++) {
      await inTransaction(sql, (tx) =>
        writeAuditEvent(tx, {
          organizationId: ORG,
          actorId: USER,
          actorLevel: 'L3',
          eventClass: 'PAYMENT',
          action: `test.event.${i}`,
          objectType: 'PaymentBatch',
          objectId: batches[0]!.id,
          outcome: 'SUCCESS',
          correlationId: `cor_BAK${i}`,
          detail: { index: i },
        }),
      );
    }

    await sql`
      INSERT INTO backup_configurations (organization_id, bucket, access_key_secret_ref,
                                         secret_key_secret_ref, retention_max_count, status, last_test_ok)
      VALUES (${ORG}, 'solvaren-test-backups', 'ref:ak', 'ref:sk', 3, 'CONNECTED', TRUE)
    `;
  }, 60_000);

  afterAll(async () => {
    await harness?.close();
  });

  it('AC-10: runs a backup and records a durable attempt with an object and a checksum', async () => {
    await runBackup(harness.sql, harness.env, {
      type: 'RUN_BACKUP',
      organizationId: ORG,
      trigger: 'MANUAL',
      requestedByUserId: USER,
      correlationId: 'cor_BAKRUN',
    });

    const attempts = await harness.sql<
      { status: string; object_key: string; size_bytes: string; checksum: string; ended_at: string }[]
    >`
      SELECT status, object_key, size_bytes, checksum, ended_at
        FROM backup_attempts WHERE organization_id = ${ORG} ORDER BY started_at DESC LIMIT 1
    `;

    expect(attempts[0]!.status).toBe('SUCCESS');
    expect(attempts[0]!.object_key).toBeTruthy();
    expect(Number(attempts[0]!.size_bytes)).toBeGreaterThan(0);
    expect(attempts[0]!.checksum).toMatch(/^[0-9a-f]{64}$/);
    expect(attempts[0]!.ended_at).toBeTruthy();

    // The object genuinely exists in storage, not merely in the attempt record.
    expect(harness.r2.objects.has(attempts[0]!.object_key)).toBe(true);
  });

  it('the object name carries no payroll information (spec §13.7)', async () => {
    const key = [...harness.r2.objects.keys()][0]!;
    expect(key).not.toMatch(/Wanjiku|254712345678|payroll|45000/i);
    expect(key).toContain(ORG); // opaque organisation id is fine
  });

  it('excludes credential material from the snapshot', async () => {
    const key = [...harness.r2.objects.keys()][0]!;
    const snapshot = JSON.parse(harness.r2.objects.get(key)!.body);

    // Sessions are absent entirely; password and PIN hashes are stripped from users.
    expect(snapshot.data.sessions).toBeUndefined();
    for (const user of snapshot.data.users) {
      expect(user.password_hash).toBeUndefined();
      expect(user.authorization_pin_hash).toBeUndefined();
    }
    expect(JSON.stringify(snapshot)).not.toContain('$argon2id$');
  });

  it('restores into a fresh database with the audit chain intact', async () => {
    const key = [...harness.r2.objects.keys()][0]!;
    const snapshot = JSON.parse(harness.r2.objects.get(key)!.body);

    const adminUrl = process.env.SOLVAREN_TEST_DATABASE_URL!;
    const restoreName = `solvaren_restore_${process.pid}`;
    const admin = postgres(adminUrl, { max: 1, onnotice: () => {} });
    await admin.unsafe(`DROP DATABASE IF EXISTS ${restoreName} WITH (FORCE)`);
    await admin.unsafe(`CREATE DATABASE ${restoreName}`);
    await admin.end({ timeout: 5 });

    const restoreUrl = adminUrl.replace(/\/[^/]*$/, `/${restoreName}`);
    const restored = postgres(restoreUrl, { max: 1, onnotice: () => {} });

    try {
      // Apply the schema exactly as the deployment guide does.
      const migrationsDir = join(process.cwd(), 'db', 'migrations');
      for (const file of readdirSync(migrationsDir).filter((f) => f.endsWith('.sql')).sort()) {
        await restored.unsafe(readFileSync(join(migrationsDir, file), 'utf8'));
      }

      await loadSnapshot(restored, snapshot);

      // ---- The properties that actually matter ---------------------------

      // 1. The audit chain verifies end to end in the restored database. This is the
      //    strictest check available: if the sequence, the links or any event content
      //    changed in transit, verification fails at the exact event.
      const events = await restored<Record<string, unknown>[]>`
        SELECT event_reference, sequence, actor_id, actor_level, event_class, action,
               object_type, object_id, outcome, occurred_at, previous_state, new_state,
               security_context, detail, correlation_id, previous_hash, event_hash
          FROM audit_events WHERE organization_id = ${ORG} ORDER BY sequence ASC
      `;
      expect(events.length).toBeGreaterThanOrEqual(5);

      const verification = await verifyChain(
        events.map(
          (r): AuditEvent => ({
            eventId: r.event_reference as string,
            organizationId: ORG,
            actorId: r.actor_id as string,
            actorLevel: r.actor_level as string | null,
            eventClass: r.event_class as AuditEvent['eventClass'],
            action: r.action as string,
            objectType: r.object_type as string,
            objectId: r.object_id as string | null,
            outcome: r.outcome as AuditEvent['outcome'],
            occurredAt: new Date(r.occurred_at as string).toISOString(),
            previousState: r.previous_state,
            newState: r.new_state,
            securityContext: r.security_context as Record<string, unknown>,
            detail: r.detail as Record<string, unknown>,
            correlationId: r.correlation_id as string,
            previousHash: r.previous_hash as string,
            eventHash: r.event_hash as string,
            sequence: Number(r.sequence),
          }),
        ),
        GENESIS_HASH,
      );
      if (!verification.valid) {
        // Diagnostic: compare the original and restored rows field by field.
        const source = await harness.sql<Record<string, unknown>[]>`
          SELECT * FROM audit_events WHERE organization_id = ${ORG} ORDER BY sequence ASC
        `;
        const target = await restored<Record<string, unknown>[]>`
          SELECT * FROM audit_events WHERE organization_id = ${ORG} ORDER BY sequence ASC
        `;
        for (const [index, before] of source.entries()) {
          const after = target[index];
          if (!after) { console.log(`  MISSING event ${index}`); continue; }
          for (const key of Object.keys(before)) {
            const a = before[key] instanceof Date ? (before[key] as Date).toISOString() : JSON.stringify(before[key]);
            const b = after[key] instanceof Date ? (after[key] as Date).toISOString() : JSON.stringify(after[key]);
            if (a !== b) console.log(`  seq ${index + 1} DIFFERS ${key}: ${a} -> ${b}`);
          }
        }
      }
      expect(verification.reason ?? 'chain verifies').toBe('chain verifies');
      expect(verification.valid).toBe(true);

      // 2. Batch totals reconcile against their instruction rows.
      const drift = await restored<{ count: string }[]>`
        SELECT COUNT(*) AS count FROM (
          SELECT b.id
            FROM payment_batches b
            JOIN payment_instructions pi ON pi.batch_id = b.id
           GROUP BY b.id, b.total_amount_cents
          HAVING b.total_amount_cents <> SUM(pi.amount_cents)
        ) mismatched
      `;
      expect(Number(drift[0]!.count)).toBe(0);

      // 3. Settled transactions still carry their evidence.
      const missingReceipt = await restored<{ count: string }[]>`
        SELECT COUNT(*) AS count FROM transactions
         WHERE status = 'SUCCESS' AND (mpesa_receipt_number IS NULL OR mpesa_receipt_number = '')
      `;
      expect(Number(missingReceipt[0]!.count)).toBe(0);

      // 4. The payment data is genuinely there.
      const transactions = await restored<{ mpesa_receipt_number: string; amount_cents: string }[]>`
        SELECT mpesa_receipt_number, amount_cents FROM transactions WHERE organization_id = ${ORG}
      `;
      expect(transactions).toHaveLength(1);
      expect(transactions[0]!.mpesa_receipt_number).toBe('SG632NMUAB');
      expect(Number(transactions[0]!.amount_cents)).toBe(4_500_000);

      // 5. Restored users exist but cannot sign in: the sentinel is not a valid Argon2
      //    encoding, and the account is marked for re-enrolment.
      const restoredUsers = await restored<{ password_hash: string; status: string; authority_level: string }[]>`
        SELECT password_hash, status, authority_level FROM users WHERE organization_id = ${ORG}
      `;
      expect(restoredUsers).toHaveLength(1);
      expect(restoredUsers[0]!.status).toBe('PENDING_ENROLMENT');
      expect(restoredUsers[0]!.password_hash).not.toMatch(/^\$argon2id\$/);
      const { verifyPassword } = await import('./services/crypto.js');
      expect(await verifyPassword('anything at all', restoredUsers[0]!.password_hash)).toBe(false);

      // 6. And the immutability guarantees are back in force after the load.
      await expect(
        restored`DELETE FROM audit_events WHERE organization_id = ${ORG}`,
      ).rejects.toThrow(/SOLVAREN immutability/);
    } finally {
      await restored.end({ timeout: 5 });
      const cleanup = postgres(adminUrl, { max: 1, onnotice: () => {} });
      await cleanup.unsafe(`DROP DATABASE IF EXISTS ${restoreName} WITH (FORCE)`).catch(() => {});
      await cleanup.end({ timeout: 5 });
    }
  }, 90_000);

  it('AC-12: retention removes the oldest objects beyond the configured count', async () => {
    // Retention is 3. Run enough backups to exceed it.
    for (let i = 0; i < 4; i++) {
      await runBackup(harness.sql, harness.env, {
        type: 'RUN_BACKUP',
        organizationId: ORG,
        trigger: 'SCHEDULED',
        correlationId: `cor_RET${i}`,
      });
    }
    await enforceRetention(harness.sql, harness.env, {
      type: 'ENFORCE_RETENTION',
      organizationId: ORG,
      trigger: 'SCHEDULED',
      correlationId: 'cor_RETFINAL',
    });

    // Retention keeps the attempt record and its object key as evidence of what was
    // written; `object_retired_at` is what says the object is gone.
    const retained = await harness.sql<{ count: string }[]>`
      SELECT COUNT(*) AS count FROM backup_attempts
       WHERE organization_id = ${ORG} AND status = 'SUCCESS' AND object_retired_at IS NULL
    `;
    expect(Number(retained[0]!.count)).toBeLessThanOrEqual(3);

    // And the objects really are gone from storage, not merely marked.
    const liveKeys = await harness.sql<{ object_key: string }[]>`
      SELECT object_key FROM backup_attempts
       WHERE organization_id = ${ORG} AND status = 'SUCCESS' AND object_retired_at IS NOT NULL
    `;
    for (const row of liveKeys) {
      expect(harness.r2.objects.has(row.object_key)).toBe(false);
    }
    expect(liveKeys.length).toBeGreaterThan(0);

    // The attempt *records* survive — they are the audit evidence that the backup existed
    // and was retired. Only the objects go.
    const allAttempts = await harness.sql<{ count: string }[]>`
      SELECT COUNT(*) AS count FROM backup_attempts WHERE organization_id = ${ORG}
    `;
    expect(Number(allAttempts[0]!.count)).toBeGreaterThan(3);
  }, 60_000);

  it('§13.7: a failure is never recorded as a success', async () => {
    const other = '00000000-0000-0000-0000-0000000ba099';
    await harness.sql`
      INSERT INTO organizations (id, name, slug) VALUES (${other}, 'No Target Co', 'no-target')
    `;

    // No backup configuration at all for this organisation.
    await runBackup(harness.sql, harness.env, {
      type: 'RUN_BACKUP',
      organizationId: other,
      trigger: 'MANUAL',
      requestedByUserId: null as never,
      correlationId: 'cor_NOTARGET',
    });

    const attempts = await harness.sql<{ status: string; error_message: string }[]>`
      SELECT status, error_message FROM backup_attempts
       WHERE organization_id = ${other} ORDER BY started_at DESC LIMIT 1
    `;
    expect(attempts[0]!.status).toBe('FAILED');
    expect(attempts[0]!.error_message).toBeTruthy();
  });

  it('a backup attempt cannot be re-reported with a different outcome', async () => {
    const attempts = await harness.sql<{ id: string }[]>`
      SELECT id FROM backup_attempts
       WHERE organization_id = ${ORG} AND status = 'SUCCESS' LIMIT 1
    `;
    await expect(
      harness.sql`UPDATE backup_attempts SET status = 'FAILED' WHERE id = ${attempts[0]!.id}`,
    ).rejects.toThrow(/SOLVAREN immutability/);
  });
});

/**
 * Load a snapshot, mirroring scripts/restore-snapshot.mjs.
 *
 * The two things that made this non-trivial, both found by this test:
 *
 *  1. **JSONB must be cast, not stringified.** Passing `JSON.stringify(value)` as a plain
 *     parameter stores the JSON *text* as a JSONB string — `"{\"state\":\"A\"}"` rather
 *     than `{"state":"A"}`. Every row loads, nothing errors, and every JSONB column is
 *     silently wrong. The audit chain then fails to verify, which is how it surfaced.
 *  2. **Credential columns are absent from the snapshot by design**, but `password_hash`
 *     is NOT NULL. The loader supplies a sentinel no password can match and marks the
 *     account for re-enrolment.
 */
async function loadSnapshot(sql: postgres.Sql<{}>, snapshot: { data: Record<string, unknown[]> }) {
  const order = [
    'organizations', 'policies', 'users', 'webauthn_credentials', 'trusted_devices',
    'recovery_codes', 'conflict_registrations', 'departments', 'recipients',
    'payment_batches', 'payment_instructions', 'approvals', 'batch_editors',
    'authorization_challenges', 'idempotency_claims', 'transactions', 'provider_callbacks',
    'reconciliation_cases', 'risk_findings', 'account_balance_snapshots', 'audit_events',
    'daraja_configurations', 'failure_reason_map', 'backup_configurations',
    'backup_attempts', 'export_records', 'batch_templates', 'payment_calendar',
    'ai_interactions', 'security_events',
  ];

  const triggers: [string, string][] = [
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

  for (const [table, trigger] of triggers) {
    await sql.unsafe(`ALTER TABLE ${table} DISABLE TRIGGER ${trigger}`).catch(() => {});
  }

  try {
    for (const table of order) {
      const rows = snapshot.data[table];
      if (!Array.isArray(rows) || rows.length === 0) continue;

      // Ask PostgreSQL what each column is. JSONB must be wrapped with `sql.json()`:
      // postgres.js types a plain string parameter as JSONB when the column is JSONB, so
      // `JSON.stringify(value)` is stored as a JSONB *string* rather than an object, and an
      // explicit `::jsonb` cast does not help because the parameter is already JSONB-typed.
      const typeRows = await sql<{ column_name: string; data_type: string }[]>`
        SELECT column_name, data_type
          FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = ${table}
      `;
      const types = new Map(typeRows.map((r) => [r.column_name, r.data_type]));

      for (const original of rows as Record<string, unknown>[]) {
        const withCredentials =
          table === 'users'
            ? {
                ...original,
                password_hash: '$solvaren-restored$credential-must-be-re-enrolled',
                authorization_pin_hash: null,
                status: 'PENDING_ENROLMENT',
              }
            : original;

        const row: Record<string, unknown> = {};
        for (const [column, value] of Object.entries(withCredentials)) {
          const type = types.get(column);
          row[column] = type === 'jsonb' || type === 'json' ? sql.json(value as never) : value;
        }

        const columns = Object.keys(row);
        await sql`
          INSERT INTO ${sql(table)} ${sql(row, ...columns)}
          ON CONFLICT DO NOTHING
        `;
      }
    }
  } finally {
    for (const [table, trigger] of triggers) {
      await sql.unsafe(`ALTER TABLE ${table} ENABLE TRIGGER ${trigger}`).catch(() => {});
    }
  }
}
