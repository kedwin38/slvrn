/**
 * Backup worker (spec 13).
 *
 * Three properties the spec insists on, and how each is achieved here:
 *
 *   - **"A failed backup must never be presented as successful"** (13.7). Every attempt
 *     writes a STARTED row first, and the terminal status is only ever set from what
 *     actually happened. The schema refuses a SUCCESS without an object key and size, so
 *     an optimistic bug cannot produce a green tick over an empty bucket.
 *   - **"Retention deletion failure -> record partial result; do not claim retention
 *     complete"** (22). Retention runs only after a new backup is durably committed, and
 *     `retention_complete` stays false unless every deletion succeeded.
 *   - **Asynchronous and observable** (13.3, BAK-004). The browser request that asks for a
 *     backup returns immediately with an attempt reference; this worker does the work.
 *
 * The snapshot mechanism is pluggable because it depends on the PostgreSQL host (spec 28
 * lists it as an open decision). The logical exporter here works on any managed
 * PostgreSQL, including hosts that do not expose `pg_dump`.
 */

import { reference, formatCents } from '@solvaren/core';
import { withConnection, inTransaction, type Sql } from '../db/client.js';
import { writeAuditEvent } from '../db/audit-writer.js';
import type { BackupQueueMessage, Env } from '../env.js';

/** Tables included in a full logical snapshot, in dependency order for restoration. */
const SNAPSHOT_TABLES = [
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
] as const;

/**
 * Columns excluded from every snapshot.
 *
 * Session tokens and credential hashes are not restored from a backup — a restore must not
 * resurrect live sessions, and password material has no business travelling to object
 * storage even hashed. Secret *references* are included because they are only names.
 */
const EXCLUDED_COLUMNS: Record<string, string[]> = {
  sessions: ['*'],
  users: ['password_hash', 'authorization_pin_hash'],
  recovery_codes: ['code_hash'],
};

export async function handleBackupBatch(
  batch: MessageBatch<BackupQueueMessage>,
  env: Env,
  ctx: ExecutionContext,
): Promise<void> {
  await withConnection(env, ctx, async (sql) => {
    for (const message of batch.messages) {
      try {
        if (message.body.type === 'RUN_BACKUP') {
          await runBackup(sql, env, message.body);
        } else {
          await enforceRetention(sql, env, message.body);
        }
        message.ack();
      } catch (err) {
        // The attempt row already carries the failure; the message itself is done.
        console.error(
          JSON.stringify({
            level: 'error',
            message: 'Backup job failed',
            organizationId: message.body.organizationId,
            error: err instanceof Error ? err.message : String(err),
          }),
        );
        message.ack();
      }
    }
  });
}

export async function runBackup(sql: Sql, env: Env, message: BackupQueueMessage): Promise<void> {
  const configs = await sql<
    {
      id: string;
      bucket: string;
      path_prefix: string;
      provider_label: string;
      endpoint: string | null;
      retention_max_count: number;
      consecutive_failures: number;
      suspended_at: string | null;
    }[]
  >`
    SELECT id, bucket, path_prefix, provider_label, endpoint, retention_max_count,
           consecutive_failures, suspended_at
      FROM backup_configurations
     WHERE organization_id = ${message.organizationId}
     LIMIT 1
  `;
  const config = configs[0];

  const attemptReference = message.attemptId ?? reference('BAK');
  const targetDescription = config
    ? `${config.provider_label} ${config.bucket}/${config.path_prefix}`
    : 'unconfigured';

  if (!config) {
    await recordFailure(
      sql,
      message,
      attemptReference,
      targetDescription,
      'BACKUP_NOT_CONFIGURED',
      'No backup target is configured for this organisation',
    );
    return;
  }

  // Spec 22: stop hammering a target whose credentials are rejected.
  if (config.suspended_at) {
    await recordFailure(
      sql,
      message,
      attemptReference,
      targetDescription,
      'BACKUP_SUSPENDED',
      'Backups are suspended after repeated failures. An administrator must correct the target configuration.',
    );
    return;
  }

  const startedAt = new Date();
  const attemptRows = await sql<{ id: string }[]>`
    INSERT INTO backup_attempts (
      organization_id, attempt_reference, trigger_type, status, started_at,
      target_description, actor_user_id, correlation_id
    ) VALUES (
      ${message.organizationId}, ${attemptReference}, ${message.trigger}, 'STARTED', ${startedAt},
      ${targetDescription}, ${message.requestedByUserId ?? null}, ${message.correlationId}
    )
    ON CONFLICT (organization_id, attempt_reference) DO NOTHING
    RETURNING id
  `;
  if (!attemptRows[0]) return; // already running under this reference

  const attemptId = attemptRows[0].id;

  try {
    const snapshot = await buildLogicalSnapshot(sql, message.organizationId);

    // Object naming deliberately carries no payroll information (spec 13.7): the
    // organisation is identified by opaque id, and nothing about amounts or people
    // appears in the key.
    const stamp = startedAt.toISOString().replace(/[:.]/g, '-');
    const objectKey = `${config.path_prefix}/${message.organizationId}/${stamp}-${attemptReference}.json`;

    const body = JSON.stringify(snapshot);
    const checksum = await sha256Hex(body);

    await env.ARTIFACTS.put(objectKey, body, {
      httpMetadata: { contentType: 'application/json', cacheControl: 'no-store' },
      customMetadata: {
        attemptReference,
        organizationId: message.organizationId,
        checksumSha256: checksum,
        solvarenSchemaVersion: '2.0',
      },
    });

    // Read back before claiming success: an object that is not retrievable is not a backup.
    const verification = await env.ARTIFACTS.head(objectKey);
    if (!verification || verification.size === 0) {
      throw new Error('The backup object could not be verified after upload');
    }

    await inTransaction(sql, async (tx) => {
      await tx`
        UPDATE backup_attempts
           SET status = 'SUCCESS', ended_at = now(), object_key = ${objectKey},
               size_bytes = ${verification.size}, checksum = ${checksum},
               checksum_algorithm = 'SHA-256'
         WHERE id = ${attemptId}
      `;
      await tx`
        UPDATE backup_configurations
           SET consecutive_failures = 0, status = 'CONNECTED',
               last_scheduled_run_at = ${message.trigger === 'SCHEDULED' ? startedAt : null}
         WHERE id = ${config.id}
      `;
      await writeAuditEvent(tx, {
        organizationId: message.organizationId,
        actorId: message.requestedByUserId ?? 'system:backup-worker',
        actorLevel: message.requestedByUserId ? 'L3' : null,
        eventClass: 'BACKUP',
        action: 'backup.completed',
        objectType: 'BackupAttempt',
        objectId: attemptId,
        outcome: 'SUCCESS',
        correlationId: message.correlationId,
        detail: {
          attemptReference,
          objectKey,
          sizeBytes: verification.size,
          checksum,
          rowCount: snapshot.metadata.totalRows,
          trigger: message.trigger,
        },
      });
    });

    // Retention runs only now — after the new backup is durably committed (spec 13.5).
    await enforceRetention(sql, env, { ...message, type: 'ENFORCE_RETENTION' });
  } catch (err) {
    const messageText = sanitizeError(err);
    await inTransaction(sql, async (tx) => {
      await tx`
        UPDATE backup_attempts
           SET status = 'FAILED', ended_at = now(), error_code = 'BACKUP_FAILED',
               error_message = ${messageText}
         WHERE id = ${attemptId}
      `;
      const failures = await tx<{ consecutive_failures: number }[]>`
        UPDATE backup_configurations
           SET consecutive_failures = consecutive_failures + 1, status = 'ERROR',
               last_test_message = ${messageText},
               suspended_at = CASE WHEN consecutive_failures + 1 >= 5 THEN now() ELSE suspended_at END,
               suspension_reason = CASE WHEN consecutive_failures + 1 >= 5
                                        THEN 'Suspended after five consecutive failures'
                                        ELSE suspension_reason END
         WHERE id = ${config.id}
        RETURNING consecutive_failures
      `;
      await tx`
        INSERT INTO security_events (organization_id, event_type, severity, description, detail)
        VALUES (
          ${message.organizationId}, 'BACKUP_FAILED', 'WARNING',
          ${'A database backup failed'},
          ${tx.json({ attemptReference, error: messageText, consecutiveFailures: failures[0]?.consecutive_failures } as never)}
        )
      `;
      await writeAuditEvent(tx, {
        organizationId: message.organizationId,
        actorId: message.requestedByUserId ?? 'system:backup-worker',
        actorLevel: null,
        eventClass: 'BACKUP',
        action: 'backup.failed',
        objectType: 'BackupAttempt',
        objectId: attemptId,
        outcome: 'FAILURE',
        correlationId: message.correlationId,
        detail: { attemptReference, error: messageText },
      });
    });
  }
}

/**
 * Delete backups beyond the retention count (spec 13.5).
 *
 * Oldest first, and only ever beyond the limit. If any deletion fails, the run is recorded
 * as partial — spec 22: "do not claim retention complete."
 */
export async function enforceRetention(
  sql: Sql,
  env: Env,
  message: BackupQueueMessage,
): Promise<void> {
  const configs = await sql<{ id: string; retention_max_count: number }[]>`
    SELECT id, retention_max_count FROM backup_configurations
     WHERE organization_id = ${message.organizationId} LIMIT 1
  `;
  const config = configs[0];
  if (!config) return;

  const surplus = await sql<{ id: string; object_key: string; attempt_reference: string }[]>`
    SELECT id, object_key, attempt_reference
      FROM backup_attempts
     WHERE organization_id = ${message.organizationId}
       AND status = 'SUCCESS'
       AND object_key IS NOT NULL
       AND object_retired_at IS NULL
     ORDER BY started_at DESC
     OFFSET ${config.retention_max_count}
  `;

  if (surplus.length === 0) return;

  let deleted = 0;
  const failures: string[] = [];

  for (const backup of surplus) {
    try {
      await env.ARTIFACTS.delete(backup.object_key);
      /*
       * The attempt row is never deleted — it is the evidence that the backup existed and
       * was retired — and the object key stays on it as the record of what was written.
       * Only a marker is added.
       *
       * An earlier version set `object_key = NULL` here, which the
       * `backup_success_requires_object` constraint rightly refuses: a SUCCESS attempt
       * must name an object. The UPDATE failed, the error was swallowed as a retention
       * failure, and the record went on claiming an object that storage no longer held.
       * A dedicated marker keeps the constraint honest and the history accurate.
       */
      await sql`
        UPDATE backup_attempts
           SET object_retired_at = now()
         WHERE id = ${backup.id} AND object_retired_at IS NULL
      `;
      deleted += 1;
    } catch (err) {
      failures.push(`${backup.attempt_reference}: ${sanitizeError(err)}`);
    }
  }

  await inTransaction(sql, async (tx) => {
    const latest = await tx<{ id: string }[]>`
      SELECT id FROM backup_attempts
       WHERE organization_id = ${message.organizationId} AND status = 'SUCCESS'
       ORDER BY started_at DESC LIMIT 1
    `;
    if (latest[0]) {
      await tx`
        UPDATE backup_attempts
           SET retention_deleted_count = ${deleted},
               retention_retained_count = ${config.retention_max_count},
               retention_complete = ${failures.length === 0}
         WHERE id = ${latest[0].id}
      `;
    }
    await writeAuditEvent(tx, {
      organizationId: message.organizationId,
      actorId: 'system:backup-worker',
      actorLevel: null,
      eventClass: 'BACKUP',
      action: failures.length === 0 ? 'backup.retention.enforced' : 'backup.retention.partial',
      objectType: 'BackupConfiguration',
      objectId: config.id,
      outcome: failures.length === 0 ? 'SUCCESS' : 'FAILURE',
      correlationId: message.correlationId,
      detail: {
        deleted,
        retained: config.retention_max_count,
        failures: failures.length > 0 ? failures : undefined,
        complete: failures.length === 0,
      },
    });
  });
}

interface Snapshot {
  metadata: {
    solvarenVersion: string;
    organizationId: string;
    takenAt: string;
    totalRows: number;
    tables: { name: string; rows: number }[];
    excludedColumns: Record<string, string[]>;
    note: string;
  };
  data: Record<string, unknown[]>;
}

/**
 * Build a point-in-time consistent logical snapshot.
 *
 * REPEATABLE READ is what makes it point-in-time: every table is read from the same
 * snapshot of the database, so the transactions table cannot contain a row whose batch is
 * missing because it was created between two SELECTs.
 */
async function buildLogicalSnapshot(sql: Sql, organizationId: string): Promise<Snapshot> {
  const data: Record<string, unknown[]> = {};
  const tables: { name: string; rows: number }[] = [];
  let totalRows = 0;

  await sql.begin(async (tx) => {
    await tx`SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY`;

    for (const table of SNAPSHOT_TABLES) {
      const excluded = EXCLUDED_COLUMNS[table] ?? [];
      if (excluded.includes('*')) continue;

      // `organizations` is keyed by id rather than organization_id; everything else is
      // tenant-scoped, so a snapshot contains exactly one organisation's data.
      const rows =
        table === 'organizations'
          ? await tx.unsafe(`SELECT * FROM organizations WHERE id = $1`, [organizationId])
          : table === 'batch_editors'
            ? await tx.unsafe(
                `SELECT be.* FROM batch_editors be
                   JOIN payment_batches b ON b.id = be.batch_id
                  WHERE b.organization_id = $1`,
                [organizationId],
              )
            : table === 'failure_reason_map'
              ? await tx.unsafe(
                  `SELECT * FROM failure_reason_map WHERE organization_id = $1 OR organization_id IS NULL`,
                  [organizationId],
                )
              : await tx.unsafe(`SELECT * FROM ${table} WHERE organization_id = $1`, [organizationId]);

      const sanitized = (rows as Record<string, unknown>[]).map((row) => {
        const copy = { ...row };
        for (const column of excluded) delete copy[column];
        return copy;
      });

      data[table] = sanitized;
      tables.push({ name: table, rows: sanitized.length });
      totalRows += sanitized.length;
    }
  });

  return {
    metadata: {
      solvarenVersion: '2.0',
      organizationId,
      takenAt: new Date().toISOString(),
      totalRows,
      tables,
      excludedColumns: EXCLUDED_COLUMNS,
      note:
        'Point-in-time consistent logical snapshot taken under REPEATABLE READ. ' +
        'Credential hashes and sessions are deliberately excluded and are not restorable from this file. ' +
        'A backup that has never been restore-validated is not disaster-recovery proven (spec 13.7).',
    },
    data,
  };
}

async function recordFailure(
  sql: Sql,
  message: BackupQueueMessage,
  attemptReference: string,
  target: string,
  code: string,
  text: string,
): Promise<void> {
  await inTransaction(sql, async (tx) => {
    await tx`
      INSERT INTO backup_attempts (
        organization_id, attempt_reference, trigger_type, status, started_at, ended_at,
        target_description, error_code, error_message, actor_user_id, correlation_id
      ) VALUES (
        ${message.organizationId}, ${attemptReference}, ${message.trigger}, 'FAILED',
        now(), now(), ${target}, ${code}, ${text}, ${message.requestedByUserId ?? null},
        ${message.correlationId}
      )
      ON CONFLICT (organization_id, attempt_reference) DO NOTHING
    `;
    await writeAuditEvent(tx, {
      organizationId: message.organizationId,
      actorId: message.requestedByUserId ?? 'system:backup-worker',
      actorLevel: null,
      eventClass: 'BACKUP',
      action: 'backup.failed',
      objectType: 'BackupAttempt',
      objectId: attemptReference,
      outcome: 'FAILURE',
      correlationId: message.correlationId,
      detail: { errorCode: code, error: text },
    });
  });
}

/**
 * Sanitize a provider error before it is stored (spec 13.7).
 * A raw S3 error can contain a presigned URL, which is a credential.
 */
function sanitizeError(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  return raw
    .replace(/https?:\/\/[^\s]+/g, '[url removed]')
    .replace(/[A-Za-z0-9+/]{40,}={0,2}/g, '[redacted]')
    .slice(0, 500);
}

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

void formatCents;
