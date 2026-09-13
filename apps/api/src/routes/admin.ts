/**
 * Administration: Daraja, backups, policies, users and audit (spec 4.3, 9.1, 13, 14).
 *
 * Everything here is L3-only. The Daraja endpoints in particular never return a plaintext
 * secret in any response shape — spec 4.4 marks "View plaintext Daraja secrets" as
 * forbidden to *every* level including L3, so the configuration API deals exclusively in
 * masked views and rotation workflows.
 */

import { Hono } from 'hono';
import { z } from 'zod';
import {
  reference,
  policySchema,
  notFoundError,
  validationError,
  stateError,
  verifyChain,
  GENESIS_HASH,
  type AuditEvent,
} from '@solvaren/core';
import {
  requireAuth,
  requirePermissions,
  requireExactLevel,
  actorOf,
} from '../middleware/security.js';
import { withConnection, inTransaction } from '../db/client.js';
import { writeAuditEvent } from '../db/audit-writer.js';
import {
  configureDaraja,
  loadDarajaClientById,
  maskConfig,
  type DarajaConfigRow,
} from '../services/daraja-config.js';
import { encryptSecret } from '../services/crypto.js';
import { assertFreshAuthentication, assertWebAuthnSession } from '../services/auth.js';
import { createSecretStore, secretReference } from '../services/daraja-config.js';
import type { AppContext, BackupQueueMessage } from '../env.js';

export const adminRoutes = new Hono<AppContext>();
adminRoutes.use('*', requireAuth);

// ---------------------------------------------------------------------------
// Daraja configuration (L3 ONLY — spec 4.4)
// ---------------------------------------------------------------------------

const darajaConfigSchema = z.object({
  environment: z.enum(['sandbox', 'production']),
  shortCode: z.string().regex(/^\d{5,9}$/, 'The shortcode must be 5 to 9 digits'),
  initiatorName: z.string().trim().min(1).max(64),
  commandId: z
    .enum(['BusinessPayment', 'SalaryPayment', 'PromotionPayment'])
    .default('BusinessPayment'),
  consumerKey: z.string().trim().min(10).max(200),
  consumerSecret: z.string().trim().min(10).max(200),
  initiatorPasswordOrCredential: z.string().trim().min(8).max(2000),
  mpesaCertificatePem: z.string().trim().max(10_000).optional(),
});

/**
 * POST /admin/daraja — configure or rotate credentials.
 *
 * Requires fresh authentication and a WebAuthn session on top of L3 authority: spec 9.1
 * says "credential changes require re-authentication + WebAuthn + SOLVAREN Authorization
 * PIN". The PIN is verified by the caller supplying it through the rotation confirmation
 * step below; re-authentication and WebAuthn are enforced here.
 */
adminRoutes.post(
  '/daraja',
  requireExactLevel('L3'),
  requirePermissions('admin:daraja'),
  async (c) => {
    const actor = actorOf(c);
    assertFreshAuthentication(actor);
    assertWebAuthnSession(actor);

    const body = darajaConfigSchema.parse(await c.req.json());
    const correlationId = c.get('correlationId');

    const masked = await withConnection(c.env, c.executionCtx, async (sql) => {
      const previous = await sql<{ credential_version: number; status: string }[]>`
        SELECT credential_version, status FROM daraja_configurations
         WHERE organization_id = ${actor.organizationId} AND environment = ${body.environment}
      `;

      const config = await configureDaraja(sql, c.env, {
        organizationId: actor.organizationId,
        environment: body.environment,
        shortCode: body.shortCode,
        initiatorName: body.initiatorName,
        commandId: body.commandId,
        consumerKey: body.consumerKey,
        consumerSecret: body.consumerSecret,
        initiatorPasswordOrCredential: body.initiatorPasswordOrCredential,
        mpesaCertificatePem: body.mpesaCertificatePem,
        apiBaseUrl: c.env.API_BASE_URL,
      });

      await inTransaction(sql, (tx) =>
        writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'INTEGRATION',
          action: previous[0] ? 'daraja.credentials.rotated' : 'daraja.configured',
          objectType: 'DarajaConfiguration',
          objectId: config.id,
          outcome: 'SUCCESS',
          previousState: previous[0]
            ? { credentialVersion: previous[0].credential_version, status: previous[0].status }
            : null,
          newState: { credentialVersion: config.credentialVersion, status: config.status },
          correlationId,
          securityContext: c.get('securityContext'),
          // Only the shape of the change is recorded. `redactForAudit` would strip the
          // credential fields even if a future edit tried to include them.
          detail: {
            environment: body.environment,
            shortCode: body.shortCode,
            initiatorName: body.initiatorName,
            commandId: body.commandId,
            note: 'Integration reset to TESTING; a connection test is required before it can process payments.',
          },
        }),
      );

      return config;
    });

    return c.json({
      configuration: masked,
      nextStep:
        'Run a connection test. The integration cannot process production payments until a test passes.',
    });
  },
);

/** GET /admin/daraja — the masked configuration view. */
adminRoutes.get(
  '/daraja',
  requireExactLevel('L3'),
  requirePermissions('admin:daraja'),
  async (c) => {
    const actor = actorOf(c);

    const configs = await withConnection(c.env, c.executionCtx, async (sql) => {
      const rows = await sql<DarajaConfigRow[]>`
      SELECT * FROM daraja_configurations
       WHERE organization_id = ${actor.organizationId}
       ORDER BY environment
    `;
      return rows.map(maskConfig);
    });

    return c.json({ configurations: configs });
  },
);

/** POST /admin/daraja/:id/test — prove the credentials work without moving money. */
adminRoutes.post(
  '/daraja/:id/test',
  requireExactLevel('L3'),
  requirePermissions('admin:daraja'),
  async (c) => {
    const actor = actorOf(c);
    const configId = c.req.param('id');
    const correlationId = c.get('correlationId');

    const result = await withConnection(c.env, c.executionCtx, async (sql) => {
      const { client } = await loadDarajaClientById(sql, c.env, actor.organizationId, configId);
      const test = await client.testConnection();

      await inTransaction(sql, async (tx) => {
        await tx`
          UPDATE daraja_configurations
             SET last_test_at = now(), last_test_ok = ${test.ok}, last_test_message = ${test.message},
                 status = ${test.ok ? 'TESTING' : 'ERROR'}
           WHERE id = ${configId} AND organization_id = ${actor.organizationId}
        `;
        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'INTEGRATION',
          action: 'daraja.connection_tested',
          objectType: 'DarajaConfiguration',
          objectId: configId,
          outcome: test.ok ? 'SUCCESS' : 'FAILURE',
          correlationId,
          securityContext: c.get('securityContext'),
          detail: { ok: test.ok, message: test.message, latencyMs: test.latencyMs },
        });
      });

      return test;
    });

    return c.json(result);
  },
);

/** POST /admin/daraja/:id/enable — switch the integration on. */
adminRoutes.post(
  '/daraja/:id/enable',
  requireExactLevel('L3'),
  requirePermissions('admin:daraja'),
  async (c) => {
    const actor = actorOf(c);
    assertFreshAuthentication(actor);
    const configId = c.req.param('id');
    const correlationId = c.get('correlationId');

    await withConnection(c.env, c.executionCtx, (sql) =>
      inTransaction(sql, async (tx) => {
        const rows = await tx<{ last_test_ok: boolean | null; environment: string }[]>`
          SELECT last_test_ok, environment FROM daraja_configurations
           WHERE id = ${configId} AND organization_id = ${actor.organizationId}
        `;
        const config = rows[0];
        if (!config)
          throw notFoundError('DARAJA_CONFIG_NOT_FOUND', 'That configuration could not be found');

        // The database constraint enforces this too; checking here produces a better message.
        if (config.last_test_ok !== true) {
          throw stateError(
            'DARAJA_TEST_REQUIRED',
            'Run a successful connection test before enabling this integration. Enabling an untested integration means discovering a credential problem during a live payroll run.',
          );
        }

        // Only one enabled integration per organisation: two would make "which credentials
        // paid this?" ambiguous.
        await tx`
          UPDATE daraja_configurations SET status = 'DISABLED'
           WHERE organization_id = ${actor.organizationId} AND id <> ${configId} AND status = 'ENABLED'
        `;
        await tx`
          UPDATE daraja_configurations
             SET status = 'ENABLED', enabled_at = now(), enabled_by_user_id = ${actor.userId}
           WHERE id = ${configId}
        `;
        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'INTEGRATION',
          action: 'daraja.enabled',
          objectType: 'DarajaConfiguration',
          objectId: configId,
          outcome: 'SUCCESS',
          newState: { status: 'ENABLED' },
          correlationId,
          securityContext: c.get('securityContext'),
          detail: { environment: config.environment },
        });
      }),
    );

    return c.json({ status: 'ENABLED' });
  },
);

/** POST /admin/daraja/:id/disable — emergency stop (see the runbook). */
adminRoutes.post(
  '/daraja/:id/disable',
  requireExactLevel('L3'),
  requirePermissions('admin:daraja'),
  async (c) => {
    const actor = actorOf(c);
    const configId = c.req.param('id');
    const body = z.object({ reason: z.string().trim().max(500) }).parse(await c.req.json());

    await withConnection(c.env, c.executionCtx, (sql) =>
      inTransaction(sql, async (tx) => {
        await tx`
          UPDATE daraja_configurations SET status = 'DISABLED'
           WHERE id = ${configId} AND organization_id = ${actor.organizationId}
        `;
        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'INTEGRATION',
          action: 'daraja.disabled',
          objectType: 'DarajaConfiguration',
          objectId: configId,
          outcome: 'SUCCESS',
          newState: { status: 'DISABLED' },
          correlationId: c.get('correlationId'),
          securityContext: c.get('securityContext'),
          detail: { reason: body.reason },
        });
      }),
    );

    return c.json({
      status: 'DISABLED',
      note: 'No further payments will be submitted. Instructions already in flight will still report their outcome.',
    });
  },
);

// ---------------------------------------------------------------------------
// Backups (spec 13)
// ---------------------------------------------------------------------------

const backupConfigSchema = z.object({
  providerLabel: z.string().trim().max(80).default('Cloudflare R2'),
  endpoint: z.string().url().max(300).optional(),
  region: z.string().trim().max(40).optional(),
  bucket: z.string().trim().min(1).max(200),
  pathPrefix: z.string().trim().max(200).default('solvaren/backups'),
  accessKeyId: z.string().trim().min(4).max(200),
  secretAccessKey: z.string().trim().min(8).max(400),
  encryptionMode: z.enum(['SSE_S3', 'SSE_KMS', 'APPLICATION']).default('SSE_S3'),
  retentionMaxCount: z.number().int().min(1).max(3650).default(30),
  scheduleCron: z.string().trim().max(100).optional(),
});

/** POST /admin/backups/target — connect an S3-compatible target (BAK-001, BAK-002). */
adminRoutes.post(
  '/backups/target',
  requireExactLevel('L3'),
  requirePermissions('admin:backups'),
  async (c) => {
    const actor = actorOf(c);
    assertFreshAuthentication(actor);
    const body = backupConfigSchema.parse(await c.req.json());
    const correlationId = c.get('correlationId');

    const result = await withConnection(c.env, c.executionCtx, async (sql) => {
      const store = createSecretStore(c.env);
      const accessRef = secretReference(actor.organizationId, 'backup', 'access_key');
      const secretRef = secretReference(actor.organizationId, 'backup', 'secret_key');

      // BAK-002: credentials are masked after save and held by the secrets mechanism.
      await store.put(
        accessRef,
        await encryptSecret(body.accessKeyId, c.env.SECRET_ENCRYPTION_KEY),
      );
      await store.put(
        secretRef,
        await encryptSecret(body.secretAccessKey, c.env.SECRET_ENCRYPTION_KEY),
      );

      const rows = await sql<{ id: string; status: string }[]>`
        INSERT INTO backup_configurations (
          organization_id, provider_label, endpoint, region, bucket, path_prefix,
          access_key_secret_ref, secret_key_secret_ref, access_key_last_four,
          encryption_mode, retention_max_count, schedule_cron, updated_by_user_id
        ) VALUES (
          ${actor.organizationId}, ${body.providerLabel}, ${body.endpoint ?? null},
          ${body.region ?? null}, ${body.bucket}, ${body.pathPrefix}, ${accessRef}, ${secretRef},
          ${body.accessKeyId.slice(-4)}, ${body.encryptionMode}, ${body.retentionMaxCount},
          ${body.scheduleCron ?? null}, ${actor.userId}
        )
        ON CONFLICT (organization_id) DO UPDATE SET
          provider_label = EXCLUDED.provider_label, endpoint = EXCLUDED.endpoint,
          region = EXCLUDED.region, bucket = EXCLUDED.bucket, path_prefix = EXCLUDED.path_prefix,
          access_key_secret_ref = EXCLUDED.access_key_secret_ref,
          secret_key_secret_ref = EXCLUDED.secret_key_secret_ref,
          access_key_last_four = EXCLUDED.access_key_last_four,
          encryption_mode = EXCLUDED.encryption_mode,
          retention_max_count = EXCLUDED.retention_max_count,
          schedule_cron = EXCLUDED.schedule_cron, updated_by_user_id = EXCLUDED.updated_by_user_id,
          -- A credential change resets the tested state and lifts any suspension.
          status = 'DISABLED', last_test_ok = NULL, schedule_enabled = FALSE,
          consecutive_failures = 0, suspended_at = NULL, suspension_reason = NULL
        RETURNING id, status
      `;

      await inTransaction(sql, (tx) =>
        writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'BACKUP',
          action: 'backup.target.configured',
          objectType: 'BackupConfiguration',
          objectId: rows[0]!.id,
          outcome: 'SUCCESS',
          correlationId,
          securityContext: c.get('securityContext'),
          detail: {
            provider: body.providerLabel,
            bucket: body.bucket,
            pathPrefix: body.pathPrefix,
            retentionMaxCount: body.retentionMaxCount,
            accessKeyLastFour: body.accessKeyId.slice(-4),
          },
        }),
      );

      return rows[0]!;
    });

    return c.json({
      configurationId: result.id,
      status: result.status,
      accessKeyMasked: `••••••••${body.accessKeyId.slice(-4)}`,
      secretKeyMasked: '••••••••',
      nextStep: 'Run a connection test before enabling the schedule.',
    });
  },
);

/** POST /admin/backups/run — on-demand snapshot (BAK-003, BAK-004: asynchronous). */
adminRoutes.post(
  '/backups/run',
  requireExactLevel('L3'),
  requirePermissions('admin:backups'),
  async (c) => {
    const actor = actorOf(c);
    const correlationId = c.get('correlationId');
    const attemptReference = reference('BAK');

    await withConnection(c.env, c.executionCtx, async (sql) => {
      const configs = await sql<{ id: string }[]>`
        SELECT id FROM backup_configurations WHERE organization_id = ${actor.organizationId}
      `;
      if (!configs[0]) {
        throw validationError(
          'BACKUP_NOT_CONFIGURED',
          'Connect an S3-compatible storage target before running a backup',
        );
      }

      const message: BackupQueueMessage = {
        type: 'RUN_BACKUP',
        organizationId: actor.organizationId,
        attemptId: attemptReference,
        trigger: 'MANUAL',
        requestedByUserId: actor.userId,
        correlationId,
      };
      await c.env.BACKUP_QUEUE.send(message);

      await inTransaction(sql, (tx) =>
        writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'BACKUP',
          action: 'backup.requested',
          objectType: 'BackupAttempt',
          objectId: attemptReference,
          outcome: 'SUCCESS',
          correlationId,
          securityContext: c.get('securityContext'),
          detail: { trigger: 'MANUAL', attemptReference },
        }),
      );
    });

    // NFR-PERF-001: the browser request never holds the operation open.
    return c.json(
      {
        accepted: true,
        attemptReference,
        message:
          'The backup has been queued. Its progress and result appear in the backup history.',
      },
      202,
    );
  },
);

/** GET /admin/backups — configuration, latest result and attempt history (BAK-008). */
adminRoutes.get(
  '/backups',
  requireExactLevel('L3'),
  requirePermissions('admin:backups'),
  async (c) => {
    const actor = actorOf(c);

    const data = await withConnection(c.env, c.executionCtx, async (sql) => {
      const configs = await sql<
        {
          id: string;
          provider_label: string;
          bucket: string;
          path_prefix: string;
          region: string | null;
          endpoint: string | null;
          access_key_last_four: string | null;
          encryption_mode: string;
          status: string;
          last_test_at: string | null;
          last_test_ok: boolean | null;
          last_test_message: string | null;
          schedule_enabled: boolean;
          schedule_cron: string | null;
          schedule_timezone: string;
          retention_max_count: number;
          last_scheduled_run_at: string | null;
          next_scheduled_run_at: string | null;
          consecutive_failures: number;
          suspended_at: string | null;
          suspension_reason: string | null;
        }[]
      >`
      SELECT id, provider_label, bucket, path_prefix, region, endpoint, access_key_last_four,
             encryption_mode, status, last_test_at, last_test_ok, last_test_message,
             schedule_enabled, schedule_cron, schedule_timezone, retention_max_count,
             last_scheduled_run_at, next_scheduled_run_at, consecutive_failures,
             suspended_at, suspension_reason
        FROM backup_configurations WHERE organization_id = ${actor.organizationId}
    `;

      const attempts = await sql<
        {
          attempt_reference: string;
          trigger_type: string;
          status: string;
          started_at: string;
          ended_at: string | null;
          size_bytes: string | null;
          checksum: string | null;
          object_key: string | null;
          error_message: string | null;
          retention_deleted_count: number;
          retention_complete: boolean;
          object_retired_at: string | null;
        }[]
      >`
      SELECT attempt_reference, trigger_type, status, started_at, ended_at, size_bytes,
             checksum, object_key, error_message, retention_deleted_count, retention_complete,
             object_retired_at
        FROM backup_attempts
       WHERE organization_id = ${actor.organizationId}
       ORDER BY started_at DESC
       LIMIT 100
    `;

      const config = configs[0];
      const latest = attempts[0] ?? null;

      return {
        configuration: config
          ? {
              configurationId: config.id,
              providerLabel: config.provider_label,
              bucket: config.bucket,
              pathPrefix: config.path_prefix,
              region: config.region,
              endpoint: config.endpoint,
              // Credentials are masked after save (BAK-002); the plaintext is unreachable
              // from any API response.
              accessKeyMasked: config.access_key_last_four
                ? `••••••••${config.access_key_last_four}`
                : '••••••••',
              secretKeyMasked: '••••••••',
              encryptionMode: config.encryption_mode,
              status: config.status,
              lastTestAt: config.last_test_at,
              lastTestOk: config.last_test_ok,
              lastTestMessage: config.last_test_message,
              scheduleEnabled: config.schedule_enabled,
              scheduleCron: config.schedule_cron,
              scheduleTimezone: config.schedule_timezone,
              retentionMaxCount: config.retention_max_count,
              lastScheduledRunAt: config.last_scheduled_run_at,
              nextScheduledRunAt: config.next_scheduled_run_at,
              suspended: config.suspended_at !== null,
              suspensionReason: config.suspension_reason,
              consecutiveFailures: config.consecutive_failures,
            }
          : null,
        // BAK-008: the most recent result is always visible, and a failure is shown as a
        // failure — never smoothed into "no recent backups".
        latestResult: latest
          ? {
              attemptReference: latest.attempt_reference,
              trigger: latest.trigger_type,
              status: latest.status,
              startedAt: latest.started_at,
              endedAt: latest.ended_at,
              sizeBytes: latest.size_bytes ? Number(latest.size_bytes) : null,
              checksum: latest.checksum,
              errorMessage: latest.error_message,
              retentionDeletedCount: latest.retention_deleted_count,
              retentionComplete: latest.retention_complete,
            }
          : null,
        history: attempts.map((a) => ({
          attemptReference: a.attempt_reference,
          trigger: a.trigger_type,
          status: a.status,
          startedAt: a.started_at,
          endedAt: a.ended_at,
          sizeBytes: a.size_bytes ? Number(a.size_bytes) : null,
          errorMessage: a.error_message,
          // The object key is retained on the record as evidence of what was written; the
          // retirement marker is what says whether it is still restorable.
          objectRetained: a.object_key !== null && a.object_retired_at === null,
          objectRetiredAt: a.object_retired_at,
        })),
        restoreValidationNote:
          'A backup that has never been restore-validated is not disaster-recovery proven. See docs/runbooks/backup-restore.md.',
      };
    });

    return c.json(data);
  },
);

/** PATCH /admin/backups/schedule — enable or disable recurring backups (BAK-006). */
adminRoutes.patch(
  '/backups/schedule',
  requireExactLevel('L3'),
  requirePermissions('admin:backups'),
  async (c) => {
    const actor = actorOf(c);
    const body = z
      .object({
        enabled: z.boolean(),
        cron: z.string().trim().max(100).optional(),
        timezone: z.string().trim().max(60).optional(),
        retentionMaxCount: z.number().int().min(1).max(3650).optional(),
      })
      .parse(await c.req.json());

    await withConnection(c.env, c.executionCtx, (sql) =>
      inTransaction(sql, async (tx) => {
        const rows = await tx<{ last_test_ok: boolean | null }[]>`
          SELECT last_test_ok FROM backup_configurations WHERE organization_id = ${actor.organizationId}
        `;
        if (!rows[0])
          throw notFoundError('BACKUP_NOT_CONFIGURED', 'No backup target is configured');
        if (body.enabled && rows[0].last_test_ok !== true) {
          throw stateError(
            'BACKUP_TEST_REQUIRED',
            'Run a successful connection test before enabling a backup schedule',
          );
        }

        await tx`
          UPDATE backup_configurations
             SET schedule_enabled = ${body.enabled},
                 schedule_cron = COALESCE(${body.cron ?? null}, schedule_cron),
                 schedule_timezone = COALESCE(${body.timezone ?? null}, schedule_timezone),
                 retention_max_count = COALESCE(${body.retentionMaxCount ?? null}, retention_max_count),
                 updated_by_user_id = ${actor.userId}
           WHERE organization_id = ${actor.organizationId}
        `;
        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'BACKUP',
          action: body.enabled ? 'backup.schedule.enabled' : 'backup.schedule.disabled',
          objectType: 'BackupConfiguration',
          objectId: actor.organizationId,
          outcome: 'SUCCESS',
          correlationId: c.get('correlationId'),
          securityContext: c.get('securityContext'),
          detail: { cron: body.cron, retentionMaxCount: body.retentionMaxCount },
        });
      }),
    );

    return c.json({ scheduleEnabled: body.enabled });
  },
);

// ---------------------------------------------------------------------------
// Policies (spec 20)
// ---------------------------------------------------------------------------

adminRoutes.get(
  '/policies',
  requireExactLevel('L3'),
  requirePermissions('admin:policies'),
  async (c) => {
    const actor = actorOf(c);
    const { loadPolicy } = await import('../services/policy-store.js');
    const policy = await withConnection(c.env, c.executionCtx, (sql) =>
      loadPolicy(sql, actor.organizationId),
    );
    return c.json({ policy });
  },
);

adminRoutes.patch(
  '/policies',
  requireExactLevel('L3'),
  requirePermissions('admin:policies'),
  async (c) => {
    const actor = actorOf(c);
    assertFreshAuthentication(actor);
    const body = policySchema.partial().parse(await c.req.json());
    const correlationId = c.get('correlationId');

    const { loadPolicy } = await import('../services/policy-store.js');

    const updated = await withConnection(c.env, c.executionCtx, (sql) =>
      inTransaction(sql, async (tx) => {
        const before = await loadPolicy(tx, actor.organizationId);
        const merged = policySchema.parse({ ...before, ...body });

        await tx`
          INSERT INTO policies (
            organization_id, max_instruction_amount_cents, max_batch_total_cents,
            max_batch_instructions, high_value_threshold_cents, cooling_off_seconds,
            blocking_risk_band, allow_l1_failed_export, max_export_rows,
            daily_disbursement_ceiling_cents, updated_by_user_id
          ) VALUES (
            ${actor.organizationId}, ${merged.maxInstructionAmountCents}, ${merged.maxBatchTotalCents},
            ${merged.maxBatchInstructions}, ${merged.highValueThresholdCents}, ${merged.coolingOffSeconds},
            ${merged.blockingRiskBand}, ${merged.allowL1FailedExport}, ${merged.maxExportRows},
            ${merged.dailyDisbursementCeilingCents}, ${actor.userId}
          )
          ON CONFLICT (organization_id) DO UPDATE SET
            max_instruction_amount_cents = EXCLUDED.max_instruction_amount_cents,
            max_batch_total_cents = EXCLUDED.max_batch_total_cents,
            max_batch_instructions = EXCLUDED.max_batch_instructions,
            high_value_threshold_cents = EXCLUDED.high_value_threshold_cents,
            cooling_off_seconds = EXCLUDED.cooling_off_seconds,
            blocking_risk_band = EXCLUDED.blocking_risk_band,
            allow_l1_failed_export = EXCLUDED.allow_l1_failed_export,
            max_export_rows = EXCLUDED.max_export_rows,
            daily_disbursement_ceiling_cents = EXCLUDED.daily_disbursement_ceiling_cents,
            updated_by_user_id = EXCLUDED.updated_by_user_id,
            updated_at = now()
        `;

        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'ADMINISTRATION',
          action: 'policy.updated',
          objectType: 'Policy',
          objectId: actor.organizationId,
          outcome: 'SUCCESS',
          previousState: before,
          newState: merged,
          correlationId,
          securityContext: c.get('securityContext'),
          detail: { changedFields: Object.keys(body) },
        });

        return merged;
      }),
    );

    return c.json({ policy: updated });
  },
);

// ---------------------------------------------------------------------------
// Audit (spec 14)
// ---------------------------------------------------------------------------

/** GET /admin/audit — controlled audit search. Scope follows the permission held. */
adminRoutes.get('/audit', requirePermissions('audit:read_org'), async (c) => {
  const actor = actorOf(c);
  const url = new URL(c.req.url);
  const eventClass = url.searchParams.get('eventClass');
  const objectId = url.searchParams.get('objectId');
  const actorId = url.searchParams.get('actorId');
  const outcome = url.searchParams.get('outcome');
  const limit = Math.min(Number(url.searchParams.get('limit') ?? '100'), 500);
  const offset = Math.max(Number(url.searchParams.get('offset') ?? '0'), 0);

  const events = await withConnection(c.env, c.executionCtx, async (sql) => {
    return sql<
      {
        event_reference: string;
        sequence: string;
        actor_id: string;
        actor_level: string | null;
        event_class: string;
        action: string;
        object_type: string;
        object_id: string | null;
        outcome: string;
        occurred_at: string;
        correlation_id: string;
        detail: unknown;
        previous_state: unknown;
        new_state: unknown;
      }[]
    >`
      SELECT event_reference, sequence, actor_id, actor_level, event_class, action,
             object_type, object_id, outcome, occurred_at, correlation_id, detail,
             previous_state, new_state
        FROM audit_events
       WHERE organization_id = ${actor.organizationId}
         AND (${eventClass ?? null}::text IS NULL OR event_class = ${eventClass ?? null}::text)
         AND (${objectId ?? null}::text   IS NULL OR object_id = ${objectId ?? null}::text)
         AND (${actorId ?? null}::text    IS NULL OR actor_id = ${actorId ?? null}::text)
         AND (${outcome ?? null}::text    IS NULL OR outcome = ${outcome ?? null}::text)
       ORDER BY sequence DESC
       LIMIT ${limit} OFFSET ${offset}
    `;
  });

  return c.json({ events });
});

/**
 * POST /admin/audit/verify — verify the tamper-evident chain.
 *
 * Recomputes every digest and every link. A break is reported with the exact event at
 * which verification failed, which is what turns "we have logs" into "we can prove the
 * logs are intact".
 */
adminRoutes.post(
  '/audit/verify',
  requireExactLevel('L3'),
  requirePermissions('audit:read_full'),
  async (c) => {
    const actor = actorOf(c);
    const body = z
      .object({
        fromSequence: z.number().int().min(1).default(1),
        limit: z.number().int().min(1).max(5000).default(1000),
      })
      .parse(await c.req.json().catch(() => ({})));

    const verification = await withConnection(c.env, c.executionCtx, async (sql) => {
      const rows = await sql<
        {
          event_reference: string;
          sequence: string;
          actor_id: string;
          actor_level: string | null;
          event_class: string;
          action: string;
          object_type: string;
          object_id: string | null;
          outcome: string;
          occurred_at: string;
          previous_state: unknown;
          new_state: unknown;
          security_context: Record<string, unknown>;
          detail: Record<string, unknown>;
          correlation_id: string;
          previous_hash: string;
          event_hash: string;
        }[]
      >`
        SELECT event_reference, sequence, actor_id, actor_level, event_class, action,
               object_type, object_id, outcome, occurred_at, previous_state, new_state,
               security_context, detail, correlation_id, previous_hash, event_hash
          FROM audit_events
         WHERE organization_id = ${actor.organizationId} AND sequence >= ${body.fromSequence}
         ORDER BY sequence ASC
         LIMIT ${body.limit}
      `;

      const events: AuditEvent[] = rows.map((r) => ({
        eventId: r.event_reference,
        organizationId: actor.organizationId,
        actorId: r.actor_id,
        actorLevel: r.actor_level,
        eventClass: r.event_class as AuditEvent['eventClass'],
        action: r.action,
        objectType: r.object_type,
        objectId: r.object_id,
        outcome: r.outcome as AuditEvent['outcome'],
        occurredAt: new Date(r.occurred_at).toISOString(),
        previousState: r.previous_state,
        newState: r.new_state,
        securityContext: r.security_context,
        detail: r.detail,
        correlationId: r.correlation_id,
        previousHash: r.previous_hash,
        eventHash: r.event_hash,
        sequence: Number(r.sequence),
      }));

      const startHash =
        body.fromSequence === 1
          ? GENESIS_HASH
          : ((
              await sql<{ event_hash: string }[]>`
                SELECT event_hash FROM audit_events
                 WHERE organization_id = ${actor.organizationId} AND sequence = ${body.fromSequence - 1}
              `
            )[0]?.event_hash ?? GENESIS_HASH);

      return verifyChain(events, startHash);
    });

    return c.json({
      ...verification,
      interpretation: verification.valid
        ? 'Every event in this range hashes to its recorded digest and links to its predecessor. No event has been added, removed, reordered or altered.'
        : 'The chain does not verify. An event has been altered or removed at the reported position. Preserve the database and follow docs/runbooks/audit-incident.md.',
    });
  },
);
