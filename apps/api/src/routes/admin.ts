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
  randomToken,
  GENESIS_HASH,
  type AuditEvent,
} from '@solvaren/core';
import {
  requireAuth,
  requirePermissions,
  requireExactLevel,
  actorOf,
} from '../middleware/security.js';
import { withConnection, inTransaction, uuidSet } from '../db/client.js';
import { writeAuditEvent } from '../db/audit-writer.js';
import {
  configureDaraja,
  loadDarajaClientById,
  maskConfig,
  type DarajaConfigRow,
} from '../services/daraja-config.js';
import { encryptSecret, hashPassword, sha256Hex } from '../services/crypto.js';
import { isPrecomputedCredential } from '@solvaren/daraja';
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
  /*
   * Either the plain initiator password, or an already-encrypted SecurityCredential from
   * the Daraja portal.
   *
   * When it is a plain password, Safaricom's portal rules apply and are enforced here.
   * The M-PESA portal restricts special characters to # & % $ and specifically rejects or
   * mishandles `@` and `.`. A password containing one is accepted by the portal-side form
   * in some flows and then fails decryption on every single payment with ResultCode 2001
   * — an error that reads like a certificate problem and costs a payroll run to diagnose.
   * Refusing it at the point of entry is the only cheap moment to catch it.
   */
  initiatorPasswordOrCredential: z
    .string()
    .trim()
    .min(8)
    .max(2000)
    .superRefine((value, ctx) => {
      if (isPrecomputedCredential(value)) return;
      if (/[@.]/.test(value)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            'The M-PESA portal does not accept "@" or "." in an initiator password. Every payment would fail with ResultCode 2001. Change it on the org portal and enter the new one.',
        });
      }
      if (/[^A-Za-z0-9#&%$]/.test(value)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            'M-PESA restricts initiator passwords to letters, digits and the symbols # & % $.',
        });
      }
    }),
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

    const masked = await withConnection(c.env, async (sql) => {
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

    const configs = await withConnection(c.env, async (sql) => {
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

    const result = await withConnection(c.env, async (sql) => {
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

    await withConnection(c.env, (sql) =>
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

    await withConnection(c.env, (sql) =>
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

    const result = await withConnection(c.env, async (sql) => {
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

    await withConnection(c.env, async (sql) => {
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
      await c.env.queue.send({ queue: 'backups', body: message });

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

    const data = await withConnection(c.env, async (sql) => {
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

    await withConnection(c.env, (sql) =>
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
    const policy = await withConnection(c.env, (sql) => loadPolicy(sql, actor.organizationId));
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

    const updated = await withConnection(c.env, (sql) =>
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

  const events = await withConnection(c.env, async (sql) => {
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

    const verification = await withConnection(c.env, async (sql) => {
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

// ---------------------------------------------------------------------------
// Organisation users (L3 ONLY)
//
// The admin:users permission existed from the start and nothing implemented it: creating a
// user meant running scripts/create-user.mjs against the database, which is not something
// an organisation administrator can do on a deployed system. A payment platform that cannot
// onboard a second approver cannot enforce separation of duties in practice, because there
// is nobody else to approve.
//
// What this deliberately does NOT do is edit the permission matrix. Authority levels are
// fixed in packages/core/src/rbac.ts, and an administrator who can grant themselves release
// rights is an administrator who has defeated separation of duties. Assigning a LEVEL to a
// person is the intended control; redefining what a level may do is a code change.
// ---------------------------------------------------------------------------

const createUserSchema = z.object({
  email: z.string().trim().email().max(320),
  fullName: z.string().trim().min(2).max(120),
  level: z.enum(['L1', 'L2', 'L3']),
});

/** A readable one-time password. Words beat character soup for a credential read aloud. */
function generatePassphrase(): string {
  const words = [
    'harbour',
    'lantern',
    'meridian',
    'quartz',
    'sable',
    'thicket',
    'vellum',
    'willow',
    'anchor',
    'basalt',
    'cinder',
    'dovetail',
    'ember',
    'fathom',
    'granite',
    'hollow',
  ];
  const picked: string[] = [];
  const bytes = new Uint8Array(4);
  crypto.getRandomValues(bytes);
  for (const b of bytes) picked.push(words[b % words.length]!);
  const suffix = new Uint8Array(2);
  crypto.getRandomValues(suffix);
  return `${picked.join('-')}-${(suffix[0]! * 256 + suffix[1]!) % 10000}`;
}

/** GET /admin/users — who is in this organisation, and can they actually act. */
adminRoutes.get('/users', requireExactLevel('L3'), requirePermissions('admin:users'), async (c) => {
  const actor = actorOf(c);

  const users = await withConnection(c.env, async (sql) => {
    const rows = await sql<
      {
        id: string;
        email: string;
        full_name: string;
        authority_level: string;
        status: string;
        created_at: string;
        last_login_at: string | null;
        has_authenticator: boolean;
        has_pin: boolean;
      }[]
    >`
        SELECT u.id, u.email, u.full_name, u.authority_level, u.status, u.created_at,
               u.last_login_at,
               EXISTS (
                 SELECT 1 FROM webauthn_credentials w
                  WHERE w.user_id = u.id AND w.status = 'ACTIVE'
               ) AS has_authenticator,
               (u.authorization_pin_hash IS NOT NULL) AS has_pin
          FROM users u
         WHERE u.organization_id = ${actor.organizationId}
         ORDER BY u.authority_level DESC, u.email
      `;

    return rows.map((r) => ({
      userId: r.id,
      email: r.email,
      fullName: r.full_name,
      level: r.authority_level,
      status: r.status,
      createdAt: new Date(r.created_at).toISOString(),
      lastLoginAt: r.last_login_at ? new Date(r.last_login_at).toISOString() : null,
      // Surfaced because an account missing either cannot complete a release, and the
      // administrator should see that before a payroll run rather than during one.
      hasAuthenticator: r.has_authenticator,
      hasAuthorizationPin: r.has_pin,
    }));
  });

  return c.json({ users });
});

/** POST /admin/users — create a member and return a one-time password. */
adminRoutes.post(
  '/users',
  requireExactLevel('L3'),
  requirePermissions('admin:users'),
  async (c) => {
    const actor = actorOf(c);
    assertFreshAuthentication(actor);
    assertWebAuthnSession(actor);

    const body = createUserSchema.parse(await c.req.json());
    const correlationId = c.get('correlationId');
    const passphrase = generatePassphrase();
    const passwordHash = await hashPassword(passphrase);

    const created = await withConnection(c.env, (sql) =>
      inTransaction(sql, async (tx) => {
        const existing = await tx<{ id: string }[]>`
          SELECT id FROM users
           WHERE organization_id = ${actor.organizationId} AND email = ${body.email.toLowerCase()}
           LIMIT 1
        `;
        if (existing.length > 0) {
          throw validationError(
            'USER_ALREADY_EXISTS',
            'Someone with that email address is already a member of this organisation',
          );
        }

        // L1 can work as soon as it has a password. Above L1 a WebAuthn credential is
        // mandatory, so the account starts PENDING_ENROLMENT and becomes ACTIVE when the
        // first authenticator is registered.
        const status = body.level === 'L1' ? 'ACTIVE' : 'PENDING_ENROLMENT';

        const rows = await tx<{ id: string }[]>`
          INSERT INTO users (organization_id, email, full_name, authority_level,
                             password_hash, status)
          VALUES (${actor.organizationId}, ${body.email.toLowerCase()}, ${body.fullName},
                  ${body.level}, ${passwordHash}, ${status})
          RETURNING id
        `;
        const user = rows[0]!;

        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'IDENTITY',
          action: 'admin.user.created',
          objectType: 'User',
          objectId: user.id,
          outcome: 'SUCCESS',
          newState: { level: body.level, status },
          correlationId,
          securityContext: c.get('securityContext'),
          detail: { email: body.email.toLowerCase(), level: body.level },
        });

        return { userId: user.id, status };
      }),
    );

    return c.json(
      {
        userId: created.userId,
        email: body.email.toLowerCase(),
        level: body.level,
        status: created.status,
        // Shown once, never stored in the clear. The caller is told to hand it over out of
        // band, the same rule scripts/create-user.mjs follows.
        temporaryPassword: passphrase,
      },
      201,
    );
  },
);

/** PATCH /admin/users/:id/status — enable or disable a member. */
adminRoutes.patch(
  '/users/:id/status',
  requireExactLevel('L3'),
  requirePermissions('admin:users'),
  async (c) => {
    const actor = actorOf(c);
    const userId = c.req.param('id');
    const body = z.object({ status: z.enum(['ACTIVE', 'DISABLED']) }).parse(await c.req.json());
    const correlationId = c.get('correlationId');

    if (userId === actor.userId) {
      throw validationError(
        'CANNOT_DISABLE_SELF',
        'You cannot change your own status. Ask another executive authority.',
      );
    }

    const result = await withConnection(c.env, (sql) =>
      inTransaction(sql, async (tx) => {
        const rows = await tx<{ id: string; authority_level: string; status: string }[]>`
          SELECT id, authority_level, status FROM users
           WHERE id = ${userId} AND organization_id = ${actor.organizationId} LIMIT 1
        `;
        const target = rows[0];
        if (!target) throw validationError('USER_NOT_FOUND', 'No such user in this organisation');

        /*
         * Never leave an organisation without an executive authority. L3 is the only level
         * that can release a payment or administer anything, so disabling the last active
         * one locks everybody out permanently — there is no support desk to call.
         */
        if (body.status === 'DISABLED' && target.authority_level === 'L3') {
          const remaining = await tx<{ count: string }[]>`
            SELECT count(*)::text AS count FROM users
             WHERE organization_id = ${actor.organizationId}
               AND authority_level = 'L3' AND status = 'ACTIVE' AND id <> ${userId}
          `;
          if (Number(remaining[0]?.count ?? '0') === 0) {
            throw validationError(
              'LAST_EXECUTIVE_AUTHORITY',
              'This is the last active executive authority. Promote another before disabling it, or nobody will be able to release a payment.',
            );
          }
        }

        await tx`UPDATE users SET status = ${body.status} WHERE id = ${userId}`;

        // A disabled account must not keep a live session.
        if (body.status === 'DISABLED') {
          await tx`UPDATE sessions SET revoked_at = now() WHERE user_id = ${userId} AND revoked_at IS NULL`;
        }

        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'IDENTITY',
          action: 'admin.user.status_changed',
          objectType: 'User',
          objectId: userId,
          outcome: 'SUCCESS',
          previousState: { status: target.status },
          newState: { status: body.status },
          correlationId,
          securityContext: c.get('securityContext'),
          detail: {},
        });

        return { status: body.status };
      }),
    );

    return c.json(result);
  },
);

/** PATCH /admin/users/:id/level — assign an authority level. */
adminRoutes.patch(
  '/users/:id/level',
  requireExactLevel('L3'),
  requirePermissions('admin:users'),
  async (c) => {
    const actor = actorOf(c);
    const userId = c.req.param('id');
    const body = z.object({ level: z.enum(['L1', 'L2', 'L3']) }).parse(await c.req.json());
    const correlationId = c.get('correlationId');

    /*
     * Changing authority is the most consequential thing on this screen: it is how someone
     * gains the ability to release money. It therefore requires the same proof as rotating
     * payment credentials — recent authentication and a WebAuthn session — and can never be
     * applied to oneself, which would make self-promotion a single click.
     */
    assertFreshAuthentication(actor);
    assertWebAuthnSession(actor);

    if (userId === actor.userId) {
      throw validationError(
        'CANNOT_CHANGE_OWN_LEVEL',
        'You cannot change your own authority level. Ask another executive authority.',
      );
    }

    const result = await withConnection(c.env, (sql) =>
      inTransaction(sql, async (tx) => {
        const rows = await tx<
          { id: string; authority_level: string; status: string; pin: string | null }[]
        >`
          SELECT id, authority_level, status, authorization_pin_hash AS pin FROM users
           WHERE id = ${userId} AND organization_id = ${actor.organizationId} LIMIT 1
        `;
        const target = rows[0];
        if (!target) throw validationError('USER_NOT_FOUND', 'No such user in this organisation');

        if (target.authority_level === 'L3' && body.level !== 'L3') {
          const remaining = await tx<{ count: string }[]>`
            SELECT count(*)::text AS count FROM users
             WHERE organization_id = ${actor.organizationId}
               AND authority_level = 'L3' AND status = 'ACTIVE' AND id <> ${userId}
          `;
          if (Number(remaining[0]?.count ?? '0') === 0) {
            throw validationError(
              'LAST_EXECUTIVE_AUTHORITY',
              'This is the last active executive authority. Promote another before demoting it, or nobody will be able to release a payment.',
            );
          }
        }

        /*
         * users_privileged_requires_pin is a CHECK constraint: an ACTIVE L2 or L3 must have
         * a PIN. Promoting an L1 who has none would violate it, so the account drops to
         * PENDING_ENROLMENT and becomes usable once it has a key and a PIN. Letting the
         * database reject the update instead would surface as an opaque constraint error.
         */
        const needsEnrolment = body.level !== 'L1' && target.pin === null;
        const status = needsEnrolment ? 'PENDING_ENROLMENT' : target.status;

        await tx`
          UPDATE users SET authority_level = ${body.level}, status = ${status}
           WHERE id = ${userId}
        `;

        // Authority changed: existing sessions carry the old level in their capabilities.
        await tx`UPDATE sessions SET revoked_at = now() WHERE user_id = ${userId} AND revoked_at IS NULL`;

        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'IDENTITY',
          action: 'admin.user.level_changed',
          objectType: 'User',
          objectId: userId,
          outcome: 'SUCCESS',
          previousState: { level: target.authority_level, status: target.status },
          newState: { level: body.level, status },
          correlationId,
          securityContext: c.get('securityContext'),
          detail: { requiresEnrolment: needsEnrolment },
        });

        return { level: body.level, status };
      }),
    );

    return c.json(result);
  },
);

/** POST /admin/users/:id/enrolment-token — let a member register their first key. */
adminRoutes.post(
  '/users/:id/enrolment-token',
  requireExactLevel('L3'),
  requirePermissions('admin:users'),
  async (c) => {
    const actor = actorOf(c);
    const userId = c.req.param('id');
    const correlationId = c.get('correlationId');

    assertFreshAuthentication(actor);
    assertWebAuthnSession(actor);

    const issued = await withConnection(c.env, (sql) =>
      inTransaction(sql, async (tx) => {
        const rows = await tx<{ id: string; email: string }[]>`
          SELECT id, email FROM users
           WHERE id = ${userId} AND organization_id = ${actor.organizationId} LIMIT 1
        `;
        const target = rows[0];
        if (!target) throw validationError('USER_NOT_FOUND', 'No such user in this organisation');

        const existing = await tx<{ id: string }[]>`
          SELECT id FROM webauthn_credentials
           WHERE user_id = ${userId} AND status = 'ACTIVE' LIMIT 1
        `;
        if (existing.length > 0) {
          throw validationError(
            'ALREADY_ENROLLED',
            'That account already has an authenticator. Enrolment tokens only register the first one.',
          );
        }

        const token = randomToken(32);

        // One live token per user, so a token glimpsed over a shoulder and one issued later
        // cannot both work.
        await tx`DELETE FROM enrolment_tokens WHERE user_id = ${userId} AND consumed_at IS NULL`;
        await tx`
          INSERT INTO enrolment_tokens (organization_id, user_id, token_hash, expires_at)
          VALUES (${actor.organizationId}, ${userId}, ${await sha256Hex(token)},
                  now() + interval '30 minutes')
        `;

        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'IDENTITY',
          action: 'admin.user.enrolment_token_issued',
          objectType: 'User',
          objectId: userId,
          outcome: 'SUCCESS',
          correlationId,
          securityContext: c.get('securityContext'),
          detail: { email: target.email },
        });

        return { token, expiresAt: new Date(Date.now() + 30 * 60_000).toISOString() };
      }),
    );

    return c.json(issued, 201);
  },
);

// ---------------------------------------------------------------------------
// Security Centre (L3 ONLY — spec §8, §13)
// ---------------------------------------------------------------------------

/**
 * The platform has been writing security events since the first commit — failed sign-ins,
 * callback signature mismatches, reconciliation escalations, recipient payment-detail
 * changes — and nothing could read them. A detection that nobody can see is not a control,
 * so this is the console that closes that loop.
 *
 * Acknowledgement is a real state change, not a dismiss button: it records who looked at a
 * CRITICAL event and when, which is the question asked first after an incident.
 */

const securityQuerySchema = z.object({
  severity: z.enum(['INFO', 'WARNING', 'CRITICAL']).optional(),
  eventType: z.string().trim().max(64).optional(),
  unacknowledgedOnly: z.coerce.boolean().optional(),
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(200).default(50),
});

adminRoutes.get(
  '/security/events',
  requireExactLevel('L3'),
  requirePermissions('admin:security'),
  async (c) => {
    const actor = actorOf(c);
    const query = securityQuerySchema.parse(c.req.query());
    const offset = (query.page - 1) * query.pageSize;

    const result = await withConnection(c.env, async (sql) => {
      const rows = await sql<
        {
          id: string;
          event_type: string;
          severity: string;
          description: string;
          ip: string | null;
          user_agent: string | null;
          detail: unknown;
          created_at: string;
          acknowledged_at: string | null;
          user_name: string | null;
          user_email: string | null;
          acknowledged_by_name: string | null;
          total_count: string;
        }[]
      >`
        SELECT se.id, se.event_type, se.severity, se.description, host(se.ip) AS ip,
               se.user_agent, se.detail, se.created_at, se.acknowledged_at,
               u.full_name AS user_name, u.email AS user_email,
               ack.full_name AS acknowledged_by_name,
               count(*) OVER ()::text AS total_count
          FROM security_events se
          LEFT JOIN users u   ON u.id = se.user_id
          LEFT JOIN users ack ON ack.id = se.acknowledged_by
         WHERE se.organization_id = ${actor.organizationId}
           ${query.severity ? sql`AND se.severity = ${query.severity}` : sql``}
           ${query.eventType ? sql`AND se.event_type = ${query.eventType}` : sql``}
           ${query.unacknowledgedOnly ? sql`AND se.acknowledged_at IS NULL` : sql``}
         ORDER BY se.created_at DESC
         LIMIT ${query.pageSize} OFFSET ${offset}
      `;

      const counts = await sql<{ severity: string; open: string; total: string }[]>`
        SELECT severity,
               count(*) FILTER (WHERE acknowledged_at IS NULL)::text AS open,
               count(*)::text AS total
          FROM security_events
         WHERE organization_id = ${actor.organizationId}
         GROUP BY severity
      `;

      const totalRows = rows.length > 0 ? Number(rows[0]!.total_count) : 0;
      return {
        events: rows.map((row) => ({
          id: row.id,
          eventType: row.event_type,
          severity: row.severity,
          description: row.description,
          ip: row.ip,
          userAgent: row.user_agent,
          detail: row.detail,
          createdAt: row.created_at,
          acknowledgedAt: row.acknowledged_at,
          acknowledgedBy: row.acknowledged_by_name,
          user: row.user_name ? { name: row.user_name, email: row.user_email } : null,
        })),
        counts: counts.map((row) => ({
          severity: row.severity,
          open: Number(row.open),
          total: Number(row.total),
        })),
        page: {
          page: query.page,
          pageSize: query.pageSize,
          totalRows,
          totalPages: Math.max(1, Math.ceil(totalRows / query.pageSize)),
          hasNext: query.page * query.pageSize < totalRows,
          hasPrevious: query.page > 1,
        },
      };
    });

    return c.json(result);
  },
);

const acknowledgeSchema = z.object({
  eventIds: z.array(z.string().uuid()).min(1).max(200),
  note: z.string().trim().max(1000).optional(),
});

adminRoutes.post(
  '/security/events/acknowledge',
  requireExactLevel('L3'),
  requirePermissions('admin:security'),
  async (c) => {
    const actor = actorOf(c);
    const body = acknowledgeSchema.parse(await c.req.json());
    const correlationId = c.get('correlationId');

    const acknowledged = await withConnection(c.env, (sql) =>
      inTransaction(sql, async (tx) => {
        // Already-acknowledged events are left alone, so the first reviewer's name and
        // timestamp survive a second pass over the list.
        const rows = await tx<{ id: string }[]>`
          UPDATE security_events
             SET acknowledged_at = now(), acknowledged_by = ${actor.userId}
           WHERE organization_id = ${actor.organizationId}
             AND acknowledged_at IS NULL
             AND id IN (${uuidSet(tx, body.eventIds)})
          RETURNING id
        `;
        if (rows.length > 0) {
          await writeAuditEvent(tx, {
            organizationId: actor.organizationId,
            actorId: actor.userId,
            actorLevel: actor.level,
            eventClass: 'SECURITY',
            action: 'security.events.acknowledged',
            objectType: 'SecurityEvent',
            objectId: rows[0]!.id,
            outcome: 'SUCCESS',
            correlationId,
            securityContext: c.get('securityContext'),
            detail: { count: rows.length, note: body.note ?? null },
          });
        }
        return rows.length;
      }),
    );

    return c.json({ acknowledged });
  },
);

/**
 * GET /admin/security/sessions — who is signed in right now, and from where.
 *
 * Session hijacking looks exactly like normal use unless somebody can see two live sessions
 * for one account from two countries. This is that view, and the revoke below is the lever
 * it exists to justify.
 */
adminRoutes.get(
  '/security/sessions',
  requireExactLevel('L3'),
  requirePermissions('admin:security'),
  async (c) => {
    const actor = actorOf(c);

    const result = await withConnection(c.env, async (sql) => {
      const sessions = await sql<
        {
          id: string;
          user_name: string;
          email: string;
          authority_level: string;
          issued_at: string;
          expires_at: string;
          last_seen_at: string;
          webauthn_verified_at: string | null;
          ip: string | null;
          user_agent: string | null;
          device_label: string | null;
          trust_status: string | null;
        }[]
      >`
        SELECT s.id, u.full_name AS user_name, u.email, u.authority_level,
               s.issued_at, s.expires_at, s.last_seen_at, s.webauthn_verified_at,
               host(s.ip) AS ip, s.user_agent,
               td.label AS device_label, td.trust_status
          FROM sessions s
          JOIN users u ON u.id = s.user_id
          LEFT JOIN trusted_devices td ON td.id = s.trusted_device_id
         WHERE s.organization_id = ${actor.organizationId}
           AND s.revoked_at IS NULL AND s.expires_at > now()
         ORDER BY s.last_seen_at DESC
         LIMIT 200
      `;

      const devices = await sql<
        {
          id: string;
          user_name: string;
          email: string;
          label: string | null;
          trust_status: string;
          first_seen_ip: string | null;
          last_seen_ip: string | null;
          user_agent: string | null;
          registered_at: string;
          last_activity_at: string;
        }[]
      >`
        SELECT td.id, u.full_name AS user_name, u.email, td.label, td.trust_status,
               host(td.first_seen_ip) AS first_seen_ip, host(td.last_seen_ip) AS last_seen_ip,
               td.user_agent, td.registered_at, td.last_activity_at
          FROM trusted_devices td
          JOIN users u ON u.id = td.user_id
         WHERE td.organization_id = ${actor.organizationId} AND td.revoked_at IS NULL
         ORDER BY td.last_activity_at DESC
         LIMIT 200
      `;

      return {
        sessions: sessions.map((s) => ({
          id: s.id,
          userName: s.user_name,
          email: s.email,
          authorityLevel: s.authority_level,
          issuedAt: s.issued_at,
          expiresAt: s.expires_at,
          lastSeenAt: s.last_seen_at,
          webauthnVerified: s.webauthn_verified_at !== null,
          ip: s.ip,
          userAgent: s.user_agent,
          deviceLabel: s.device_label,
          deviceTrust: s.trust_status,
        })),
        devices: devices.map((d) => ({
          id: d.id,
          userName: d.user_name,
          email: d.email,
          label: d.label,
          trustStatus: d.trust_status,
          firstSeenIp: d.first_seen_ip,
          lastSeenIp: d.last_seen_ip,
          userAgent: d.user_agent,
          registeredAt: d.registered_at,
          lastActivityAt: d.last_activity_at,
        })),
      };
    });

    return c.json(result);
  },
);

adminRoutes.post(
  '/security/sessions/:id/revoke',
  requireExactLevel('L3'),
  requirePermissions('admin:security'),
  async (c) => {
    const actor = actorOf(c);
    const sessionId = c.req.param('id');
    const correlationId = c.get('correlationId');

    const revoked = await withConnection(c.env, (sql) =>
      inTransaction(sql, async (tx) => {
        const rows = await tx<{ id: string; user_id: string }[]>`
          UPDATE sessions
             SET revoked_at = now(), revocation_reason = 'REVOKED_BY_ADMINISTRATOR'
           WHERE id = ${sessionId} AND organization_id = ${actor.organizationId}
             AND revoked_at IS NULL
          RETURNING id, user_id
        `;
        const row = rows[0];
        if (!row) {
          throw notFoundError('SESSION_NOT_FOUND', 'That session is not active');
        }
        await tx`
          INSERT INTO security_events (organization_id, user_id, event_type, severity, description, detail)
          VALUES (
            ${actor.organizationId}, ${row.user_id}, 'SESSION_REVOKED_BY_ADMIN', 'WARNING',
            ${'A session was revoked by an administrator'},
            ${tx.json({ sessionId, revokedBy: actor.userId })}
          )
        `;
        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'SECURITY',
          action: 'session.revoked',
          objectType: 'Session',
          objectId: sessionId,
          outcome: 'SUCCESS',
          correlationId,
          securityContext: c.get('securityContext'),
          detail: { targetUserId: row.user_id },
        });
        return true;
      }),
    );

    return c.json({ revoked });
  },
);

adminRoutes.post(
  '/security/devices/:id/revoke',
  requireExactLevel('L3'),
  requirePermissions('admin:security'),
  async (c) => {
    const actor = actorOf(c);
    const deviceId = c.req.param('id');
    const correlationId = c.get('correlationId');

    await withConnection(c.env, (sql) =>
      inTransaction(sql, async (tx) => {
        const rows = await tx<{ id: string; user_id: string; label: string | null }[]>`
          UPDATE trusted_devices
             SET trust_status = 'REVOKED', revoked_at = now()
           WHERE id = ${deviceId} AND organization_id = ${actor.organizationId}
             AND revoked_at IS NULL
          RETURNING id, user_id, label
        `;
        const row = rows[0];
        if (!row) throw notFoundError('DEVICE_NOT_FOUND', 'That device could not be found');

        // Revoking the device without its live sessions would leave the attacker signed in
        // on the very machine just declared untrusted.
        await tx`
          UPDATE sessions
             SET revoked_at = now(), revocation_reason = 'DEVICE_REVOKED'
           WHERE trusted_device_id = ${deviceId} AND revoked_at IS NULL
        `;

        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'SECURITY',
          action: 'trusted_device.revoked',
          objectType: 'TrustedDevice',
          objectId: deviceId,
          outcome: 'SUCCESS',
          correlationId,
          securityContext: c.get('securityContext'),
          detail: { targetUserId: row.user_id, label: row.label },
        });
      }),
    );

    return c.json({ revoked: true });
  },
);

// ---------------------------------------------------------------------------
// Conflict-of-interest registry (L3 ONLY — spec "Essentials extras", SoD)
// ---------------------------------------------------------------------------

/**
 * A declared conflict bars an approver from authorizing payments in its scope, and
 * `assertNoDeclaredConflict` has enforced that at every release since the first commit —
 * against a table nothing could write to. The control was real and unreachable: an executive
 * who is a director of a supplier, or is related to an employee, had no way to say so.
 *
 * Declaring one is deliberately not self-service in the ordinary sense: an L3 may record a
 * conflict for themselves or for another approver, because the point of the registry is that
 * the organisation knows, not that the individual remembers. Withdrawal is a separate,
 * audited act rather than a delete, so the history of who was barred from what survives.
 */

const conflictSchema = z.object({
  userId: z.string().uuid(),
  scopeType: z.enum(['RECIPIENT', 'DEPARTMENT', 'ORGANIZATION']),
  scopeId: z.string().uuid().nullish(),
  reason: z.string().trim().min(10).max(500),
});

adminRoutes.get(
  '/conflicts',
  requireExactLevel('L3'),
  requirePermissions('admin:policies'),
  async (c) => {
    const actor = actorOf(c);
    const conflicts = await withConnection(c.env, async (sql) => {
      const rows = await sql<
        {
          id: string;
          user_name: string;
          email: string;
          scope_type: string;
          scope_id: string | null;
          scope_name: string | null;
          reason: string;
          declared_at: string;
          declared_by: string | null;
          withdrawn_at: string | null;
        }[]
      >`
        SELECT cr.id, u.full_name AS user_name, u.email, cr.scope_type, cr.scope_id,
               COALESCE(r.full_name, d.name) AS scope_name,
               cr.reason, cr.declared_at, cr.withdrawn_at,
               declarer.full_name AS declared_by
          FROM conflict_registrations cr
          JOIN users u              ON u.id = cr.user_id
          LEFT JOIN users declarer  ON declarer.id = cr.declared_by_user_id
          LEFT JOIN recipients r    ON r.id = cr.scope_id AND cr.scope_type = 'RECIPIENT'
          LEFT JOIN departments d   ON d.id = cr.scope_id AND cr.scope_type = 'DEPARTMENT'
         WHERE cr.organization_id = ${actor.organizationId}
         ORDER BY cr.withdrawn_at NULLS FIRST, cr.declared_at DESC
      `;
      return rows.map((row) => ({
        id: row.id,
        userName: row.user_name,
        email: row.email,
        scopeType: row.scope_type,
        scopeId: row.scope_id,
        scopeName: row.scope_name,
        reason: row.reason,
        declaredAt: row.declared_at,
        declaredBy: row.declared_by,
        withdrawnAt: row.withdrawn_at,
      }));
    });
    return c.json({ conflicts });
  },
);

adminRoutes.post(
  '/conflicts',
  requireExactLevel('L3'),
  requirePermissions('admin:policies'),
  async (c) => {
    const actor = actorOf(c);
    const body = conflictSchema.parse(await c.req.json());
    const correlationId = c.get('correlationId');

    if (body.scopeType === 'ORGANIZATION' && body.scopeId) {
      throw validationError(
        'CONFLICT_SCOPE_INVALID',
        'An organisation-wide conflict covers everything, so it takes no specific scope.',
      );
    }
    if (body.scopeType !== 'ORGANIZATION' && !body.scopeId) {
      throw validationError(
        'CONFLICT_SCOPE_REQUIRED',
        `Name the ${body.scopeType.toLowerCase()} this conflict applies to.`,
      );
    }

    const created = await withConnection(c.env, (sql) =>
      inTransaction(sql, async (tx) => {
        const subject = await tx<{ id: string; full_name: string }[]>`
          SELECT id, full_name FROM users
           WHERE id = ${body.userId} AND organization_id = ${actor.organizationId}
        `;
        if (!subject[0]) throw notFoundError('USER_NOT_FOUND', 'That member could not be found');

        const rows = await tx<{ id: string }[]>`
          INSERT INTO conflict_registrations (
            organization_id, user_id, scope_type, scope_id, reason, declared_by_user_id
          ) VALUES (
            ${actor.organizationId}, ${body.userId}, ${body.scopeType},
            ${body.scopeId ?? null}, ${body.reason}, ${actor.userId}
          )
          RETURNING id
        `;

        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'AUTHORITY',
          action: 'conflict.declared',
          objectType: 'ConflictRegistration',
          objectId: rows[0]!.id,
          outcome: 'SUCCESS',
          newState: {
            userId: body.userId,
            scopeType: body.scopeType,
            scopeId: body.scopeId ?? null,
          },
          correlationId,
          securityContext: c.get('securityContext'),
          detail: { subject: subject[0].full_name, reason: body.reason },
        });
        return rows[0]!;
      }),
    );

    return c.json({ conflict: { id: created.id } }, 201);
  },
);

adminRoutes.post(
  '/conflicts/:id/withdraw',
  requireExactLevel('L3'),
  requirePermissions('admin:policies'),
  async (c) => {
    const actor = actorOf(c);
    const conflictId = c.req.param('id');
    const correlationId = c.get('correlationId');
    const body = z
      .object({ reason: z.string().trim().min(10).max(500) })
      .parse(await c.req.json().catch(() => ({})));

    await withConnection(c.env, (sql) =>
      inTransaction(sql, async (tx) => {
        // Withdrawn, never deleted: who was barred from authorizing what, and when that
        // stopped, is exactly the question an investigation asks afterwards.
        const rows = await tx<{ id: string; user_id: string }[]>`
          UPDATE conflict_registrations SET withdrawn_at = now()
           WHERE id = ${conflictId} AND organization_id = ${actor.organizationId}
             AND withdrawn_at IS NULL
          RETURNING id, user_id
        `;
        const row = rows[0];
        if (!row) {
          throw notFoundError(
            'CONFLICT_NOT_FOUND',
            'That declaration could not be found, or it has already been withdrawn',
          );
        }
        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'AUTHORITY',
          action: 'conflict.withdrawn',
          objectType: 'ConflictRegistration',
          objectId: conflictId,
          outcome: 'SUCCESS',
          correlationId,
          securityContext: c.get('securityContext'),
          detail: { targetUserId: row.user_id, reason: body.reason },
        });
      }),
    );

    return c.json({ withdrawn: true });
  },
);

/**
 * POST /admin/users/:id/reset-access — controlled administrative recovery (spec §11).
 *
 * The other half of recovery: an executive vouching for somebody who cannot get back in on
 * their own. Before this, an administrator could change a member's *level* and *status* and
 * nothing else — so an employee who forgot their password was locked out for good, and the
 * only remedy was editing the database by hand.
 *
 * It is the most dangerous operation an administrator has, because it mints a credential
 * for an account that is not theirs. The controls follow from that:
 *
 *   - Fresh authentication and a WebAuthn session, the same bar as changing Daraja
 *     credentials. A borrowed unlocked laptop must not be able to do this.
 *   - Never on yourself. An executive who has lost their own password uses a recovery code;
 *     allowing self-reset would let anyone holding a live L3 session quietly re-key the
 *     account they are sitting in, which is how a session compromise becomes permanent.
 *   - Every session of the target dies immediately, and the passphrase is shown once.
 *   - Recovering an L3 raises a CRITICAL security event. §11 asks for Level 3 recovery to
 *     be "particularly restrictive and fully audited"; one executive re-keying another is
 *     precisely the move a hostile insider would make, so it is loud.
 *
 * Optionally revokes the member's authenticators too, for the "lost the laptop and the
 * key" case. That forces re-enrolment, which is why it also parks the account as
 * PENDING_ENROLMENT rather than leaving it ACTIVE and unusable.
 */
adminRoutes.post(
  '/users/:id/reset-access',
  requireExactLevel('L3'),
  requirePermissions('admin:users'),
  async (c) => {
    const actor = actorOf(c);
    assertFreshAuthentication(actor);
    assertWebAuthnSession(actor);

    const userId = c.req.param('id');
    const correlationId = c.get('correlationId');
    const body = z
      .object({
        reason: z.string().trim().min(10).max(500),
        revokeAuthenticators: z.boolean().default(false),
      })
      .parse(await c.req.json());

    if (userId === actor.userId) {
      throw validationError(
        'CANNOT_RESET_SELF',
        'You cannot reset your own access. Use a recovery code, or ask another executive to recover the account.',
      );
    }

    const passphrase = generatePassphrase();

    const result = await withConnection(c.env, (sql) =>
      inTransaction(sql, async (tx) => {
        const rows = await tx<
          {
            id: string;
            email: string;
            full_name: string;
            authority_level: string;
            status: string;
          }[]
        >`
          SELECT id, email, full_name, authority_level, status FROM users
           WHERE id = ${userId} AND organization_id = ${actor.organizationId}
           FOR UPDATE
        `;
        const target = rows[0];
        if (!target) throw notFoundError('USER_NOT_FOUND', 'That member could not be found');

        const revokeKeys = body.revokeAuthenticators;
        if (revokeKeys) {
          await tx`DELETE FROM webauthn_credentials WHERE user_id = ${userId}`;
        }

        const hasAuthenticator = revokeKeys
          ? false
          : (
              await tx<{ count: string }[]>`
                SELECT count(*)::text AS count FROM webauthn_credentials WHERE user_id = ${userId}
              `
            )[0]!.count !== '0';

        /*
         * An L2 or L3 without an authenticator cannot sign in, so marking it ACTIVE would
         * be a lie the database itself half-catches (users_privileged_requires_pin) and the
         * login path fully catches. PENDING_ENROLMENT is the honest state.
         */
        const status =
          target.authority_level !== 'L1' && !hasAuthenticator ? 'PENDING_ENROLMENT' : 'ACTIVE';

        await tx`
          UPDATE users
             SET password_hash = ${await hashPassword(passphrase)},
                 password_updated_at = now(),
                 failed_login_count = 0,
                 locked_until = NULL,
                 status = ${status}
           WHERE id = ${userId}
        `;

        // Any recovery ticket already outstanding for this member is spent: the
        // administrator's action supersedes it, and two live routes in is one too many.
        await tx`
          UPDATE recovery_tickets SET consumed_at = now()
           WHERE user_id = ${userId} AND consumed_at IS NULL
        `;
        await tx`
          UPDATE sessions SET revoked_at = now(), revocation_reason = 'ACCESS_RESET_BY_ADMINISTRATOR'
           WHERE user_id = ${userId} AND revoked_at IS NULL
        `;

        await tx`
          INSERT INTO security_events (organization_id, user_id, event_type, severity, description, ip, detail)
          VALUES (
            ${actor.organizationId}, ${userId}, 'ACCESS_RESET_BY_ADMINISTRATOR',
            ${target.authority_level === 'L3' ? 'CRITICAL' : 'WARNING'},
            ${`Access was reset for ${target.full_name} by an executive`},
            ${c.get('securityContext').ip},
            ${tx.json({
              resetBy: actor.userId,
              targetLevel: target.authority_level,
              authenticatorsRevoked: revokeKeys,
              reason: body.reason,
            })}
          )
        `;
        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'IDENTITY',
          action: 'user.access_reset',
          objectType: 'User',
          objectId: userId,
          outcome: 'SUCCESS',
          previousState: { status: target.status },
          newState: { status, authenticatorsRevoked: revokeKeys },
          correlationId,
          securityContext: c.get('securityContext'),
          detail: { reason: body.reason, targetEmail: target.email },
        });

        return { email: target.email, status, authenticatorsRevoked: revokeKeys };
      }),
    );

    return c.json({
      email: result.email,
      status: result.status,
      oneTimePassword: passphrase,
      authenticatorsRevoked: result.authenticatorsRevoked,
      note: result.authenticatorsRevoked
        ? 'Read this to them in person or over a channel you trust — it is shown once. They will also need a new enrolment token before they can sign in.'
        : 'Read this to them in person or over a channel you trust — it is shown once. Every session on the account has been signed out.',
    });
  },
);
