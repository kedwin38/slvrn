/**
 * SOLVAREN Payment Solutions — API Worker entry point.
 *
 * One Worker serves three roles, each with its own entry:
 *   `fetch`      — the HTTP API
 *   `queue`      — payment execution, callback processing, reconciliation and backups
 *   `scheduled`  — reconciliation sweeps, backup schedules and housekeeping
 *
 * Keeping them in one Worker means they share the same domain code, the same state
 * machines and the same audit writer. A reconciliation sweep cannot drift from the rules
 * the API enforces, because there is only one copy of those rules.
 */

import { Hono } from 'hono';
import {
  requestContext,
  securityHeaders,
  cors,
  errorHandler,
  limitBodySize,
} from './middleware/security.js';
import { authRoutes } from './routes/auth.js';
import { batchRoutes } from './routes/batches.js';
import { transactionRoutes } from './routes/transactions.js';
import { authorizationRoutes } from './routes/authorization.js';
import { dashboardRoutes } from './routes/dashboard.js';
import { adminRoutes } from './routes/admin.js';
import { aiRoutes } from './routes/ai.js';
import { callbackRoutes } from './routes/callbacks.js';
import { handlePaymentBatch } from './queues/payment-executor.js';
import { handleCallbackBatch } from './queues/callback-processor.js';
import { handleReconciliationBatch } from './queues/reconciliation-worker.js';
import { handleBackupBatch } from './queues/backup-worker.js';
import { withConnection } from './db/client.js';
export { OrganizationRateLimiter } from './rate-limiter.js';
import { correlationId } from '@solvaren/core';
import type {
  AppContext,
  Env,
  PaymentQueueMessage,
  CallbackQueueMessage,
  ReconciliationQueueMessage,
  BackupQueueMessage,
} from './env.js';

const app = new Hono<AppContext>();

// ---------------------------------------------------------------------------
// Global middleware. Order matters: context first so every later layer and the
// error handler can reach the correlation id.
// ---------------------------------------------------------------------------
app.use('*', requestContext);
app.use('*', securityHeaders);
app.use('*', cors);
// A generous default; the CSV upload route raises its own limit, and the auth routes
// lower theirs.
app.use('*', limitBodySize(1024 * 1024));

app.onError((err, c) => errorHandler(err, c as never) as never);

app.notFound((c) =>
  c.json(
    {
      error: {
        code: 'ROUTE_NOT_FOUND',
        category: 'NOT_FOUND',
        message: 'That endpoint does not exist',
        correlationId: c.get('correlationId'),
      },
    },
    404,
  ),
);

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

/** Liveness. Deliberately reveals nothing about version, tenancy or configuration. */
app.get('/health', (c) => c.json({ status: 'ok' }));

/**
 * Readiness, including database reachability. Not public — it is reachable only through
 * the Cloudflare Access policy on `/health/*` (see infra/terraform).
 */
app.get('/health/ready', async (c) => {
  const started = Date.now();
  try {
    await withConnection(c.env, c.executionCtx, async (sql) => {
      await sql`SELECT 1`;
    });
    return c.json({ status: 'ready', databaseLatencyMs: Date.now() - started });
  } catch {
    // The error text is not echoed: a connection string can appear in a driver message.
    return c.json({ status: 'degraded', reason: 'database unreachable' }, 503);
  }
});

// ---------------------------------------------------------------------------
// Route groups (spec 17)
// ---------------------------------------------------------------------------
app.route('/auth', authRoutes);
app.route('/batches', batchRoutes);
app.route('/payments', transactionRoutes);
app.route('/exports', transactionRoutes);
app.route('/authorization', authorizationRoutes);
app.route('/analytics', dashboardRoutes);
app.route('/admin', adminRoutes);
app.route('/ai', aiRoutes);
// The only route group that does not require a session; it authenticates by shared secret.
app.route('/integrations', callbackRoutes);

// ---------------------------------------------------------------------------
// Queue consumers
// ---------------------------------------------------------------------------

type AnyQueueMessage =
  | PaymentQueueMessage
  | CallbackQueueMessage
  | ReconciliationQueueMessage
  | BackupQueueMessage;

export default {
  fetch: app.fetch,

  /**
   * Route a batch by its queue name.
   *
   * Each consumer acknowledges or retries per message rather than per batch: one poisoned
   * message must not force thirty healthy payments to be redelivered, which would be
   * thirty more opportunities for a double submission.
   */
  async queue(batch: MessageBatch<AnyQueueMessage>, env: Env, ctx: ExecutionContext): Promise<void> {
    switch (batch.queue) {
      case 'solvaren-payments':
      case 'solvaren-payments-staging':
        await handlePaymentBatch(batch as MessageBatch<PaymentQueueMessage>, env, ctx);
        break;
      case 'solvaren-callbacks':
      case 'solvaren-callbacks-staging':
        await handleCallbackBatch(batch as MessageBatch<CallbackQueueMessage>, env, ctx);
        break;
      case 'solvaren-reconciliation':
      case 'solvaren-reconciliation-staging':
        await handleReconciliationBatch(batch as MessageBatch<ReconciliationQueueMessage>, env, ctx);
        break;
      case 'solvaren-backups':
      case 'solvaren-backups-staging':
        await handleBackupBatch(batch as MessageBatch<BackupQueueMessage>, env, ctx);
        break;
      default:
        // An unrecognised queue is a deployment error. Acknowledge rather than loop, and
        // make it loud in the logs.
        console.error(
          JSON.stringify({ level: 'error', message: 'Unknown queue', queue: batch.queue }),
        );
        for (const message of batch.messages) message.ack();
    }
  },

  /**
   * Scheduled work (spec 10, TRK-008, 13.4).
   *
   * Cron expressions are declared in wrangler.toml; this dispatches on which one fired.
   */
  async scheduled(event: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    const correlation = correlationId();

    switch (event.cron) {
      // Every five minutes: sweep in-flight transactions for every organisation.
      case '*/5 * * * *':
        ctx.waitUntil(runReconciliationSweep(env, ctx, correlation));
        break;

      // Hourly: fire due backup schedules and record missed ones.
      case '0 * * * *':
        ctx.waitUntil(runBackupSchedules(env, ctx, correlation));
        break;

      // Daily at 02:00 UTC (05:00 East Africa Time): housekeeping.
      case '0 2 * * *':
        ctx.waitUntil(runHousekeeping(env, ctx, correlation));
        break;

      default:
        console.warn(JSON.stringify({ level: 'warn', message: 'Unhandled cron', cron: event.cron }));
    }
  },
};

/** Enqueue a reconciliation sweep per organisation with an enabled integration. */
async function runReconciliationSweep(
  env: Env,
  ctx: ExecutionContext,
  correlation: string,
): Promise<void> {
  await withConnection(env, ctx, async (sql) => {
    const organizations = await sql<{ organization_id: string }[]>`
      SELECT DISTINCT t.organization_id
        FROM transactions t
        JOIN daraja_configurations dc
          ON dc.organization_id = t.organization_id AND dc.status = 'ENABLED'
       WHERE t.status IN ('SUBMITTED', 'AWAITING_CALLBACK', 'PROCESSING', 'TIMEOUT', 'RECONCILING')
         AND t.submitted_at < now() - interval '10 minutes'
    `;

    for (const org of organizations) {
      const message: ReconciliationQueueMessage = {
        type: 'SWEEP_ORGANIZATION',
        organizationId: org.organization_id,
        correlationId: correlation,
      };
      await env.RECONCILIATION_QUEUE.send(message);
    }

    if (organizations.length > 0) {
      console.info(
        JSON.stringify({
          level: 'info',
          message: 'Reconciliation sweep dispatched',
          organizations: organizations.length,
          correlationId: correlation,
        }),
      );
    }
  });
}

/**
 * Fire due backup schedules.
 *
 * Spec 13.4: "A missed execution must be observable as a failed or missed backup event
 * rather than silently disappearing." A schedule whose window has passed by more than two
 * hours records a MISSED attempt before the next run is queued, so the gap is visible in
 * the history instead of being inferred from its absence.
 */
async function runBackupSchedules(env: Env, ctx: ExecutionContext, correlation: string): Promise<void> {
  await withConnection(env, ctx, async (sql) => {
    const due = await sql<
      { organization_id: string; schedule_cron: string; last_scheduled_run_at: string | null; next_scheduled_run_at: string | null }[]
    >`
      SELECT organization_id, schedule_cron, last_scheduled_run_at, next_scheduled_run_at
        FROM backup_configurations
       WHERE schedule_enabled = TRUE
         AND suspended_at IS NULL
         AND (next_scheduled_run_at IS NULL OR next_scheduled_run_at <= now())
    `;

    for (const schedule of due) {
      // Record the miss before queueing the new run, so the history shows both.
      if (schedule.next_scheduled_run_at) {
        const overdueHours =
          (Date.now() - new Date(schedule.next_scheduled_run_at).getTime()) / 3_600_000;
        if (overdueHours > 2) {
          await sql`
            INSERT INTO backup_attempts (
              organization_id, attempt_reference, trigger_type, status, started_at, ended_at,
              target_description, error_code, error_message, correlation_id
            ) VALUES (
              ${schedule.organization_id},
              ${'BAK-MISSED-' + new Date(schedule.next_scheduled_run_at).toISOString().slice(0, 16)},
              'SCHEDULED', 'MISSED', ${schedule.next_scheduled_run_at}, now(),
              ${'scheduled window'}, 'SCHEDULE_MISSED',
              ${`The backup scheduled for ${schedule.next_scheduled_run_at} did not run and is ${Math.floor(overdueHours)} hours overdue.`},
              ${correlation}
            )
            ON CONFLICT (organization_id, attempt_reference) DO NOTHING
          `;
        }
      }

      const message: BackupQueueMessage = {
        type: 'RUN_BACKUP',
        organizationId: schedule.organization_id,
        trigger: 'SCHEDULED',
        correlationId: correlation,
      };
      await env.BACKUP_QUEUE.send(message);

      // Next window: the cron string is stored for display, but the scheduler advances in
      // fixed daily steps, which is what the supported schedules (daily/weekly) need.
      await sql`
        UPDATE backup_configurations
           SET last_scheduled_run_at = now(),
               next_scheduled_run_at = now() + interval '1 day'
         WHERE organization_id = ${schedule.organization_id}
      `;
    }
  });
}

/** Daily housekeeping: expire stale ceremonies and sessions. Never touches ledger rows. */
async function runHousekeeping(env: Env, ctx: ExecutionContext, correlation: string): Promise<void> {
  await withConnection(env, ctx, async (sql) => {
    // An authorization ceremony left open past its expiry blocks the partial unique index
    // and prevents a new one from being started.
    const abandoned = await sql<{ id: string }[]>`
      UPDATE authorization_challenges
         SET abandoned_at = now()
       WHERE consumed_at IS NULL AND abandoned_at IS NULL AND expires_at < now() - interval '1 hour'
      RETURNING id
    `;
    if (abandoned.length > 0) {
      await sql`
        UPDATE payment_batches SET state = 'L3_READY'
         WHERE state = 'AUTHORIZATION_PENDING'
           AND id IN (
             SELECT batch_id FROM authorization_challenges
              WHERE id = ANY(${abandoned.map((a) => a.id)}::uuid[])
           )
      `;
    }

    await sql`
      UPDATE sessions SET revoked_at = now(), revocation_reason = 'Expired'
       WHERE revoked_at IS NULL AND expires_at < now() - interval '1 day'
    `;

    console.info(
      JSON.stringify({
        level: 'info',
        message: 'Housekeeping complete',
        expiredCeremonies: abandoned.length,
        correlationId: correlation,
      }),
    );
  });
}
