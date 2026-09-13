/**
 * PostgreSQL-backed job queue.
 *
 * Claiming uses `FOR UPDATE SKIP LOCKED`, which is the standard way to turn a table into a
 * work queue: each worker locks the rows it takes, and concurrent workers skip past locked
 * rows instead of blocking on them. Two workers polling simultaneously get disjoint sets.
 *
 * Three properties the consumers depend on, stated explicitly because they are the ones
 * that matter when money is involved:
 *
 *  1. **Delivery is at-least-once.** A worker can claim a job, do its work, and die before
 *     recording success; the lease expires and the job is delivered again. Every consumer
 *     is written for this. The payment executor in particular commits its idempotency claim
 *     *before* calling Daraja, so a redelivery reconciles rather than paying twice.
 *
 *  2. **Enqueue can be transactional.** `send(job, tx)` writes the row inside the caller's
 *     transaction, so a job and the state change that justified it commit together. This is
 *     the property the Cloudflare Queues version could not have.
 *
 *  3. **A dead worker releases its work.** There is no broker here to notice a crash, so a
 *     claim carries a deadline. Past that deadline the job is claimable again. This is why
 *     `claimed_until` exists and why the visibility timeout must exceed the longest a
 *     consumer can legitimately take — a backup snapshot is the long pole.
 */

import { randomUUID } from 'node:crypto';
import type { Sql } from '../db/client.js';
import type {
  JobQueue,
  QueueJob,
  QueueName,
  QueueMessage,
  QueueBatch,
  EnqueueOptions,
} from '../env.js';

/**
 * Per-queue delivery policy.
 *
 * These mirror the values that were in `wrangler.toml`, because they were chosen for the
 * provider's constraints rather than the platform's.
 */
export interface QueuePolicy {
  /** Jobs claimed per poll. */
  batchSize: number;
  /** How long a claim is held before the job becomes claimable again. */
  visibilityTimeoutSeconds: number;
  /** Total delivery attempts before dead-lettering. */
  maxAttempts: number;
  /** Base delay for exponential backoff between attempts. */
  retryBackoffSeconds: number;
}

export const QUEUE_POLICIES: Record<QueueName, QueuePolicy> = {
  // Payment submission is deliberately the most conservative consumer on the platform.
  // Three attempts, then dead-letter: a payment is never retried into an unknown outcome
  // (spec 9.3) — the executor reconciles instead — so retries here only cover failures
  // that provably never reached M-PESA.
  payments: {
    batchSize: 10,
    visibilityTimeoutSeconds: 120,
    maxAttempts: 3,
    retryBackoffSeconds: 10,
  },
  callbacks: {
    batchSize: 25,
    visibilityTimeoutSeconds: 60,
    maxAttempts: 5,
    retryBackoffSeconds: 5,
  },
  reconciliation: {
    batchSize: 10,
    visibilityTimeoutSeconds: 180,
    maxAttempts: 3,
    retryBackoffSeconds: 30,
  },
  // A backup snapshot is long-running and memory-hungry: one at a time, and a generous
  // lease because exceeding it would hand the same snapshot to a second worker.
  backups: {
    batchSize: 1,
    visibilityTimeoutSeconds: 900,
    maxAttempts: 2,
    retryBackoffSeconds: 60,
  },
};

/** Every job body carries these two fields; the queue lifts them out into columns. */
interface JobBodyCommon {
  organizationId: string;
  correlationId: string;
}

/**
 * Producer.
 *
 * `send` accepts an optional transaction handle. Pass it whenever the enqueue belongs with
 * a state change — which, in this codebase, is nearly always.
 */
export class PostgresJobQueue implements JobQueue {
  constructor(private readonly pool: Sql) {}

  async send(job: QueueJob, tx?: Sql, options: EnqueueOptions = {}): Promise<void> {
    const sql = tx ?? this.pool;
    const body = job.body as unknown as JobBodyCommon;
    const policy = QUEUE_POLICIES[job.queue];
    const delaySeconds = Math.max(0, options.delaySeconds ?? 0);

    await sql`
      INSERT INTO job_queue (
        queue, body, organization_id, correlation_id, max_attempts, run_after
      )
      VALUES (
        ${job.queue},
        ${sql.json(job.body as never)},
        ${body.organizationId},
        ${body.correlationId},
        ${policy.maxAttempts},
        now() + make_interval(secs => ${delaySeconds})
      )
      -- A payment instruction may have at most one live job
      -- (job_queue_one_live_payment_per_instruction). A duplicate release attempt is a
      -- no-op here rather than an error: the first job is already queued and will run, so
      -- failing the caller would be reporting a problem that does not exist.
      ON CONFLICT DO NOTHING
    `;
  }
}

/** A batch of claimed jobs, typed so the runner can read each decision back. */
export interface ClaimedBatch<T> extends QueueBatch<T> {
  messages: ClaimedMessage<T>[];
}

/** A job row as claimed from the table. */
interface ClaimedJob {
  id: string;
  queue: QueueName;
  body: unknown;
  attempts: number;
}

/** What a consumer decided about each message, collected by the runner. */
type Disposition = { kind: 'ack' } | { kind: 'retry'; delaySeconds?: number };

/**
 * A claimed job, carrying the consumer's decision.
 *
 * The first call wins: a consumer that acks and then throws has still acked, which matches
 * the Cloudflare Queues semantics the consumers were written against. `disposition` stays
 * null when the consumer said nothing, and the runner treats that as a retry.
 */
class ClaimedMessage<T> implements QueueMessage<T> {
  disposition: Disposition | null = null;

  constructor(
    readonly id: string,
    readonly body: T,
    readonly attempts: number,
  ) {}

  ack(): void {
    this.disposition ??= { kind: 'ack' };
  }

  retry(options?: { delaySeconds?: number }): void {
    this.disposition ??= { kind: 'retry', ...(options ?? {}) };
  }
}

/**
 * Claim up to `batchSize` jobs from one queue.
 *
 * The claim is a single statement so it is atomic without an explicit transaction: the CTE
 * selects and locks candidate rows, and the UPDATE marks them in-flight. A crash between
 * the two is impossible because there is no "between".
 */
export async function claimBatch<T>(
  sql: Sql,
  queue: QueueName,
  workerId: string,
  policy: QueuePolicy = QUEUE_POLICIES[queue],
): Promise<ClaimedBatch<T>> {
  const rows = await sql<ClaimedJob[]>`
    WITH claimable AS (
      SELECT id
        FROM job_queue
       WHERE queue = ${queue}
         AND status = 'PENDING'
         AND run_after <= now()
       ORDER BY run_after, id
       LIMIT ${policy.batchSize}
       FOR UPDATE SKIP LOCKED
    )
    UPDATE job_queue AS j
       SET status        = 'IN_FLIGHT',
           attempts      = j.attempts + 1,
           claimed_at    = now(),
           claimed_by    = ${workerId},
           claimed_until = now() + make_interval(secs => ${policy.visibilityTimeoutSeconds})
      FROM claimable c
     WHERE j.id = c.id
    RETURNING j.id, j.queue, j.body, j.attempts
  `;

  const messages = rows.map((row) => new ClaimedMessage<T>(row.id, row.body as T, row.attempts));
  return { queue, messages };
}

/**
 * Record the outcome of a batch.
 *
 * A message the consumer neither acked nor retried is treated as a retry. That default is
 * deliberate: a consumer that threw partway through, or returned early on an unexpected
 * branch, has not told us the work is done, and assuming success would silently drop a
 * payment. Redelivery is safe here — every consumer is idempotent — whereas a false ack is
 * not recoverable.
 */
export async function settleBatch<T>(
  sql: Sql,
  batch: ClaimedBatch<T>,
  policy: QueuePolicy,
  error?: unknown,
): Promise<void> {
  const message = error ? describeError(error) : null;

  for (const held of batch.messages) {
    const disposition = held.disposition ?? { kind: 'retry' as const };

    if (disposition.kind === 'ack') {
      await sql`
        UPDATE job_queue
           SET status = 'SUCCEEDED', completed_at = now(),
               claimed_until = NULL, claimed_by = NULL
         WHERE id = ${held.id} AND status = 'IN_FLIGHT'
      `;
      continue;
    }

    // Exponential backoff, so a consistently failing dependency is not hammered.
    const delaySeconds =
      disposition.delaySeconds ?? policy.retryBackoffSeconds * 2 ** Math.max(0, held.attempts - 1);

    await sql`
      UPDATE job_queue
         SET status = CASE
                        WHEN attempts >= max_attempts THEN 'DEAD_LETTERED'
                        ELSE 'PENDING'
                      END,
             run_after = now() + make_interval(secs => ${delaySeconds}),
             dead_lettered_at = CASE
                                  WHEN attempts >= max_attempts THEN now()
                                  ELSE dead_lettered_at
                                END,
             -- A dead-lettered job must carry a reason (job_dead_lettered_requires_reason).
             -- When the consumer retried without throwing, say so rather than leaving the
             -- operator to guess.
             last_error = COALESCE(${message}, last_error, 'Consumer requested retry without recording an error'),
             claimed_until = NULL,
             claimed_by = NULL
       WHERE id = ${held.id} AND status = 'IN_FLIGHT'
    `;
  }
}

/**
 * Return jobs whose worker died holding them.
 *
 * Called on a timer. Without this, a job claimed by a process that was OOM-killed stays
 * IN_FLIGHT forever and the payment it represents never runs. The `claimed_until` deadline
 * is what makes the crash recoverable.
 */
export async function recoverExpiredLeases(sql: Sql): Promise<number> {
  const rows = await sql<{ id: string }[]>`
    UPDATE job_queue
       SET status = CASE
                      WHEN attempts >= max_attempts THEN 'DEAD_LETTERED'
                      ELSE 'PENDING'
                    END,
           dead_lettered_at = CASE
                                WHEN attempts >= max_attempts THEN now()
                                ELSE dead_lettered_at
                              END,
           last_error = 'Worker lease expired: the process holding this job stopped without recording an outcome',
           run_after = now(),
           claimed_until = NULL,
           claimed_by = NULL
     WHERE status = 'IN_FLIGHT'
       AND claimed_until < now()
    RETURNING id
  `;
  return rows.length;
}

function describeError(error: unknown): string {
  if (error instanceof Error) return `${error.name}: ${error.message}`.slice(0, 2000);
  return String(error).slice(0, 2000);
}

/** Identifies this process in `claimed_by`, for diagnosing a stuck job. */
export function workerIdentity(): string {
  const railway = process.env.RAILWAY_REPLICA_ID ?? process.env.RAILWAY_SERVICE_ID;
  return `${railway ?? 'local'}:${process.pid}:${randomUUID().slice(0, 8)}`;
}
