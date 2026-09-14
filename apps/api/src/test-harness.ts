/**
 * Integration test harness.
 *
 * Runs the real Hono application against a real PostgreSQL database. The point is that
 * *nothing about the application is stubbed*: the same middleware, the same route handlers,
 * the same state machines, the same SQL and the same triggers that run in production run
 * here.
 *
 * Since the move to Railway there is less to fake than there was, which is the main reason
 * the port was worth doing carefully:
 *
 *   - **The queue is real.** It is the same `job_queue` table, the same `FOR UPDATE SKIP
 *     LOCKED` claim and the same settle logic that production runs. Previously this was an
 *     in-memory list, so the tests proved the consumers worked but proved nothing about
 *     delivery, retry, dead-lettering or the transactional enqueue. Now they do.
 *   - **The rate limiter is real**, backed by the same table, with a switch to force the
 *     throttled path.
 *   - **Object storage is a Map.** The four operations we rely on (put, get, head, delete)
 *     are trivial, and signing them against a live S3 would make the suite need network and
 *     credentials. The SigV4 implementation is covered separately.
 *   - **The Daraja HTTP client is given a scripted `fetch`**, so provider behaviour —
 *     including failures, timeouts and duplicate callbacks — is exercised deterministically.
 *
 * This file is test infrastructure and is excluded from the production build.
 */

import postgres from 'postgres';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import type { Sql } from './db/client.js';
import { PostgresJobQueue } from './queue/queue.js';
import { drainQueuesOnce } from './queue/runner.js';
import { PostgresRateLimiter } from './rate-limiter.js';
import type {
  Env,
  ObjectStore,
  ObjectPutOptions,
  ObjectBody,
  ObjectMetadata,
  RateLimiter,
  QueueName,
  PaymentQueueMessage,
  CallbackQueueMessage,
  ReconciliationQueueMessage,
  BackupQueueMessage,
  AnyQueueMessage,
} from './env.js';

/** A job as a test sees it: the payload plus the delivery bookkeeping around it. */
export interface QueuedMessage<T> {
  id: string;
  body: T;
  attempts: number;
  status: 'PENDING' | 'IN_FLIGHT' | 'SUCCEEDED' | 'DEAD_LETTERED';
  lastError: string | null;
}

/**
 * Read-side view of one queue.
 *
 * Every method is async because the queue is a table now rather than an array. That is a
 * real cost in test ergonomics and it buys something worth more: an assertion about what is
 * queued is an assertion about what production would actually deliver.
 */
export class QueueInspector<T> {
  constructor(
    private readonly sql: Sql,
    private readonly queue: QueueName,
    private readonly producer: PostgresJobQueue,
  ) {}

  /** Enqueue directly, for tests that exercise a consumer without the route that feeds it. */
  async send(body: T): Promise<void> {
    await this.producer.send({ queue: this.queue, body } as never);
  }

  /** Every job ever enqueued on this queue, oldest first. */
  async all(): Promise<QueuedMessage<T>[]> {
    const rows = await this.sql<
      { id: string; body: T; attempts: number; status: string; last_error: string | null }[]
    >`
      SELECT id, body, attempts, status, last_error
        FROM job_queue WHERE queue = ${this.queue}
       ORDER BY created_at, id
    `;
    return rows.map((row) => ({
      id: row.id,
      body: row.body,
      attempts: row.attempts,
      status: row.status as QueuedMessage<T>['status'],
      lastError: row.last_error,
    }));
  }

  /** Jobs still awaiting delivery. */
  async pending(): Promise<QueuedMessage<T>[]> {
    return (await this.all()).filter((m) => m.status === 'PENDING' || m.status === 'IN_FLIGHT');
  }

  /** Jobs that exhausted their attempts. */
  async deadLettered(): Promise<QueuedMessage<T>[]> {
    return (await this.all()).filter((m) => m.status === 'DEAD_LETTERED');
  }

  async count(): Promise<number> {
    return (await this.all()).length;
  }

  /**
   * Simulate an at-least-once redelivery of a job that already ran.
   *
   * The honest simulation is a second row with the same body: that is exactly what a broker
   * redelivering a message looks like to a consumer, and it is what happens here when a
   * worker dies after doing its work but before settling, and the lease expires.
   *
   * Note what this does NOT do — it does not reopen the original job. The
   * `job_queue_guard_update` trigger forbids that, because a terminal job coming back to
   * life would re-submit a payment that already settled. A test that reached for that would
   * be testing something the database refuses to allow.
   */
  async redeliver(id: string): Promise<void> {
    await this.sql`
      INSERT INTO job_queue (queue, body, organization_id, correlation_id, max_attempts)
      SELECT queue, body, organization_id, correlation_id, max_attempts
        FROM job_queue WHERE id = ${id}
    `;
  }

  /** Remove every job on this queue, so a test can assert on what a later action enqueues. */
  async clear(): Promise<void> {
    await this.sql`DELETE FROM job_queue WHERE queue = ${this.queue}`;
  }
}

/**
 * In-memory object store.
 *
 * Implements the same four-method `ObjectStore` interface the S3 client does, so the code
 * under test cannot tell the difference.
 */
export class InMemoryObjectStore implements ObjectStore {
  readonly objects = new Map<string, { body: Uint8Array; metadata: Record<string, string> }>();

  async put(key: string, body: string | Uint8Array, options: ObjectPutOptions = {}): Promise<void> {
    const bytes = typeof body === 'string' ? new TextEncoder().encode(body) : body;
    this.objects.set(key, { body: bytes, metadata: options.metadata ?? {} });
  }

  async get(key: string): Promise<ObjectBody | null> {
    const object = this.objects.get(key);
    if (!object) return null;
    return {
      size: object.body.byteLength,
      text: async () => new TextDecoder().decode(object.body),
      bytes: async () => object.body,
    };
  }

  async head(key: string): Promise<ObjectMetadata | null> {
    const object = this.objects.get(key);
    if (!object) return null;
    return { size: object.body.byteLength, etag: null };
  }

  async delete(key: string): Promise<void> {
    this.objects.delete(key);
  }
}

/**
 * The real Postgres rate limiter, with a switch.
 *
 * Delegates to the production implementation so the bucket arithmetic and row locking are
 * genuinely exercised, but can be forced to refuse so the throttled path in the payment
 * executor is reachable without submitting twenty payments to drain a bucket.
 */
export class ControllableRateLimiter implements RateLimiter {
  /** Set to false to exercise the throttled path. */
  allow = true;

  private readonly real: PostgresRateLimiter;

  constructor(sql: Sql) {
    this.real = new PostgresRateLimiter(sql);
  }

  async acquire(
    organizationId: string,
    options?: { permits?: number; ratePerSecond?: number; burst?: number },
  ): Promise<{ allowed: boolean; remaining: number; retryAfterMs: number }> {
    if (!this.allow) return { allowed: false, remaining: 0, retryAfterMs: 1000 };
    return this.real.acquire(organizationId, options);
  }
}

export interface TestEnvironment {
  env: Env;
  sql: Sql;
  queues: {
    payments: QueueInspector<PaymentQueueMessage>;
    callbacks: QueueInspector<CallbackQueueMessage>;
    reconciliation: QueueInspector<ReconciliationQueueMessage>;
    backups: QueueInspector<BackupQueueMessage>;
  };
  storage: InMemoryObjectStore;
  rateLimiter: ControllableRateLimiter;
  /**
   * Run pending jobs through their real consumers, once.
   *
   * Claims and settles exactly as the production runner does, so a test that drains is
   * testing delivery as well as the consumer.
   */
  drain(queue?: QueueName): Promise<number>;
  close(): Promise<void>;
}

export interface HarnessOptions {
  databaseUrl?: string;
  /** Unique per test file, so suites can run in parallel without colliding. */
  databaseName?: string;
}

const MIGRATIONS_DIR = join(
  import.meta.dirname ?? process.cwd(),
  '..',
  '..',
  '..',
  'db',
  'migrations',
);

/**
 * Create a disposable database with the full schema applied.
 *
 * A fresh database per suite, not a transaction rolled back at the end: the schema's own
 * immutability triggers make audit and transaction rows impossible to clean up, which is
 * exactly the property under test.
 */
export async function createTestEnvironment(
  options: HarnessOptions = {},
): Promise<TestEnvironment> {
  const adminUrl =
    options.databaseUrl ??
    process.env.SOLVAREN_TEST_DATABASE_URL ??
    'postgres://postgres@localhost:5433/postgres';
  const databaseName =
    options.databaseName ?? `solvaren_it_${Date.now()}_${Math.floor(Math.random() * 1e6)}`;

  const admin = postgres(adminUrl, { max: 1, onnotice: () => {} });
  await admin.unsafe(`CREATE DATABASE ${databaseName}`);
  await admin.end({ timeout: 5 });

  const databaseUrl = adminUrl.replace(/\/[^/]*$/, `/${databaseName}`);
  const sql = postgres(databaseUrl, {
    max: 4,
    onnotice: () => {},
    transform: { undefined: null },
    fetch_types: false,
  }) as Sql;

  for (const file of readdirSync(MIGRATIONS_DIR)
    .filter((f) => f.endsWith('.sql'))
    .sort()) {
    await sql.unsafe(readFileSync(join(MIGRATIONS_DIR, file), 'utf8'));
  }

  const producer = new PostgresJobQueue(sql);
  const storage = new InMemoryObjectStore();
  const rateLimiter = new ControllableRateLimiter(sql);

  const env: Env = {
    sql,
    queue: producer,
    objects: storage,
    rateLimiter,
    SESSION_SIGNING_KEY: 'test-session-signing-key-0123456789abcdef',
    SECRET_ENCRYPTION_KEY: 'test-secret-encryption-key-0123456789abcdef',
    CALLBACK_SHARED_SECRET: 'test-callback-shared-secret-0123456789',
    ENVIRONMENT: 'development',
    APP_ORIGIN: 'https://app.solvaren.test',
    API_BASE_URL: 'https://api.solvaren.test',
    WEBAUTHN_RP_ID: 'solvaren.test',
    WEBAUTHN_RP_NAME: 'SOLVAREN Test',
    DARAJA_ENVIRONMENT: 'sandbox',
    // No AI key: the AI routes must degrade gracefully, which is itself under test.
  };

  const queues = {
    payments: new QueueInspector<PaymentQueueMessage>(sql, 'payments', producer),
    callbacks: new QueueInspector<CallbackQueueMessage>(sql, 'callbacks', producer),
    reconciliation: new QueueInspector<ReconciliationQueueMessage>(sql, 'reconciliation', producer),
    backups: new QueueInspector<BackupQueueMessage>(sql, 'backups', producer),
  };

  return {
    env,
    sql,
    queues,
    storage,
    rateLimiter,
    async drain(queue?: QueueName) {
      return drainQueuesOnce(env, queue);
    },
    async close() {
      await sql.end({ timeout: 5 });
      const cleanup = postgres(adminUrl, { max: 1, onnotice: () => {} });
      await cleanup.unsafe(`DROP DATABASE IF EXISTS ${databaseName} WITH (FORCE)`).catch(() => {});
      await cleanup.end({ timeout: 5 });
    },
  };
}

export type { AnyQueueMessage };

// ---------------------------------------------------------------------------
// Scripted Daraja provider
// ---------------------------------------------------------------------------

export interface DarajaScript {
  /** Response for the OAuth token call. */
  token?: { ok: boolean };
  /** Per-call behaviour for B2C submissions, consumed in order. */
  b2c?: (
    | { kind: 'accept'; conversationId?: string }
    | { kind: 'reject'; httpStatus: number; errorCode: string; errorMessage: string }
    | { kind: 'timeout' }
    | { kind: 'server-error' }
  )[];
  statusQuery?: { kind: 'accept' } | { kind: 'reject' };
  accountBalance?: { kind: 'accept' };
}

export interface ScriptedDaraja {
  fetch: typeof fetch;
  /** Bodies of every B2C request that actually reached the provider. */
  submissions: Record<string, unknown>[];
  tokenCalls: number;
  statusQueries: Record<string, unknown>[];
}

/**
 * Build a `fetch` that behaves like Daraja according to a script.
 *
 * Recording the submissions is the important part: the double-payment tests assert on the
 * exact number of requests that reached the provider, which is the only measurement that
 * actually matters for "did we pay twice".
 */
/**
 * Read a scripted request body as JSON.
 *
 * `RequestInit['body']` is a `BodyInit`, which includes Blob, FormData and streams. Passing
 * one of those to `String()` yields "[object Object]", and the resulting parse error points
 * at the harness rather than at the caller that sent the wrong shape. The Daraja client
 * sends a JSON string and nothing else, so anything else is a bug worth failing on loudly.
 */
function scriptedJsonBody(init?: RequestInit): Record<string, unknown> {
  const body = init?.body;
  if (body === undefined || body === null) return {};
  if (typeof body !== 'string') {
    throw new Error(
      `Daraja script received a non-string request body (${Object.prototype.toString.call(body)}). ` +
        'The Daraja client is expected to send JSON text.',
    );
  }
  return JSON.parse(body) as Record<string, unknown>;
}

export function scriptDaraja(script: DarajaScript = {}): ScriptedDaraja {
  const submissions: Record<string, unknown>[] = [];
  const statusQueries: Record<string, unknown>[] = [];
  let tokenCalls = 0;
  let b2cIndex = 0;

  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

  const impl: typeof fetch = async (
    url: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> => {
    const href = typeof url === 'string' ? url : url instanceof URL ? url.href : url.url;

    if (href.includes('/oauth/')) {
      tokenCalls += 1;
      if (script.token?.ok === false) {
        return json(
          { requestId: 'r', errorCode: '401.002.01', errorMessage: 'Invalid credentials' },
          401,
        );
      }
      return json({ access_token: 'test-token', expires_in: '3599' });
    }

    if (href.includes('/b2c/')) {
      const body = scriptedJsonBody(init);
      const behaviour = script.b2c?.[b2cIndex] ?? { kind: 'accept' as const };
      b2cIndex += 1;

      if (behaviour.kind === 'timeout') {
        // Record it: a timeout means the request DID reach the provider, which is the
        // whole reason the executor must reconcile rather than resend.
        submissions.push(body);
        const error = new Error('aborted');
        error.name = 'AbortError';
        throw error;
      }

      submissions.push(body);

      if (behaviour.kind === 'reject') {
        return json(
          { requestId: 'r', errorCode: behaviour.errorCode, errorMessage: behaviour.errorMessage },
          behaviour.httpStatus,
        );
      }
      if (behaviour.kind === 'server-error') {
        return json(
          { requestId: 'r', errorCode: '500.003.1001', errorMessage: 'Internal Server Error' },
          500,
        );
      }

      return json({
        ConversationID: behaviour.conversationId ?? `AG_TEST_${submissions.length}`,
        OriginatorConversationID: body.OriginatorConversationID,
        ResponseCode: '0',
        ResponseDescription: 'Accept the service request successfully.',
      });
    }

    if (href.includes('/transactionstatus/')) {
      statusQueries.push(scriptedJsonBody(init));
      if (script.statusQuery?.kind === 'reject') {
        return json({ requestId: 'r', errorCode: '500.003.1001', errorMessage: 'error' }, 500);
      }
      return json({
        ConversationID: 'AG_STATUS',
        OriginatorConversationID: 'status-query',
        ResponseCode: '0',
        ResponseDescription: 'Accept the service request successfully.',
      });
    }

    if (href.includes('/accountbalance/')) {
      return json({
        ConversationID: 'AG_BALANCE',
        ResponseCode: '0',
        ResponseDescription: 'Accept the service request successfully.',
      });
    }

    return json({ error: 'unexpected endpoint' }, 404);
  };

  return {
    fetch: impl,
    submissions,
    get tokenCalls() {
      return tokenCalls;
    },
    statusQueries,
  };
}

/** Build a Daraja B2C success callback body for a given originator id. */
export function b2cSuccessCallback(
  originatorConversationId: string,
  receipt = 'SG632NMUAB',
  amountShillings = 45000,
): unknown {
  return {
    Result: {
      ResultType: 0,
      ResultCode: 0,
      ResultDesc: 'The service request is processed successfully.',
      OriginatorConversationID: originatorConversationId,
      ConversationID: 'AG_TEST_CALLBACK',
      TransactionID: receipt,
      ResultParameters: {
        ResultParameter: [
          { Key: 'TransactionAmount', Value: amountShillings },
          { Key: 'TransactionReceipt', Value: receipt },
          { Key: 'ReceiverPartyPublicName', Value: '254712345678 - Test Recipient' },
          { Key: 'TransactionCompletedDateTime', Value: '13.09.2026 11:30:45' },
          { Key: 'B2CUtilityAccountAvailableFunds', Value: 228037.0 },
          { Key: 'B2CWorkingAccountAvailableFunds', Value: 700000.0 },
          { Key: 'B2CRecipientIsRegisteredCustomer', Value: 'Y' },
          { Key: 'B2CChargesPaidAccountAvailableFunds', Value: -1540.0 },
        ],
      },
    },
  };
}

/** Build a Daraja B2C failure callback body. */
export function b2cFailureCallback(
  originatorConversationId: string,
  resultCode = '1',
  resultDesc = 'The balance is insufficient for the transaction',
): unknown {
  return {
    Result: {
      ResultType: 0,
      ResultCode: resultCode,
      ResultDesc: resultDesc,
      OriginatorConversationID: originatorConversationId,
      ConversationID: 'AG_TEST_CALLBACK_FAIL',
    },
  };
}
