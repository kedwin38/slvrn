/**
 * Integration test harness.
 *
 * Runs the real Hono application against a real PostgreSQL database, with the Cloudflare
 * bindings replaced by in-memory doubles. The point is that *nothing about the application
 * is stubbed*: the same middleware, the same route handlers, the same state machines, the
 * same SQL and the same triggers that run in production run here.
 *
 * What is faked, and why that is honest:
 *   - Queues become an in-memory list the test drains by calling the real consumer. The
 *     consumer code is the production code; only the delivery mechanism differs.
 *   - R2 becomes a Map. Object semantics we rely on (put, get, head, delete) are trivial.
 *   - Hyperdrive becomes a plain connection string, which is what it resolves to anyway.
 *   - The Daraja HTTP client is given a scripted `fetch`, so provider behaviour — including
 *     failures, timeouts and duplicate callbacks — is exercised deterministically.
 *
 * This file is test infrastructure and is excluded from the Worker build.
 */

import postgres from 'postgres';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import type {
  Env,
  PaymentQueueMessage,
  CallbackQueueMessage,
  ReconciliationQueueMessage,
  BackupQueueMessage,
} from './env.js';

export interface QueuedMessage<T> {
  body: T;
  attempts: number;
  acked: boolean;
  retried: boolean;
  retryDelaySeconds: number | null;
}

/** In-memory stand-in for a Cloudflare Queue. */
export class FakeQueue<T> {
  readonly name: string;
  readonly messages: QueuedMessage<T>[] = [];

  constructor(name: string) {
    this.name = name;
  }

  async send(body: T): Promise<void> {
    this.messages.push({ body, attempts: 0, acked: false, retried: false, retryDelaySeconds: null });
  }

  async sendBatch(batch: { body: T }[]): Promise<void> {
    for (const item of batch) await this.send(item.body);
  }

  /** Messages not yet acknowledged, in delivery order. */
  pending(): QueuedMessage<T>[] {
    return this.messages.filter((m) => !m.acked);
  }

  /** Build the MessageBatch shape a consumer expects. */
  toBatch(): {
    queue: string;
    messages: {
      id: string;
      timestamp: Date;
      body: T;
      attempts: number;
      ack(): void;
      retry(options?: { delaySeconds?: number }): void;
    }[];
    ackAll(): void;
    retryAll(): void;
  } {
    const pending = this.pending();
    return {
      queue: this.name,
      messages: pending.map((message, index) => ({
        id: `msg-${index}`,
        timestamp: new Date(),
        body: message.body,
        attempts: message.attempts + 1,
        ack: () => {
          message.acked = true;
        },
        retry: (options?: { delaySeconds?: number }) => {
          message.retried = true;
          message.attempts += 1;
          message.retryDelaySeconds = options?.delaySeconds ?? 0;
        },
      })),
      ackAll: () => pending.forEach((m) => (m.acked = true)),
      retryAll: () => pending.forEach((m) => (m.retried = true)),
    };
  }

  clear(): void {
    this.messages.length = 0;
  }
}

/** In-memory stand-in for an R2 bucket. */
export class FakeR2 {
  readonly objects = new Map<string, { body: string; metadata: Record<string, string> }>();

  async put(
    key: string,
    value: string | ArrayBuffer,
    options?: { customMetadata?: Record<string, string> },
  ): Promise<{ key: string; size: number }> {
    const body = typeof value === 'string' ? value : new TextDecoder().decode(value);
    this.objects.set(key, { body, metadata: options?.customMetadata ?? {} });
    return { key, size: body.length };
  }

  async get(key: string): Promise<{ text(): Promise<string> } | null> {
    const object = this.objects.get(key);
    if (!object) return null;
    return { text: async () => object.body };
  }

  async head(key: string): Promise<{ size: number; customMetadata: Record<string, string> } | null> {
    const object = this.objects.get(key);
    if (!object) return null;
    return { size: object.body.length, customMetadata: object.metadata };
  }

  async delete(key: string): Promise<void> {
    this.objects.delete(key);
  }
}

/** Durable Object namespace double backing the rate limiter with an always-allow stub. */
class FakeRateLimiterNamespace {
  /** Set to false to exercise the throttled path. */
  allow = true;

  idFromName(name: string) {
    return { toString: () => name };
  }

  get(_id: unknown) {
    const allow = () => this.allow;
    return {
      async fetch(): Promise<Response> {
        return Response.json({
          allowed: allow(),
          remaining: allow() ? 19 : 0,
          retryAfterMs: allow() ? 0 : 1000,
        });
      },
    };
  }
}

export interface TestEnvironment {
  env: Env;
  sql: postgres.Sql<{}>;
  queues: {
    payments: FakeQueue<PaymentQueueMessage>;
    callbacks: FakeQueue<CallbackQueueMessage>;
    reconciliation: FakeQueue<ReconciliationQueueMessage>;
    backups: FakeQueue<BackupQueueMessage>;
  };
  r2: FakeR2;
  rateLimiter: FakeRateLimiterNamespace;
  /** Execution context double; `waitUntil` is awaited so tests are deterministic. */
  ctx: ExecutionContext;
  close(): Promise<void>;
}

export interface HarnessOptions {
  databaseUrl?: string;
  /** Unique per test file, so suites can run in parallel without colliding. */
  databaseName?: string;
}

const MIGRATIONS_DIR = join(import.meta.dirname ?? process.cwd(), '..', '..', '..', 'db', 'migrations');

/**
 * Create a disposable database with the full schema applied.
 *
 * A fresh database per suite, not a transaction rolled back at the end: the schema's own
 * immutability triggers make audit and transaction rows impossible to clean up, which is
 * exactly the property under test.
 */
export async function createTestEnvironment(options: HarnessOptions = {}): Promise<TestEnvironment> {
  const adminUrl =
    options.databaseUrl ??
    process.env.SOLVAREN_TEST_DATABASE_URL ??
    'postgres://postgres@localhost:5433/postgres';
  const databaseName = options.databaseName ?? `solvaren_it_${Date.now()}_${Math.floor(Math.random() * 1e6)}`;

  const admin = postgres(adminUrl, { max: 1, onnotice: () => {} });
  await admin.unsafe(`CREATE DATABASE ${databaseName}`);
  await admin.end({ timeout: 5 });

  const databaseUrl = adminUrl.replace(/\/[^/]*$/, `/${databaseName}`);
  const sql = postgres(databaseUrl, { max: 2, onnotice: () => {}, transform: { undefined: null } });

  for (const file of readdirSync(MIGRATIONS_DIR).filter((f) => f.endsWith('.sql')).sort()) {
    await sql.unsafe(readFileSync(join(MIGRATIONS_DIR, file), 'utf8'));
  }

  const queues = {
    payments: new FakeQueue<PaymentQueueMessage>('solvaren-payments'),
    callbacks: new FakeQueue<CallbackQueueMessage>('solvaren-callbacks'),
    reconciliation: new FakeQueue<ReconciliationQueueMessage>('solvaren-reconciliation'),
    backups: new FakeQueue<BackupQueueMessage>('solvaren-backups'),
  };
  const r2 = new FakeR2();
  const rateLimiter = new FakeRateLimiterNamespace();

  const env = {
    HYPERDRIVE: { connectionString: databaseUrl } as Hyperdrive,
    PAYMENT_QUEUE: queues.payments as unknown as Queue<PaymentQueueMessage>,
    CALLBACK_QUEUE: queues.callbacks as unknown as Queue<CallbackQueueMessage>,
    RECONCILIATION_QUEUE: queues.reconciliation as unknown as Queue<ReconciliationQueueMessage>,
    BACKUP_QUEUE: queues.backups as unknown as Queue<BackupQueueMessage>,
    ARTIFACTS: r2 as unknown as R2Bucket,
    RATE_LIMITER: rateLimiter as unknown as DurableObjectNamespace,
    SESSION_SIGNING_KEY: 'test-session-signing-key-0123456789abcdef',
    SECRET_ENCRYPTION_KEY: 'test-secret-encryption-key-0123456789abcdef',
    CALLBACK_SHARED_SECRET: 'test-callback-shared-secret-0123456789',
    ENVIRONMENT: 'development' as const,
    APP_ORIGIN: 'https://app.solvaren.test',
    API_BASE_URL: 'https://api.solvaren.test',
    WEBAUTHN_RP_ID: 'solvaren.test',
    WEBAUTHN_RP_NAME: 'SOLVAREN Test',
    DARAJA_ENVIRONMENT: 'sandbox' as const,
    // No AI key: the AI routes must degrade gracefully, which is itself under test.
  } as Env;

  const pending: Promise<unknown>[] = [];
  const ctx = {
    waitUntil: (promise: Promise<unknown>) => {
      pending.push(promise.catch(() => {}));
    },
    passThroughOnException: () => {},
    props: {},
  } as unknown as ExecutionContext;

  return {
    env,
    sql,
    queues,
    r2,
    rateLimiter,
    ctx,
    async close() {
      await Promise.all(pending);
      await sql.end({ timeout: 5 });
      const cleanup = postgres(adminUrl, { max: 1, onnotice: () => {} });
      await cleanup.unsafe(`DROP DATABASE IF EXISTS ${databaseName} WITH (FORCE)`).catch(() => {});
      await cleanup.end({ timeout: 5 });
    },
  };
}

/** Drain every pending message on a queue through its real consumer. */
export async function drainQueue<T>(
  queue: FakeQueue<T>,
  consumer: (batch: never, env: Env, ctx: ExecutionContext) => Promise<void>,
  env: Env,
  ctx: ExecutionContext,
): Promise<void> {
  if (queue.pending().length === 0) return;
  await consumer(queue.toBatch() as never, env, ctx);
}

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
export function scriptDaraja(script: DarajaScript = {}): ScriptedDaraja {
  const submissions: Record<string, unknown>[] = [];
  const statusQueries: Record<string, unknown>[] = [];
  let tokenCalls = 0;
  let b2cIndex = 0;

  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

  const impl = (async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const href = typeof url === 'string' ? url : url instanceof URL ? url.href : url.url;

    if (href.includes('/oauth/')) {
      tokenCalls += 1;
      if (script.token?.ok === false) {
        return json({ requestId: 'r', errorCode: '401.002.01', errorMessage: 'Invalid credentials' }, 401);
      }
      return json({ access_token: 'test-token', expires_in: '3599' });
    }

    if (href.includes('/b2c/')) {
      const body = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
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
        return json({ requestId: 'r', errorCode: '500.003.1001', errorMessage: 'Internal Server Error' }, 500);
      }

      return json({
        ConversationID: behaviour.conversationId ?? `AG_TEST_${submissions.length}`,
        OriginatorConversationID: body.OriginatorConversationID,
        ResponseCode: '0',
        ResponseDescription: 'Accept the service request successfully.',
      });
    }

    if (href.includes('/transactionstatus/')) {
      statusQueries.push(JSON.parse(String(init?.body ?? '{}')));
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
  }) as unknown as typeof fetch;

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
