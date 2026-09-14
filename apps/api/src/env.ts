/**
 * Runtime environment and service container.
 *
 * SOLVAREN runs as an ordinary Node process on Railway. Where the Cloudflare build received
 * platform *bindings* injected by the runtime, this one receives a small set of interfaces
 * constructed once at boot from validated environment variables (see `config.ts`).
 *
 * The shape is deliberately flat and the interfaces deliberately narrow. `ObjectStore` has
 * four methods because those are the four the application actually calls; `JobQueue` has
 * one. A narrow seam is what made this port a day's work rather than a rewrite, and it is
 * what will make the next one cheap too.
 *
 * Secrets arrive as process environment variables set by Railway. They are never logged,
 * never returned by an API, and never written to an audit detail payload (NFR-SEC-003).
 * `config.ts` refuses to start the process if any of them is missing or too weak.
 */

import type { AuthorityLevel } from '@solvaren/core';
import type { Sql } from './db/client.js';

// ---------------------------------------------------------------------------
// Platform interfaces
// ---------------------------------------------------------------------------

/**
 * Object storage for backups, encrypted secret envelopes and generated artefacts.
 *
 * Four methods, because four is what the application uses. Any S3-compatible target
 * satisfies this — Cloudflare R2, Backblaze B2, AWS S3, or MinIO running alongside the app
 * on Railway. Spec BAK-001 already required an S3-compatible target, so this interface is
 * the specification's own shape rather than a concession to the move.
 */
export interface ObjectStore {
  put(key: string, body: string | Uint8Array, options?: ObjectPutOptions): Promise<void>;
  /** Returns null when the object does not exist, rather than throwing. */
  get(key: string): Promise<ObjectBody | null>;
  /** Metadata only. Used to verify a backup really landed before recording SUCCESS. */
  head(key: string): Promise<ObjectMetadata | null>;
  delete(key: string): Promise<void>;
}

export interface ObjectPutOptions {
  contentType?: string;
  /** Opaque metadata stored alongside the object. */
  metadata?: Record<string, string>;
}

export interface ObjectBody {
  text(): Promise<string>;
  bytes(): Promise<Uint8Array>;
  size: number;
}

export interface ObjectMetadata {
  size: number;
  etag: string | null;
}

/**
 * Enqueue a job for asynchronous processing.
 *
 * The queue is a PostgreSQL table, which means `send` can be called with a transaction
 * handle and the enqueue then commits atomically with the state change that justified it.
 * That property is the reason for the choice: on the Cloudflare build, a Worker that died
 * between committing a database change and enqueueing its follow-up left the two
 * disagreeing. Here that window does not exist.
 *
 * Pass `tx` whenever the enqueue is part of a larger unit of work. Omitting it enqueues on
 * its own connection, which is correct only when there is nothing to be atomic with.
 */
export interface JobQueue {
  send(job: QueueJob, tx?: Sql, options?: EnqueueOptions): Promise<void>;
}

export interface EnqueueOptions {
  /**
   * Hold the job back for this many seconds before it becomes claimable.
   *
   * Used where running immediately would be wasted work — a reconciliation queued the
   * instant a payment is submitted has nothing to reconcile yet, because the provider has
   * not answered.
   */
  delaySeconds?: number;
}

/** Per-organisation submission permits, aligned to the active Daraja contract (§10). */
export interface RateLimiter {
  acquire(
    organizationId: string,
    options?: { permits?: number; ratePerSecond?: number; burst?: number },
  ): Promise<{ allowed: boolean; remaining: number; retryAfterMs: number }>;
}

// ---------------------------------------------------------------------------
// The environment handed to every route, consumer and scheduled job
// ---------------------------------------------------------------------------

export interface Env {
  // ---- Services -----------------------------------------------------------
  /** Connection pool to the system of record. */
  sql: Sql;
  /** Producer side of the PostgreSQL-backed job queue. */
  queue: JobQueue;
  /** S3-compatible object storage. */
  objects: ObjectStore;
  /** Per-organisation submission rate limiting. */
  rateLimiter: RateLimiter;

  // ---- Secrets (Railway environment variables) ----------------------------
  /** Key used to derive per-organisation secret lookups and sign session tokens. */
  SESSION_SIGNING_KEY: string;
  /** Master key for envelope-encrypting organisation secrets at rest. */
  SECRET_ENCRYPTION_KEY: string;
  /** Shared secret Daraja callbacks must present (§9.4). */
  CALLBACK_SHARED_SECRET: string;
  /** AI provider key. Absent in environments where the AI layer is disabled. */
  AI_API_KEY?: string;

  // ---- Configuration ------------------------------------------------------
  ENVIRONMENT: 'development' | 'staging' | 'production';
  /** Public origin of the web application, used for WebAuthn and CORS. */
  APP_ORIGIN: string;
  /** WebAuthn Relying Party ID — the registrable domain, e.g. `solvaren.example`. */
  WEBAUTHN_RP_ID: string;
  WEBAUTHN_RP_NAME: string;
  /** Public base URL of this API, used to build provider callback URLs. */
  API_BASE_URL: string;
  /** Daraja environment override for non-production deployments. */
  DARAJA_ENVIRONMENT?: 'sandbox' | 'production';
  AI_MODEL?: string;
}

// ---------------------------------------------------------------------------
// Queue message contracts
// ---------------------------------------------------------------------------

/** The queues a job may be routed to. One table, this column selects the consumer. */
export type QueueName = 'payments' | 'callbacks' | 'reconciliation' | 'backups';

/**
 * One authorized payment instruction to submit to Daraja.
 *
 * The message carries the manifest hash and fingerprint so the consumer can re-verify that
 * what it is about to pay is what was authorized — a message that has been tampered with
 * in transit, or that refers to a batch edited since, fails that check and is dead-lettered
 * rather than paid.
 */
export interface PaymentQueueMessage {
  type: 'EXECUTE_INSTRUCTION';
  organizationId: string;
  batchId: string;
  instructionId: string;
  /** Batch version at authorization. */
  batchVersion: number;
  manifestHash: string;
  fingerprint: string;
  challengeId: string;
  correlationId: string;
  attempt: number;
  /**
   * Which deliberate re-attempt this is, for an operator retrying a FAILED payment.
   *
   * Absent for an original execution. The executor MUST thread it back into
   * `instructionFingerprint`, or the fingerprint it re-derives will not match the one the
   * retry claimed and the message is refused as tampered-with.
   */
  retrySequence?: number;
}

export interface CallbackQueueMessage {
  type: 'PROCESS_CALLBACK';
  callbackId: string;
  organizationId: string;
  callbackType: 'B2C_RESULT' | 'B2C_TIMEOUT' | 'TRANSACTION_STATUS' | 'ACCOUNT_BALANCE';
  correlationId: string;
}

export interface ReconciliationQueueMessage {
  type: 'RECONCILE_TRANSACTION' | 'SWEEP_ORGANIZATION' | 'REFRESH_BALANCE';
  organizationId: string;
  transactionId?: string;
  /** Set when a user pressed "refresh status" rather than the sweep firing. */
  requestedByUserId?: string;
  correlationId: string;
}

export interface BackupQueueMessage {
  type: 'RUN_BACKUP' | 'ENFORCE_RETENTION';
  organizationId: string;
  attemptId?: string;
  trigger: 'MANUAL' | 'SCHEDULED';
  requestedByUserId?: string;
  correlationId: string;
}

/** A job as handed to `JobQueue.send`: the destination plus its typed payload. */
export type QueueJob =
  | { queue: 'payments'; body: PaymentQueueMessage }
  | { queue: 'callbacks'; body: CallbackQueueMessage }
  | { queue: 'reconciliation'; body: ReconciliationQueueMessage }
  | { queue: 'backups'; body: BackupQueueMessage };

export type AnyQueueMessage =
  PaymentQueueMessage | CallbackQueueMessage | ReconciliationQueueMessage | BackupQueueMessage;

/**
 * One claimed job, as handed to a consumer.
 *
 * `ack` and `retry` mirror the Cloudflare Queues contract deliberately: the consumers were
 * written against per-message acknowledgement so that one poisoned message cannot force
 * thirty healthy payments to be redelivered, and that property is worth preserving exactly.
 */
export interface QueueMessage<T> {
  id: string;
  body: T;
  /** How many times this job has previously been delivered. First delivery is 1. */
  attempts: number;
  ack(): void;
  retry(options?: { delaySeconds?: number }): void;
}

/** A batch of claimed jobs from one queue. */
export interface QueueBatch<T> {
  queue: QueueName;
  messages: QueueMessage<T>[];
}

// ---------------------------------------------------------------------------
// Request context
// ---------------------------------------------------------------------------

export interface AuthenticatedActor {
  userId: string;
  organizationId: string;
  organizationSlug: string;
  level: AuthorityLevel;
  status: 'ACTIVE' | 'DISABLED' | 'LOCKED';
  email: string;
  fullName: string;
  sessionId: string;
  /** Epoch ms of the most recent full authentication, for step-up decisions. */
  authenticatedAt: number;
  webauthnVerifiedAt: number | null;
  trustedDeviceId: string | null;
}

/** Hono context variables available to every handler. */
export interface AppVariables {
  correlationId: string;
  actor?: AuthenticatedActor;
  /** Set by the request logger; used by the audit writer. */
  securityContext: {
    ip: string | null;
    userAgent: string | null;
    country: string | null;
    deviceFingerprint: string | null;
  };
}

export type AppContext = { Bindings: Env; Variables: AppVariables };
