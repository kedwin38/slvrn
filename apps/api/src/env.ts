/**
 * Cloudflare Worker bindings and runtime environment.
 *
 * Every secret in this interface is a **binding**, not a value read from a database row or
 * an environment file committed to the repository. Wrangler injects them from the
 * Cloudflare Secrets Store at request time; they are never logged, never returned by an
 * API, and never written to an audit detail payload (NFR-SEC-003).
 */

import type { AuthorityLevel } from '@solvaren/core';

export interface Env {
  // ---- Data ---------------------------------------------------------------
  /** Hyperdrive binding to the managed PostgreSQL system of record. */
  HYPERDRIVE: Hyperdrive;

  // ---- Asynchronous processing (§16) --------------------------------------
  /** Payment executor queue — one message per authorized instruction. */
  PAYMENT_QUEUE: Queue<PaymentQueueMessage>;
  /** Provider callback processing, kept off the ingress request path. */
  CALLBACK_QUEUE: Queue<CallbackQueueMessage>;
  /** Reconciliation and Transaction Status sweeps. */
  RECONCILIATION_QUEUE: Queue<ReconciliationQueueMessage>;
  /** Backup snapshot and retention jobs. */
  BACKUP_QUEUE: Queue<BackupQueueMessage>;

  // ---- Object storage -----------------------------------------------------
  /** R2 bucket for backups, generated exports and permitted artefacts. */
  ARTIFACTS: R2Bucket;

  // ---- Durable coordination ----------------------------------------------
  /** Per-organisation submission rate limiting, aligned to the Daraja contract. */
  RATE_LIMITER: DurableObjectNamespace;

  // ---- Secrets (Cloudflare Secrets Store bindings) ------------------------
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
