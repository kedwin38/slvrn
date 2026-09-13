/**
 * Append-only, tamper-evident audit log (spec §14, Zone 7).
 *
 * Tamper-evidence is achieved with a per-organization hash chain: each event's digest
 * covers its own content *and* the digest of the previous event. Deleting or altering an
 * event in the middle of the chain breaks every subsequent link, and `verifyChain` finds
 * the exact index where the break occurs.
 *
 * This does not make deletion impossible — nothing in software does, given database
 * superuser access — it makes deletion *detectable*, which is the property an auditor
 * actually needs. The database layer additionally blocks UPDATE and DELETE on the audit
 * table via triggers (see `db/migrations/0003_immutability.sql`), so breaking the chain
 * requires disabling those triggers, which is itself a logged administrative act.
 */

import { sha256Hex } from './manifest.js';

export const AUDIT_CHAIN_VERSION = 'SLV-AUDIT-1' as const;
/** Digest of the notional event before the first one in an organization's chain. */
export const GENESIS_HASH = '0'.repeat(64);

export type AuditEventClass =
  | 'IDENTITY'
  | 'AUTHORITY'
  | 'PAYMENT'
  | 'INTEGRATION'
  | 'DATA_EXPORT'
  | 'SECURITY'
  | 'BACKUP'
  | 'ADMINISTRATION';

export type AuditOutcome = 'SUCCESS' | 'DENIED' | 'FAILURE';

export interface AuditEventInput {
  eventId: string;
  organizationId: string;
  /** User id, or a system actor like `system:reconciliation-worker`. */
  actorId: string;
  actorLevel: string | null;
  eventClass: AuditEventClass;
  /** Dotted action name, e.g. `payment.release` or `daraja.credential.rotate`. */
  action: string;
  objectType: string;
  objectId: string | null;
  outcome: AuditOutcome;
  /** ISO-8601 UTC. Supplied by the caller so the value hashed is the value stored. */
  occurredAt: string;
  previousState: unknown;
  newState: unknown;
  correlationId: string;
  /** IP, user agent, device id, session id — never credential material. */
  securityContext: Record<string, unknown>;
  /** Free-form detail. MUST NOT contain secrets; see `redactForAudit`. */
  detail: Record<string, unknown>;
}

export interface AuditEvent extends AuditEventInput {
  previousHash: string;
  eventHash: string;
  sequence: number;
}

const FS = '\x1f';

/**
 * Canonical serialization for hashing. `JSON.stringify` is not used directly on the
 * variable-shaped fields because its key order follows insertion order, which is not
 * stable across code paths — `stableStringify` sorts keys recursively.
 */
export function stableStringify(value: unknown): string {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'number') return Number.isFinite(value) ? String(value) : 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`).join(',')}}`;
  }
  return 'null';
}

export function auditCanonicalForm(event: AuditEventInput, previousHash: string, sequence: number): string {
  return [
    AUDIT_CHAIN_VERSION,
    String(sequence),
    previousHash,
    event.eventId,
    event.organizationId,
    event.actorId,
    event.actorLevel ?? '',
    event.eventClass,
    event.action,
    event.objectType,
    event.objectId ?? '',
    event.outcome,
    event.occurredAt,
    event.correlationId,
    stableStringify(event.previousState),
    stableStringify(event.newState),
    stableStringify(event.securityContext),
    stableStringify(event.detail),
  ].join(FS);
}

/** Compute the chained digest for the next event in an organization's log. */
export async function sealAuditEvent(
  event: AuditEventInput,
  previousHash: string,
  sequence: number,
): Promise<AuditEvent> {
  const eventHash = await sha256Hex(auditCanonicalForm(event, previousHash, sequence));
  return { ...event, previousHash, eventHash, sequence };
}

export interface ChainVerification {
  valid: boolean;
  /** Index within the supplied slice where verification failed. */
  brokenAtIndex: number | null;
  brokenEventId: string | null;
  reason: string | null;
  eventsVerified: number;
}

/**
 * Verify a contiguous slice of the chain. `expectedStartHash` is the digest of the event
 * immediately preceding the slice (or GENESIS_HASH when verifying from the beginning).
 */
export async function verifyChain(
  events: readonly AuditEvent[],
  expectedStartHash: string = GENESIS_HASH,
): Promise<ChainVerification> {
  let previousHash = expectedStartHash;
  for (let i = 0; i < events.length; i++) {
    const event = events[i]!;
    if (event.previousHash !== previousHash) {
      return {
        valid: false,
        brokenAtIndex: i,
        brokenEventId: event.eventId,
        reason: `Event ${event.eventId} references previous hash ${event.previousHash.slice(0, 12)}… but the preceding event hashes to ${previousHash.slice(0, 12)}…. An event has been removed, reordered or altered.`,
        eventsVerified: i,
      };
    }
    const recomputed = await sha256Hex(auditCanonicalForm(event, event.previousHash, event.sequence));
    if (recomputed !== event.eventHash) {
      return {
        valid: false,
        brokenAtIndex: i,
        brokenEventId: event.eventId,
        reason: `Event ${event.eventId} does not hash to its recorded digest. Its content has been altered after it was written.`,
        eventsVerified: i,
      };
    }
    previousHash = event.eventHash;
  }
  return { valid: true, brokenAtIndex: null, brokenEventId: null, reason: null, eventsVerified: events.length };
}

/**
 * Keys whose values must never reach the audit log, an exception message, an AI prompt or
 * a log line. Matching is on the *key*, case-insensitively, at any depth.
 * NFR-SEC-003: "Sensitive secrets are never written to plaintext logs…".
 */
const SECRET_KEY_PATTERN =
  /(password|passphrase|secret|credential|token|authorization|api[_-]?key|consumer[_-]?key|consumer[_-]?secret|private[_-]?key|initiator[_-]?password|security[_-]?credential|access[_-]?key|pin|cookie|session[_-]?id|recovery[_-]?code)/i;

export const REDACTED = '[REDACTED]' as const;

/**
 * Recursively redact secret-shaped fields. Applied to every audit `detail` payload and to
 * every error detail leaving the API, so that a future contributor logging a whole request
 * body does not create a credential leak.
 */
export function redactForAudit(value: unknown, depth = 0): unknown {
  if (depth > 12) return '[TRUNCATED]';
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map((v) => redactForAudit(v, depth + 1));

  const out: Record<string, unknown> = {};
  for (const [key, v] of Object.entries(value as Record<string, unknown>)) {
    if (SECRET_KEY_PATTERN.test(key)) {
      out[key] = REDACTED;
    } else {
      out[key] = redactForAudit(v, depth + 1);
    }
  }
  return out;
}

/** True when a string looks like it carries credential material. Used in log guards/tests. */
export function looksLikeSecret(text: string): boolean {
  if (/^Bearer\s+[A-Za-z0-9._-]{20,}$/i.test(text.trim())) return true;
  if (/^Basic\s+[A-Za-z0-9+/=]{20,}$/i.test(text.trim())) return true;
  // Long unbroken base64 runs are how the Daraja SecurityCredential travels.
  if (/[A-Za-z0-9+/]{120,}={0,2}/.test(text)) return true;
  return false;
}
