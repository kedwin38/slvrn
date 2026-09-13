/**
 * Audit event writer.
 *
 * The writer computes the chained digest in the Worker and lets PostgreSQL verify it on
 * insert (`seal_audit_event`), so the chain is validated on both sides of the connection.
 * If the two ever disagree, the insert fails and the operation it was recording fails with
 * it — an action SOLVAREN cannot record is an action SOLVAREN does not take.
 */

import {
  sealAuditEvent,
  redactForAudit,
  GENESIS_HASH,
  reference,
  type AuditEventInput,
  type AuditEventClass,
  type AuditOutcome,
} from '@solvaren/core';
import type { Sql } from './client.js';

export interface AuditWriteInput {
  organizationId: string;
  actorId: string;
  actorLevel: string | null;
  eventClass: AuditEventClass;
  action: string;
  objectType: string;
  objectId: string | null;
  outcome: AuditOutcome;
  previousState?: unknown;
  newState?: unknown;
  correlationId: string;
  securityContext?: Record<string, unknown>;
  detail?: Record<string, unknown>;
  occurredAt?: Date;
}

/**
 * Append one audit event.
 *
 * MUST be called inside the same transaction as the state change it records. That is the
 * whole point: a released payment and its audit event commit together or not at all, so
 * there is no window in which money moved without a record.
 */
export async function writeAuditEvent(tx: Sql, input: AuditWriteInput): Promise<string> {
  const tail = await tx<{ sequence: string; event_hash: string }[]>`
    SELECT sequence, event_hash
      FROM audit_events
     WHERE organization_id = ${input.organizationId}
     ORDER BY sequence DESC
     LIMIT 1
  `;

  const previousHash = tail[0]?.event_hash ?? GENESIS_HASH;
  const sequence = tail[0] ? Number(tail[0].sequence) + 1 : 1;
  const eventReference = reference('EVT');

  const event: AuditEventInput = {
    eventId: eventReference,
    organizationId: input.organizationId,
    actorId: input.actorId,
    actorLevel: input.actorLevel,
    eventClass: input.eventClass,
    action: input.action,
    objectType: input.objectType,
    objectId: input.objectId,
    outcome: input.outcome,
    occurredAt: (input.occurredAt ?? new Date()).toISOString(),
    // Redaction happens here rather than at the call sites, so a future contributor who
    // passes a whole request body into `detail` cannot create a credential leak.
    previousState: redactForAudit(input.previousState ?? null),
    newState: redactForAudit(input.newState ?? null),
    correlationId: input.correlationId,
    securityContext: redactForAudit(input.securityContext ?? {}) as Record<string, unknown>,
    detail: redactForAudit(input.detail ?? {}) as Record<string, unknown>,
  };

  const sealed = await sealAuditEvent(event, previousHash, sequence);

  await tx`
    INSERT INTO audit_events (
      organization_id, sequence, event_reference, actor_id, actor_level, event_class,
      action, object_type, object_id, outcome, previous_state, new_state,
      security_context, detail, correlation_id, occurred_at, previous_hash, event_hash
    ) VALUES (
      ${sealed.organizationId}, ${sealed.sequence}, ${sealed.eventId}, ${sealed.actorId},
      ${sealed.actorLevel}, ${sealed.eventClass}, ${sealed.action}, ${sealed.objectType},
      ${sealed.objectId}, ${sealed.outcome}, ${tx.json(sealed.previousState as never)},
      ${tx.json(sealed.newState as never)}, ${tx.json(sealed.securityContext as never)},
      ${tx.json(sealed.detail as never)}, ${sealed.correlationId}, ${sealed.occurredAt},
      ${sealed.previousHash}, ${sealed.eventHash}
    )
  `;

  return eventReference;
}

/**
 * Record a denied privileged attempt.
 *
 * Denials are logged as deliberately as successes: a pattern of refused L1 attempts on the
 * release endpoint is exactly the signal a security team needs, and §14 lists "policy
 * denial" as an auditable security event.
 */
export async function writeDenial(
  tx: Sql,
  input: Omit<AuditWriteInput, 'outcome'> & { reason: string },
): Promise<string> {
  return writeAuditEvent(tx, {
    ...input,
    outcome: 'DENIED',
    detail: { ...(input.detail ?? {}), denialReason: input.reason },
  });
}
