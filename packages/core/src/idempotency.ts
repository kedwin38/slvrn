/**
 * Idempotency and duplicate-execution control (spec §9.3, NFR-REL-003).
 *
 * The threat is specific: a queue redelivery, a Worker retry, or an operator double-click
 * causes the same salary to be paid twice. Daraja's own `OriginatorConversationID`
 * uniqueness check is a *backstop*, not the primary control — by the time Safaricom
 * returns `500.002.1001` we have already lost track of whether the first attempt paid out.
 *
 * The primary control is a database-unique idempotency key derived from the instruction
 * itself, claimed *before* the provider call and never released. A retry of the same
 * instruction finds the existing claim and returns the recorded outcome rather than
 * submitting again.
 */

import { sha256Hex } from './manifest.js';

export interface InstructionFingerprintInput {
  organizationId: string;
  batchId: string;
  instructionId: string;
  /** The batch version at authorization time — an edit changes the fingerprint. */
  batchVersion: number;
  msisdn: string;
  amountCents: number;
  /** Manifest hash that was authorized; binds execution to the signed intent. */
  manifestHash: string;
  /**
   * Which deliberate re-attempt this is, for an operator retrying a FAILED payment.
   *
   * Omitted (or 0) for the original execution, and the payload is then byte-identical to
   * what it has always been — existing claims keep their fingerprints.
   *
   * A retry MUST carry a distinct fingerprint. Reusing the original would collide with the
   * spent claim, the executor would read it as a replay of a payment already sent, and the
   * retry would silently do nothing — the worst outcome, because the operator would believe
   * the payment had been re-sent.
   */
  retrySequence?: number;
}

/**
 * Deterministic fingerprint of "this exact payment, authorized under this exact manifest".
 *
 * Two submissions with the same fingerprint are the same payment and must never both
 * reach Daraja. Two submissions that differ in any field are different payments and are
 * both allowed — which is why a deliberate re-payment after a failure carries a new
 * instruction id rather than reusing the old one.
 */
export async function instructionFingerprint(input: InstructionFingerprintInput): Promise<string> {
  const payload = [
    'SLV-IDEM-1',
    input.organizationId,
    input.batchId,
    String(input.batchVersion),
    input.instructionId,
    input.msisdn,
    String(input.amountCents),
    input.manifestHash,
    // Appended only for a retry, so the original execution's fingerprint is unchanged.
    ...(input.retrySequence ? [`retry:${input.retrySequence}`] : []),
  ].join('\x1f');
  return sha256Hex(payload);
}

export type IdempotencyState = 'CLAIMED' | 'SUBMITTED' | 'SETTLED' | 'ABANDONED';

export interface IdempotencyRecord {
  fingerprint: string;
  state: IdempotencyState;
  /** The provider correlation id used for the claimed attempt. */
  originatorConversationId: string | null;
  transactionId: string | null;
  claimedAt: number;
  updatedAt: number;
}

export type ClaimDecision =
  | { action: 'SUBMIT'; reason: string }
  | { action: 'SKIP_ALREADY_SETTLED'; reason: string }
  | { action: 'RECONCILE_FIRST'; reason: string };

/**
 * Decide what to do when an execution message arrives for an instruction that already has
 * an idempotency record.
 *
 * The `SUBMITTED` case is the important one: we told Daraja to pay and then the worker
 * died. We do **not** know whether money moved. Resubmitting risks a double payment;
 * ignoring risks an unpaid employee. The only correct action is to query the Transaction
 * Status API first — spec §9.3, "Ambiguous provider outcomes must enter a controlled
 * reconciliation state rather than being blindly retried."
 */
export function decideOnExistingClaim(record: IdempotencyRecord | null): ClaimDecision {
  if (!record) {
    return { action: 'SUBMIT', reason: 'No prior attempt exists for this instruction' };
  }
  switch (record.state) {
    case 'CLAIMED':
      // Claimed but never submitted: the worker died between claiming and the HTTP call,
      // so no request reached Daraja and it is safe to proceed under the same claim.
      return { action: 'SUBMIT', reason: 'A claim exists but no request was ever sent to M-PESA' };
    case 'SUBMITTED':
      return {
        action: 'RECONCILE_FIRST',
        reason:
          'A request was already sent to M-PESA for this instruction and the outcome is unknown. Querying transaction status before any further action.',
      };
    case 'SETTLED':
      return {
        action: 'SKIP_ALREADY_SETTLED',
        reason: 'This instruction already has a settled provider outcome',
      };
    case 'ABANDONED':
      return {
        action: 'SUBMIT',
        reason: 'The previous attempt was abandoned before reaching M-PESA',
      };
  }
}

/**
 * Validate a client-supplied `Idempotency-Key` header on a mutating API request.
 * Keys are opaque to us but must be long enough to be unguessable and short enough to index.
 */
export function isValidIdempotencyKey(key: string | null | undefined): key is string {
  if (!key) return false;
  const k = key.trim();
  return k.length >= 16 && k.length <= 255 && /^[A-Za-z0-9._:-]+$/.test(k);
}
