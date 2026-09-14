/**
 * Transaction execution state machine (spec §6.1, §9.2).
 *
 *   PENDING → SUBMITTED → AWAITING_CALLBACK → PROCESSING → SUCCESS
 *                                       ↘ FAILED   (failure code + reason captured)
 *                                       ↘ TIMEOUT  → RECONCILING → terminal
 *
 * Two invariants are enforced here and nowhere else:
 *
 *  1. SUCCESS and FAILED are terminal for the *provider outcome*. Once Daraja has told us
 *     a transaction settled, no later message, retry or operator action rewrites it. A
 *     reconciliation sweep that disagrees with a settled state raises a discrepancy case
 *     instead of mutating the ledger (§4.3 "force status to SUCCESS" is impossible).
 *  2. A transition into SUCCESS requires a provider receipt. You cannot reach SUCCESS by
 *     asserting it; you reach it by presenting evidence.
 */

import { stateError } from './errors.js';

export const TXN_STATES = [
  'PENDING',
  'SUBMITTED',
  'AWAITING_CALLBACK',
  'PROCESSING',
  'RECONCILING',
  'SUCCESS',
  'FAILED',
  'TIMEOUT',
  'CANCELLED',
] as const;

export type TxnState = (typeof TXN_STATES)[number];

/** Statuses shown as "still moving" in the explorer; they drive the reconciliation sweep. */
export const IN_FLIGHT_STATES: readonly TxnState[] = [
  'PENDING',
  'SUBMITTED',
  'AWAITING_CALLBACK',
  'PROCESSING',
  'RECONCILING',
  'TIMEOUT',
];

/** Statuses eligible for the failed-transactions export by default (§6.4). */
export const FAILED_EXPORT_STATES: readonly TxnState[] = ['FAILED'];
/** Optional additions to that export, per the "include timeouts" toggle. */
export const AMBIGUOUS_EXPORT_STATES: readonly TxnState[] = [
  'TIMEOUT',
  'AWAITING_CALLBACK',
  'RECONCILING',
];

/** Outcome is settled and immutable. */
export const SETTLED_STATES: readonly TxnState[] = ['SUCCESS', 'FAILED', 'CANCELLED'];

export type TxnStatusSource =
  | 'SYNC_ACK' // Daraja's synchronous accept/reject of the request itself
  | 'CALLBACK' // ResultURL delivery
  | 'QUEUE_TIMEOUT' // QueueTimeOutURL delivery
  | 'STATUS_QUERY' // Transaction Status API (scheduled sweep or on-demand refresh)
  | 'SYSTEM'; // internal transition (enqueue, submit, cancel-before-submit)

const ALLOWED: Record<TxnState, readonly TxnState[]> = {
  PENDING: ['SUBMITTED', 'FAILED', 'CANCELLED'],
  SUBMITTED: ['AWAITING_CALLBACK', 'PROCESSING', 'SUCCESS', 'FAILED', 'TIMEOUT'],
  AWAITING_CALLBACK: ['PROCESSING', 'SUCCESS', 'FAILED', 'TIMEOUT', 'RECONCILING'],
  PROCESSING: ['SUCCESS', 'FAILED', 'TIMEOUT', 'RECONCILING'],
  RECONCILING: ['SUCCESS', 'FAILED', 'TIMEOUT'],
  TIMEOUT: ['RECONCILING', 'SUCCESS', 'FAILED'],
  SUCCESS: [],
  FAILED: [],
  CANCELLED: [],
};

export interface TxnTransitionInput {
  from: TxnState;
  to: TxnState;
  source: TxnStatusSource;
  /** M-PESA receipt (`TransactionID`, e.g. `SG632NMUAB`) — required to reach SUCCESS. */
  providerReceipt?: string | null;
  /** Provider `ResultCode` — required to reach FAILED. */
  failureCode?: string | null;
}

export interface TxnTransitionResult {
  to: TxnState;
  /** True when the transition should also open a reconciliation case. */
  opensReconciliation: boolean;
}

/**
 * Validate a transaction state transition.
 *
 * @throws SolvarenError when the edge does not exist, when a settled transaction is being
 *   rewritten, or when terminal evidence is missing.
 */
export function assertTxnTransition(input: TxnTransitionInput): TxnTransitionResult {
  const { from, to, source } = input;

  if (from === to) {
    // Idempotent no-op: a duplicate callback re-delivering the same outcome. The caller
    // records the duplicate as audit evidence and leaves the ledger untouched.
    return { to, opensReconciliation: false };
  }

  if (SETTLED_STATES.includes(from)) {
    throw stateError(
      'TXN_ALREADY_SETTLED',
      `Transaction already settled as ${from}; a ${to} update from ${source} cannot rewrite it`,
      { from, to, source },
    );
  }

  if (!ALLOWED[from].includes(to)) {
    throw stateError('TXN_TRANSITION_INVALID', `Transaction cannot move from ${from} to ${to}`, {
      from,
      to,
      allowed: ALLOWED[from],
    });
  }

  if (to === 'SUCCESS') {
    // Evidence, not assertion. §23: "Attempt to forge a SUCCESS status … confirm the
    // application cannot perform it."
    if (source === 'SYSTEM') {
      throw stateError(
        'TXN_SUCCESS_REQUIRES_PROVIDER_EVIDENCE',
        'A transaction may only be marked SUCCESS from a provider callback or status query',
        { source },
      );
    }
    if (!input.providerReceipt || input.providerReceipt.trim() === '') {
      throw stateError(
        'TXN_SUCCESS_REQUIRES_RECEIPT',
        'A transaction may only be marked SUCCESS when a provider receipt number is present',
        { source },
      );
    }
  }

  if (to === 'FAILED' && (!input.failureCode || input.failureCode.trim() === '')) {
    // §6.2: failures are never blank and never just "Error".
    throw stateError(
      'TXN_FAILURE_REQUIRES_CODE',
      'A transaction may only be marked FAILED together with a provider failure code',
      { source },
    );
  }

  return { to, opensReconciliation: to === 'TIMEOUT' || to === 'RECONCILING' };
}

export function isSettled(state: TxnState): boolean {
  return SETTLED_STATES.includes(state);
}

export function isInFlight(state: TxnState): boolean {
  return IN_FLIGHT_STATES.includes(state);
}

/** Colour semantics for the explorer's status chips (§6.3). */
export function statusTone(state: TxnState): 'success' | 'danger' | 'warning' | 'info' | 'neutral' {
  switch (state) {
    case 'SUCCESS':
      return 'success';
    case 'FAILED':
      return 'danger';
    case 'TIMEOUT':
      return 'warning';
    case 'RECONCILING':
    case 'AWAITING_CALLBACK':
      return 'info';
    case 'CANCELLED':
      return 'neutral';
    default:
      return 'info';
  }
}

/**
 * Whether a failed transaction may be retried as a *new* payment instruction.
 * Never a blind resend of the same one: §9.3 forbids retrying into an ambiguous outcome,
 * and codes like 2001 (bad initiator credentials) will fail identically until a human acts.
 */
export function isRetryEligible(state: TxnState, failureCode: string | null | undefined): boolean {
  if (state !== 'FAILED') return false;
  if (!failureCode) return false;
  const permanent = new Set([
    '2001', // initiator information invalid — credential problem, not transient
    '2040', // recipient is not a registered M-PESA customer
    '8006', // security credential locked
    '21', // initiator not allowed to perform this operation
    '2028', // not permitted per product assignment
    'SFC_IC0003', // operator does not exist (bad MSISDN)
    '2', // below minimum amount
    '3', // above maximum amount
    '4', // would exceed customer daily limit
    '8', // would exceed customer maximum balance
  ]);
  return !permanent.has(failureCode.trim());
}
