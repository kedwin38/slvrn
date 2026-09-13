/**
 * Daraja failure-reason dictionary (spec §6.2, TRK-002, TRK-009).
 *
 * Every code Safaricom can hand us is mapped to an explanation an operations officer can
 * act on, plus an `operatorAction` telling them what to actually do. The three rules:
 *
 *   1. Never blank. An unmapped code falls through to the provider's own description.
 *   2. Never just "Error". If we have nothing at all, we say so explicitly and show the code.
 *   3. Versioned and data-driven. This table is seeded into `failure_reason_map` so new
 *      provider codes are mappable by an administrator without a code deploy (TRK-009);
 *      the compiled table remains the fallback when the database has no row.
 *
 * Sources: Daraja B2C result codes, Account Balance numeric core errors, and the
 * platform-wide gateway error table.
 */

export const FAILURE_DICTIONARY_VERSION = '2026.09.13' as const;

export type FailureClass =
  | 'FUNDING' // the organization must move or add money
  | 'RECIPIENT' // something about the payee is wrong
  | 'LIMIT' // amount or velocity limit
  | 'CREDENTIAL' // initiator/API credential problem — L3 action
  | 'PERMISSION' // portal role/product assignment problem — L3 action
  | 'PROVIDER' // Safaricom-side fault or throttling
  | 'REQUEST' // our request was malformed — engineering fault
  | 'AMBIGUOUS' // no outcome known; reconciliation owns it
  | 'UNKNOWN';

export interface FailureReason {
  code: string;
  /** Human-readable explanation shown in the explorer, detail page and CSV export. */
  reason: string;
  class: FailureClass;
  /** Concrete next step for the operator. */
  operatorAction: string;
  /** Whether resubmitting the same instruction unchanged could plausibly succeed. */
  transient: boolean;
}

const D = (
  code: string,
  reason: string,
  cls: FailureClass,
  operatorAction: string,
  transient: boolean,
): FailureReason => ({ code, reason, class: cls, operatorAction, transient });

/** Canonical table. Keys are the raw provider codes exactly as Daraja emits them. */
export const FAILURE_REASONS: Readonly<Record<string, FailureReason>> = Object.freeze({
  // ---- B2C ResultCodes ----------------------------------------------------
  '0': D('0', 'Processed successfully', 'UNKNOWN', 'No action required', false),
  '1': D(
    '1',
    "Insufficient balance in the organization's Utility account",
    'FUNDING',
    'Top up the B2C shortcode, or move funds from the Working (MMF) account to Utility on the M-PESA org portal — B2C debits Utility, not Working',
    true,
  ),
  '2': D(
    '2',
    'Amount is below the minimum permitted for this payment (M-PESA minimum is KES 10)',
    'LIMIT',
    'Correct the instruction amount and resubmit as a new instruction',
    false,
  ),
  '3': D(
    '3',
    'Amount exceeds the maximum permitted per transaction (M-PESA B2C maximum is KES 250,000)',
    'LIMIT',
    'Split the payment across multiple instructions within the per-transaction limit',
    false,
  ),
  '4': D(
    '4',
    "Payment would exceed the recipient's daily M-PESA transfer limit (KES 500,000)",
    'LIMIT',
    'Pay the balance on a later date, or ask the recipient to confirm their limit with Safaricom',
    true,
  ),
  '8': D(
    '8',
    "Payment would exceed the recipient's maximum M-PESA wallet balance (KES 500,000)",
    'LIMIT',
    'Ask the recipient to withdraw funds before the payment is retried',
    true,
  ),
  '11': D(
    '11',
    'The organization B2C account is not in an active state',
    'PROVIDER',
    'Contact Safaricom business support to reactivate the B2C shortcode; hold further releases until resolved',
    false,
  ),
  '15': D(
    '15',
    'Duplicate request detected by M-PESA — this OriginatorConversationID was already seen',
    'AMBIGUOUS',
    'Do not resend. Run a status query on the original OriginatorConversationID to establish the true outcome',
    false,
  ),
  '17': D('17', 'M-PESA internal failure', 'PROVIDER', 'Reconcile before any retry; escalate to Safaricom if it repeats', true),
  '18': D(
    '18',
    'Initiator credential check failed (wrong password or an encryption/decryption problem)',
    'CREDENTIAL',
    'Level 3: regenerate the SecurityCredential against the current M-PESA public certificate and rotate the stored credential',
    false,
  ),
  '19': D('19', 'Message sequencing failure at M-PESA', 'PROVIDER', 'Reconcile the transaction; escalate if it repeats', true),
  '20': D(
    '20',
    'Unresolved initiator — the API username was not found on the M-PESA portal',
    'CREDENTIAL',
    'Level 3: verify the InitiatorName matches an active API operator on the shortcode',
    false,
  ),
  '21': D(
    '21',
    'The initiator is not permitted to perform this operation (missing the ORG B2C API Initiator role)',
    'PERMISSION',
    'Level 3: have the Business Administrator assign the "ORG B2C API Initiator" role to the API user',
    false,
  ),
  '22': D(
    '22',
    'The initiator is not permitted to pay this receiver, or the initiator is not active',
    'PERMISSION',
    'Level 3: check the API operator is active and permitted for the receiving party',
    false,
  ),
  '24': D('24', 'M-PESA rejected the request for missing mandatory fields', 'REQUEST', 'Raise an engineering incident — the submitted payload is incomplete', false),
  '25': D('25', 'M-PESA could not convert one of the request parameters', 'REQUEST', 'Raise an engineering incident — a field is the wrong type', false),
  '26': D(
    '26',
    'M-PESA is applying traffic blocking (system too busy)',
    'PROVIDER',
    'The reconciliation sweep will re-check; throughput is throttled automatically',
    true,
  ),
  '29': D('29', 'M-PESA rejected the command as invalid', 'REQUEST', 'Raise an engineering incident — the CommandID is not valid for this shortcode', false),
  '2001': D(
    '2001',
    'The initiator information is invalid (username, password, encryption or certificate)',
    'CREDENTIAL',
    'Level 3: test the Daraja connection, then rotate the initiator credential. Payments will keep failing identically until this is fixed',
    false,
  ),
  '2006': D(
    '2006',
    'Declined by an account rule — the B2C account is not active',
    'PROVIDER',
    'Contact Safaricom business support; hold releases until the account is active',
    false,
  ),
  '2028': D(
    '2028',
    'The paying shortcode is not permitted to perform B2C under its product assignment',
    'PERMISSION',
    'Level 3: confirm the shortcode is a Bulk Disbursement / one-account shortcode with B2C enabled',
    false,
  ),
  '2040': D(
    '2040',
    'The recipient is not a registered M-PESA customer',
    'RECIPIENT',
    'Verify the phone number on the recipient record. B2C CommandIDs only pay registered customers',
    false,
  ),
  '8006': D(
    '8006',
    'The API security credential is locked',
    'CREDENTIAL',
    'Level 3: ask the Business Administrator to unlock the API user password on the M-PESA org portal, then rotate the credential',
    false,
  ),
  SFC_IC0003: D(
    'SFC_IC0003',
    'The operator does not exist — the phone number is invalid or unassigned',
    'RECIPIENT',
    'Correct the recipient MSISDN on the master record and issue a new instruction',
    false,
  ),

  // ---- Gateway / platform error codes ------------------------------------
  '400.002.02': D('400.002.02', 'Daraja rejected a field in the request as invalid', 'REQUEST', 'Raise an engineering incident with the correlation id', false),
  '400.002.05': D('400.002.05', 'Daraja rejected the request payload as malformed', 'REQUEST', 'Raise an engineering incident with the correlation id', false),
  '400.003.01': D('400.003.01', 'The Daraja access token was invalid or expired', 'CREDENTIAL', 'The token cache refreshes automatically; if it persists, Level 3 should re-test the Daraja connection', true),
  '400.003.02': D('400.003.02', 'Daraja rejected the request as incomplete', 'REQUEST', 'Raise an engineering incident with the correlation id', false),
  '401.002.01': D('401.002.01', 'The Daraja access token was rejected', 'CREDENTIAL', 'Level 3: verify the consumer key and secret, then re-test the connection', true),
  '404.001.03': D('404.001.03', 'The Daraja access token was rejected as invalid', 'CREDENTIAL', 'Level 3: verify the consumer key and secret, then re-test the connection', true),
  '404.001.04': D('404.001.04', 'Daraja rejected the authentication header or HTTP method', 'REQUEST', 'Raise an engineering incident with the correlation id', false),
  '500.001.1001': D('500.001.1001', 'Daraja internal server error while handling the request', 'PROVIDER', 'Reconcile before any retry — the payment may still have been processed', true),
  '500.002.1001': D(
    '500.002.1001',
    'Duplicate OriginatorConversationID — Daraja has already seen this request identifier',
    'AMBIGUOUS',
    'Do not resend. Query the transaction status for the original identifier to establish whether money moved',
    false,
  ),
  '500.003.02': D('500.003.02', 'Spike arrest violation — request rate exceeded the permitted burst', 'PROVIDER', 'Throughput is throttled automatically; the sweep will re-check', true),
  '500.003.03': D('500.003.03', 'Quota violation — the request exceeded the permitted TPS', 'PROVIDER', 'Throughput is throttled automatically; the sweep will re-check', true),
  '500.003.1001': D('500.003.1001', 'Daraja internal server error', 'PROVIDER', 'Reconcile before any retry', true),
  '100000001': D('100000001', 'M-PESA reports the system is overloaded', 'PROVIDER', 'The reconciliation sweep will re-check', true),
  '100000002': D('100000002', 'M-PESA throttling error', 'PROVIDER', 'The reconciliation sweep will re-check', true),
  '100000004': D('100000004', 'M-PESA internal server error', 'PROVIDER', 'Reconcile before any retry', true),
  '100000010': D('100000010', 'Insufficient permissions on the M-PESA account', 'PERMISSION', 'Level 3: review the API operator roles on the org portal', false),
  '100000011': D('100000011', 'M-PESA request rate limit exceeded', 'PROVIDER', 'Throughput is throttled automatically', true),
  '00.002.1001': D('00.002.1001', 'M-PESA is under maintenance', 'PROVIDER', 'Releases are paused automatically; retry after the maintenance window', true),

  // ---- SOLVAREN-internal outcomes ----------------------------------------
  SLV_TIMEOUT: D(
    'SLV_TIMEOUT',
    'No result was received from M-PESA within the expected window',
    'AMBIGUOUS',
    'Reconciliation is querying the Transaction Status API. Do not resubmit until the outcome is known',
    false,
  ),
  SLV_QUEUE_TIMEOUT: D(
    'SLV_QUEUE_TIMEOUT',
    'M-PESA reported the request timed out while queued for processing',
    'AMBIGUOUS',
    'Reconciliation is querying the Transaction Status API. Do not resubmit until the outcome is known',
    false,
  ),
  SLV_NO_CALLBACK: D(
    'SLV_NO_CALLBACK',
    'The request was accepted by M-PESA but no result callback has arrived',
    'AMBIGUOUS',
    'Reconciliation is querying the Transaction Status API. Do not resubmit until the outcome is known',
    false,
  ),
  SLV_SUBMIT_FAILED: D(
    'SLV_SUBMIT_FAILED',
    'SOLVAREN could not deliver the request to M-PESA',
    'PROVIDER',
    'The instruction was never accepted, so no money moved. It can be safely reissued once connectivity is restored',
    true,
  ),
  SLV_INTEGRATION_DISABLED: D(
    'SLV_INTEGRATION_DISABLED',
    'The Daraja integration was disabled before this instruction could be submitted',
    'CREDENTIAL',
    'Level 3: re-enable the integration in Settings → Daraja, then reissue the instruction',
    false,
  ),
});

export interface ResolvedFailure {
  failureCode: string;
  failureReason: string;
  failureClass: FailureClass;
  operatorAction: string;
  transient: boolean;
  /** True when the explanation came from the dictionary rather than a provider fallback. */
  mapped: boolean;
  dictionaryVersion: string;
}

/** Database-backed overrides, so administrators can map new codes without a deploy. */
export type FailureOverrides = Readonly<Record<string, Pick<FailureReason, 'reason' | 'class' | 'operatorAction' | 'transient'>>>;

/**
 * Resolve a provider code to an explanation.
 *
 * Precedence: administrator override → compiled dictionary → provider's own description →
 * an explicit "unmapped" sentence that still shows the raw code. It never returns blank
 * and never returns the word "Error" alone (TRK-002).
 */
export function resolveFailure(
  rawCode: string | null | undefined,
  providerDescription?: string | null,
  overrides: FailureOverrides = {},
): ResolvedFailure {
  const code = (rawCode ?? '').toString().trim();
  const description = (providerDescription ?? '').toString().trim();

  if (code === '') {
    return {
      failureCode: 'SLV_UNSPECIFIED',
      failureReason:
        description !== ''
          ? `M-PESA reported: ${description}`
          : 'M-PESA returned a failure without a result code. Reconciliation will determine the outcome.',
      failureClass: 'UNKNOWN',
      operatorAction: 'Open the reconciliation case for this transaction to establish the outcome',
      transient: false,
      mapped: false,
      dictionaryVersion: FAILURE_DICTIONARY_VERSION,
    };
  }

  const override = overrides[code];
  if (override) {
    return {
      failureCode: code,
      failureReason: override.reason,
      failureClass: override.class,
      operatorAction: override.operatorAction,
      transient: override.transient,
      mapped: true,
      dictionaryVersion: `${FAILURE_DICTIONARY_VERSION}+override`,
    };
  }

  const known = FAILURE_REASONS[code];
  if (known) {
    return {
      failureCode: code,
      failureReason: known.reason,
      failureClass: known.class,
      operatorAction: known.operatorAction,
      transient: known.transient,
      mapped: true,
      dictionaryVersion: FAILURE_DICTIONARY_VERSION,
    };
  }

  // Unmapped: show the provider's own words verbatim rather than inventing an explanation.
  return {
    failureCode: code,
    failureReason:
      description !== ''
        ? `M-PESA result code ${code}: ${description}`
        : `M-PESA result code ${code} — this code is not yet in the SOLVAREN failure dictionary. Contact Safaricom API support with the conversation identifiers on this transaction.`,
    failureClass: 'UNKNOWN',
    operatorAction:
      'Record the outcome with Safaricom support, then add a mapping under Settings → Policies → Failure reasons so future occurrences are explained automatically',
    transient: false,
    mapped: false,
    dictionaryVersion: FAILURE_DICTIONARY_VERSION,
  };
}

/** All dictionary entries, for the administration screen and the seed migration. */
export function listFailureReasons(): FailureReason[] {
  return Object.values(FAILURE_REASONS).sort((a, b) => a.code.localeCompare(b.code));
}
