/**
 * Parsing and interpretation of Daraja result callbacks.
 *
 * Daraja's callback shape is inconsistent in ways that break naive parsers:
 *   - `ResultParameter` is an array for multi-value results and a bare object for one;
 *   - `ResultCode` arrives as a number on some endpoints and a string on others;
 *   - amounts arrive as numbers, strings, or pipe-delimited account strings;
 *   - `TransactionCompletedDateTime` is `dd.MM.yyyy HH:mm:ss` while `TransCompletedTime`
 *     on other endpoints is a 14-digit `yyyyMMddHHmmss`.
 *
 * Every one of those is handled here, once, so the rest of the platform sees clean data.
 */

import { resultCallbackSchema, type DarajaResultCallback } from './types.js';
import type { OrganizationAccountBalance } from './types.js';

export interface NormalizedResultParameters {
  [key: string]: string | number | undefined;
}

/** Collapse Daraja's object-or-array shapes into a plain record. */
export function normalizeResultParameters(
  callback: DarajaResultCallback,
): NormalizedResultParameters {
  const out: NormalizedResultParameters = {};
  const collect = (
    entry: { Key: string; Value?: string | number } | { Key: string; Value?: string | number }[],
  ) => {
    const list = Array.isArray(entry) ? entry : [entry];
    for (const item of list) {
      if (item && typeof item.Key === 'string') out[item.Key] = item.Value;
    }
  };
  const params = callback.Result.ResultParameters?.ResultParameter;
  if (params) collect(params);
  const reference = callback.Result.ReferenceData?.ReferenceItem;
  if (reference) collect(reference);
  return out;
}

export interface ParsedB2cResult {
  /** `0` means the payout succeeded. */
  resultCode: string;
  resultDescription: string;
  originatorConversationId: string | null;
  conversationId: string | null;
  /** M-PESA receipt, e.g. `SG632NMUAB`. Present only on success. */
  transactionReceipt: string | null;
  transactionAmountCents: number | null;
  receiverPartyPublicName: string | null;
  /** Parsed from `dd.MM.yyyy HH:mm:ss`, as an ISO-8601 UTC string. */
  completedAt: string | null;
  recipientIsRegistered: boolean | null;
  utilityAccountBalanceCents: number | null;
  workingAccountBalanceCents: number | null;
  chargesPaidAccountBalanceCents: number | null;
  succeeded: boolean;
  raw: DarajaResultCallback;
}

function toStringValue(value: string | number | undefined): string | null {
  if (value === undefined || value === null) return null;
  const s = String(value).trim();
  return s === '' ? null : s;
}

/** Convert a Daraja money value ("12000", 12000, "12,000.00") to integer cents. */
export function toCents(value: string | number | undefined): number | null {
  const s = toStringValue(value);
  if (s === null) return null;
  const cleaned = s.replace(/,/g, '');
  const numeric = Number(cleaned);
  if (!Number.isFinite(numeric)) return null;
  return Math.round(numeric * 100);
}

/**
 * Parse `dd.MM.yyyy HH:mm:ss` (B2C) or `yyyyMMddHHmmss` (balance/top-up) into ISO-8601.
 * Daraja timestamps are East Africa Time (UTC+3) with no zone marker.
 */
export function parseDarajaTimestamp(value: string | number | undefined): string | null {
  const s = toStringValue(value);
  if (s === null) return null;

  const dotted = s.match(/^(\d{2})\.(\d{2})\.(\d{4})\s+(\d{2}):(\d{2}):(\d{2})$/);
  if (dotted) {
    const [, dd, MM, yyyy, HH, mm, ss] = dotted;
    return eatToIso(Number(yyyy), Number(MM), Number(dd), Number(HH), Number(mm), Number(ss));
  }

  const compact = s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/);
  if (compact) {
    const [, yyyy, MM, dd, HH, mm, ss] = compact;
    return eatToIso(Number(yyyy), Number(MM), Number(dd), Number(HH), Number(mm), Number(ss));
  }

  const parsed = Date.parse(s);
  return Number.isNaN(parsed) ? null : new Date(parsed).toISOString();
}

/** East Africa Time is UTC+3 year-round — Kenya observes no daylight saving. */
function eatToIso(
  y: number,
  m: number,
  d: number,
  h: number,
  min: number,
  s: number,
): string | null {
  const ms = Date.UTC(y, m - 1, d, h - 3, min, s);
  if (Number.isNaN(ms)) return null;
  return new Date(ms).toISOString();
}

export function parseB2cResult(payload: unknown): ParsedB2cResult {
  const callback = resultCallbackSchema.parse(payload);
  const params = normalizeResultParameters(callback);
  const result = callback.Result;
  const resultCode = String(result.ResultCode).trim();

  return {
    resultCode,
    resultDescription: result.ResultDesc?.trim() ?? '',
    originatorConversationId: toStringValue(result.OriginatorConversationID),
    conversationId: toStringValue(result.ConversationID),
    transactionReceipt:
      toStringValue(params.TransactionReceipt) ?? toStringValue(result.TransactionID),
    transactionAmountCents: toCents(params.TransactionAmount),
    receiverPartyPublicName: toStringValue(params.ReceiverPartyPublicName),
    completedAt: parseDarajaTimestamp(params.TransactionCompletedDateTime),
    recipientIsRegistered:
      params.B2CRecipientIsRegisteredCustomer === undefined
        ? null
        : String(params.B2CRecipientIsRegisteredCustomer).toUpperCase() === 'Y',
    utilityAccountBalanceCents: toCents(params.B2CUtilityAccountAvailableFunds),
    workingAccountBalanceCents: toCents(params.B2CWorkingAccountAvailableFunds),
    chargesPaidAccountBalanceCents: toCents(params.B2CChargesPaidAccountAvailableFunds),
    succeeded: resultCode === '0',
    raw: callback,
  };
}

export interface ParsedTransactionStatusResult {
  resultCode: string;
  resultDescription: string;
  originatorConversationId: string | null;
  conversationId: string | null;
  receiptNumber: string | null;
  /** `Completed`, `Cancelled`, `Declined`, `Expired`, `Initiated`, `Pending Authorized`… */
  transactionStatus: string | null;
  amountCents: number | null;
  initiatedAt: string | null;
  finalisedAt: string | null;
  debitAccountType: string | null;
  reasonType: string | null;
  raw: DarajaResultCallback;
}

export function parseTransactionStatusResult(payload: unknown): ParsedTransactionStatusResult {
  const callback = resultCallbackSchema.parse(payload);
  const params = normalizeResultParameters(callback);
  const result = callback.Result;

  return {
    resultCode: String(result.ResultCode).trim(),
    resultDescription: result.ResultDesc?.trim() ?? '',
    originatorConversationId:
      toStringValue(params.OriginatorConversationID) ??
      toStringValue(result.OriginatorConversationID),
    conversationId: toStringValue(params.ConversationID) ?? toStringValue(result.ConversationID),
    receiptNumber: toStringValue(params.ReceiptNo) ?? toStringValue(result.TransactionID),
    transactionStatus: toStringValue(params.TransactionStatus),
    amountCents: toCents(params.Amount),
    initiatedAt: parseDarajaTimestamp(params.InitiatedTime),
    finalisedAt: parseDarajaTimestamp(params.FinalisedTime),
    debitAccountType: toStringValue(params.DebitAccountType),
    reasonType: toStringValue(params.ReasonType),
    raw: callback,
  };
}

/**
 * Map a Daraja transaction lifecycle status onto SOLVAREN's outcome vocabulary.
 *
 * `Initiated`, `Authorized` and `Pending Authorized` are *not* outcomes: they mean M-PESA
 * is still working. Treating them as failure would mark a paid employee unpaid, which is
 * why they map to `PENDING` and leave the transaction in reconciliation.
 */
export function interpretTransactionStatus(
  status: string | null,
): 'SUCCESS' | 'FAILED' | 'PENDING' | 'UNKNOWN' {
  if (!status) return 'UNKNOWN';
  switch (status.trim().toLowerCase()) {
    case 'completed':
      return 'SUCCESS';
    case 'cancelled':
    case 'declined':
    case 'expired':
      return 'FAILED';
    case 'initiated':
    case 'authorized':
    case 'pending authorized':
      return 'PENDING';
    default:
      return 'UNKNOWN';
  }
}

/**
 * Parse the `AccountBalance` result parameter:
 * `Working Account|KES|700000.00|700000.00|0.00|0.00&Utility Account|KES|228037.00|…`
 */
export function parseAccountBalances(
  raw: string | number | undefined,
): OrganizationAccountBalance[] {
  const s = toStringValue(raw);
  if (s === null) return [];
  const accounts: OrganizationAccountBalance[] = [];
  for (const segment of s.split('&')) {
    if (segment.trim() === '') continue;
    const fields = segment.split('|');
    if (fields.length < 3) continue;
    accounts.push({
      accountType: fields[0]!.trim(),
      currency: (fields[1] ?? 'KES').trim(),
      availableBalanceCents: toCents(fields[2]) ?? 0,
      unclearedBalanceCents: toCents(fields[3]) ?? 0,
      reservedBalanceCents: toCents(fields[4]) ?? 0,
    });
  }
  return accounts;
}

export function parseAccountBalanceResult(payload: unknown): {
  resultCode: string;
  resultDescription: string;
  accounts: OrganizationAccountBalance[];
  completedAt: string | null;
  raw: DarajaResultCallback;
} {
  const callback = resultCallbackSchema.parse(payload);
  const params = normalizeResultParameters(callback);
  return {
    resultCode: String(callback.Result.ResultCode).trim(),
    resultDescription: callback.Result.ResultDesc?.trim() ?? '',
    accounts: parseAccountBalances(params.AccountBalance),
    completedAt: parseDarajaTimestamp(params.BOCompletedTime),
    raw: callback,
  };
}
