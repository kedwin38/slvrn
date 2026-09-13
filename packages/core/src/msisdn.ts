/**
 * Kenyan MSISDN normalization.
 *
 * Daraja B2C requires `PartyB` as a 12-digit MSISDN with no `+` (e.g. 254705912645).
 * Operators paste numbers in every conceivable local format, and a mistyped digit pays a
 * stranger, so normalization is strict and total: either we produce a canonical 2547/2541
 * number or we reject the row.
 */

import { validationError } from './errors.js';

/** Safaricom/Kenyan mobile prefixes after the 254 country code (7xx and 1xx ranges). */
const KE_MOBILE = /^254(7\d{8}|1\d{8})$/;

export interface MsisdnParseResult {
  ok: boolean;
  msisdn?: string;
  reason?: string;
}

/** Non-throwing normalization, for row-level CSV validation where we collect all errors. */
export function tryNormalizeMsisdn(input: string): MsisdnParseResult {
  const raw = (input ?? '').trim();
  if (raw === '') return { ok: false, reason: 'Phone number is empty' };

  // Strip formatting humans add: spaces, dashes, brackets, and a leading +.
  let digits = raw.replace(/[\s()\-.]/g, '');
  if (digits.startsWith('+')) digits = digits.slice(1);

  if (!/^\d+$/.test(digits)) {
    return { ok: false, reason: `Phone number "${raw}" contains non-numeric characters` };
  }

  // 0712345678 -> 254712345678
  if (digits.length === 10 && digits.startsWith('0')) digits = `254${digits.slice(1)}`;
  // 712345678 -> 254712345678
  else if (digits.length === 9 && (digits.startsWith('7') || digits.startsWith('1')))
    digits = `254${digits}`;
  // 00254712345678 -> 254712345678
  else if (digits.startsWith('00254')) digits = digits.slice(2);

  if (digits.length !== 12) {
    return { ok: false, reason: `Phone number "${raw}" is not a 12-digit Kenyan MSISDN` };
  }
  if (!KE_MOBILE.test(digits)) {
    return {
      ok: false,
      reason: `Phone number "${raw}" is not a recognised Kenyan mobile number (expected 2547XXXXXXXX or 2541XXXXXXXX)`,
    };
  }
  return { ok: true, msisdn: digits };
}

/** Throwing normalization for code paths where an invalid number is a programming error. */
export function normalizeMsisdn(input: string): string {
  const result = tryNormalizeMsisdn(input);
  if (!result.ok || !result.msisdn) {
    throw validationError('MSISDN_INVALID', result.reason ?? 'Invalid MSISDN');
  }
  return result.msisdn;
}

/**
 * Mask an MSISDN for display in logs, exports to lower-privilege roles and AI prompts:
 * `254712345678` -> `2547****5678`.
 */
export function maskMsisdn(msisdn: string): string {
  if (msisdn.length < 8) return '****';
  return `${msisdn.slice(0, 4)}****${msisdn.slice(-4)}`;
}
