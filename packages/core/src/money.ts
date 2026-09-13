/**
 * Money handling.
 *
 * SOLVAREN stores every amount as an integer number of cents (KES 1 = 100 cents) so that
 * no financial total ever passes through a binary floating-point addition. Daraja itself
 * accepts whole shillings for B2C, so submission converts back at the boundary and refuses
 * fractional shillings rather than silently rounding someone's salary.
 */

import { validationError } from './errors.js';

export const CURRENCY = 'KES' as const;

/** Daraja B2C per-transaction limits (see Daraja KB §5.1 "Limits"). */
export const DARAJA_B2C_MIN_CENTS = 10_00;
export const DARAJA_B2C_MAX_CENTS = 250_000_00;
/** M-PESA customer daily receive limit and maximum wallet balance. */
export const MPESA_CUSTOMER_DAILY_LIMIT_CENTS = 500_000_00;

const AMOUNT_PATTERN = /^-?\d{1,15}(\.\d{1,2})?$/;

/**
 * Parse a user- or CSV-supplied amount into integer cents.
 * Accepts `12000`, `12000.50`, `12,000.50`, `KES 12000`. Rejects anything else outright —
 * a mis-parsed amount is a mis-paid salary.
 */
export function parseAmountToCents(input: string | number): number {
  const raw = typeof input === 'number' ? String(input) : input;
  const cleaned = raw.trim().replace(/^KES\s*/i, '').replace(/,/g, '').replace(/\s/g, '');
  if (cleaned === '' || !AMOUNT_PATTERN.test(cleaned)) {
    throw validationError('AMOUNT_INVALID', `Amount "${raw}" is not a valid KES amount`);
  }
  const negative = cleaned.startsWith('-');
  const [whole, frac = ''] = cleaned.replace('-', '').split('.') as [string, string?];
  const cents = Number(whole) * 100 + Number((frac + '00').slice(0, 2));
  if (!Number.isSafeInteger(cents)) {
    throw validationError('AMOUNT_OUT_OF_RANGE', `Amount "${raw}" exceeds the supported range`);
  }
  return negative ? -cents : cents;
}

/** Format integer cents for display: `1234567` -> `12,345.67`. */
export function formatCents(cents: number): string {
  const negative = cents < 0;
  const abs = Math.abs(cents);
  const whole = Math.floor(abs / 100).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  const frac = (abs % 100).toString().padStart(2, '0');
  return `${negative ? '-' : ''}${whole}.${frac}`;
}

/** Sum integer cents with overflow protection. Never use `Array.reduce` on floats. */
export function sumCents(values: readonly number[]): number {
  let total = 0;
  for (const v of values) {
    if (!Number.isSafeInteger(v)) {
      throw validationError('AMOUNT_INVALID', 'Encountered a non-integer cent value while totalling');
    }
    total += v;
    if (!Number.isSafeInteger(total)) {
      throw validationError('AMOUNT_OUT_OF_RANGE', 'Batch total exceeds the supported range');
    }
  }
  return total;
}

/**
 * Convert stored cents into the whole-shilling string Daraja expects.
 * Fractional shillings are rejected: rounding at the payment boundary is a silent
 * financial mutation, and SOLVAREN does not perform silent financial mutations.
 */
export function centsToDarajaAmount(cents: number): string {
  if (!Number.isSafeInteger(cents) || cents <= 0) {
    throw validationError('AMOUNT_INVALID', 'Daraja amount must be a positive integer of cents');
  }
  if (cents % 100 !== 0) {
    throw validationError(
      'AMOUNT_FRACTIONAL',
      `Daraja B2C accepts whole shillings only; ${formatCents(cents)} has a fractional part`,
    );
  }
  return String(cents / 100);
}
