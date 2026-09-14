/**
 * @solvaren/daraja — Safaricom M-PESA Daraja integration.
 *
 * Scope is deliberately narrow: the three APIs SOLVAREN actually uses (B2C v3, Transaction
 * Status, Account Balance), the SecurityCredential scheme, and callback normalisation.
 * Reversals are **not** implemented — v2.0 of the specification removed the in-app reversal
 * workflow entirely, and erroneous payouts are handled on the M-PESA organization portal.
 */

export * from './types.js';
export * from './security-credential.js';
export * from './callbacks.js';
export * from './client.js';
