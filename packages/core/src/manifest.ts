/**
 * Transaction manifest, authorization challenge and SPAC binding (spec §7.4, §7.5).
 *
 *   Challenge = HASH(organization + batch + amount + recipients
 *                    + approval + manifest + nonce + expiry)
 *
 * The manifest is a *deterministic* representation of exactly what is about to be paid.
 * Any change to the amount, the recipient set, or the approval chain produces a different
 * digest, which invalidates the authorization already in flight and forces a new approval
 * path. This is the mechanism behind §23's "Change a payment amount after Level 3 review
 * and confirm the prior signature is invalid".
 *
 * Determinism rules (all load-bearing — changing any of them is a breaking protocol change):
 *   - Instructions are sorted by instruction id, which is stable and unique.
 *   - Amounts are integer cents rendered without separators.
 *   - MSISDNs are canonical 12-digit form.
 *   - Fields are joined with ASCII unit separators that cannot occur in the field values.
 *   - The serialization is versioned, so a future change is detectable rather than silent.
 */

import { sumCents } from './money.js';
import { validationError, stateError } from './errors.js';

export const MANIFEST_VERSION = 'SLV-MANIFEST-1' as const;

/** ASCII unit / record separators — impossible in ids, MSISDNs or decimal amounts. */
const FS = '\x1f';
const RS = '\x1e';

export interface ManifestInstruction {
  instructionId: string;
  recipientId: string;
  /** Canonical 12-digit MSISDN. */
  msisdn: string;
  /** Integer cents. */
  amountCents: number;
}

export interface ManifestInput {
  organizationId: string;
  batchId: string;
  batchReference: string;
  /** Monotonic version of the batch content; bumped by every material edit. */
  batchVersion: number;
  /** The approval record this authorization is bound to (e.g. `APR-8821`). */
  approvalId: string;
  /** Version of the batch that the approver actually approved. */
  approvedBatchVersion: number;
  instructions: readonly ManifestInstruction[];
}

export interface Manifest {
  version: typeof MANIFEST_VERSION;
  organizationId: string;
  batchId: string;
  batchReference: string;
  batchVersion: number;
  approvalId: string;
  approvedBatchVersion: number;
  recipientCount: number;
  totalAmountCents: number;
  /** SHA-256 over the canonical serialization, uppercase hex. */
  manifestHash: string;
  /** The exact bytes that were hashed — retained for audit reproduction. */
  canonicalForm: string;
}

const HEX = '0123456789ABCDEF';

function toHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let out = '';
  for (const b of bytes) out += HEX[b >> 4]! + HEX[b & 0x0f]!;
  return out;
}

export async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  return toHex(await crypto.subtle.digest('SHA-256', data));
}

/** Deterministic serialization of the payment payload. Order and format are the contract. */
export function canonicalizeManifest(input: ManifestInput): string {
  if (input.instructions.length === 0) {
    throw validationError('MANIFEST_EMPTY', 'A payment manifest must contain at least one instruction');
  }
  if (input.approvedBatchVersion !== input.batchVersion) {
    // Refusing here (rather than hashing a mismatch) makes the failure loud at the exact
    // moment an edit slipped in after approval.
    throw stateError(
      'MANIFEST_APPROVAL_STALE',
      'The batch has changed since it was approved; a new approval is required before authorization',
      { approvedBatchVersion: input.approvedBatchVersion, batchVersion: input.batchVersion },
    );
  }

  const sorted = [...input.instructions].sort((a, b) =>
    a.instructionId < b.instructionId ? -1 : a.instructionId > b.instructionId ? 1 : 0,
  );

  const seen = new Set<string>();
  for (const i of sorted) {
    if (seen.has(i.instructionId)) {
      throw validationError('MANIFEST_DUPLICATE_INSTRUCTION', `Instruction ${i.instructionId} appears twice`);
    }
    seen.add(i.instructionId);
    if (!Number.isSafeInteger(i.amountCents) || i.amountCents <= 0) {
      throw validationError('MANIFEST_AMOUNT_INVALID', `Instruction ${i.instructionId} has a non-positive amount`);
    }
  }

  const total = sumCents(sorted.map((i) => i.amountCents));

  const header = [
    MANIFEST_VERSION,
    input.organizationId,
    input.batchId,
    input.batchReference,
    String(input.batchVersion),
    input.approvalId,
    String(input.approvedBatchVersion),
    String(sorted.length),
    String(total),
  ].join(FS);

  const body = sorted
    .map((i) => [i.instructionId, i.recipientId, i.msisdn, String(i.amountCents)].join(FS))
    .join(RS);

  return `${header}${RS}${body}`;
}

export async function buildManifest(input: ManifestInput): Promise<Manifest> {
  const canonicalForm = canonicalizeManifest(input);
  const manifestHash = await sha256Hex(canonicalForm);
  return {
    version: MANIFEST_VERSION,
    organizationId: input.organizationId,
    batchId: input.batchId,
    batchReference: input.batchReference,
    batchVersion: input.batchVersion,
    approvalId: input.approvalId,
    approvedBatchVersion: input.approvedBatchVersion,
    recipientCount: input.instructions.length,
    totalAmountCents: sumCents(input.instructions.map((i) => i.amountCents)),
    manifestHash,
    canonicalForm,
  };
}

// ---------------------------------------------------------------------------
// Authorization challenge
// ---------------------------------------------------------------------------

export interface ChallengeInput {
  manifest: Manifest;
  /** Single-use random value; persisted and burned on use. */
  nonce: string;
  /** Epoch milliseconds after which the challenge is refused. */
  expiresAt: number;
  /** The L3 user the challenge was issued to — it is not transferable. */
  authorizerUserId: string;
}

export interface AuthorizationChallenge {
  challengeHash: string;
  manifestHash: string;
  nonce: string;
  expiresAt: number;
  authorizerUserId: string;
  batchId: string;
  /** What the authorizer is shown and must confirm before signing (NFR-UX-001). */
  display: {
    batchReference: string;
    recipientCount: number;
    totalAmountCents: number;
    approvalId: string;
  };
}

/** Default challenge lifetime. Short enough to bound replay, long enough to read the screen. */
export const CHALLENGE_TTL_MS = 5 * 60 * 1000;

export async function buildChallenge(input: ChallengeInput): Promise<AuthorizationChallenge> {
  const { manifest, nonce, expiresAt, authorizerUserId } = input;
  if (!nonce || nonce.length < 16) {
    throw validationError('CHALLENGE_NONCE_WEAK', 'Authorization nonce must be at least 16 characters');
  }
  const payload = [
    MANIFEST_VERSION,
    manifest.organizationId,
    manifest.batchId,
    String(manifest.totalAmountCents),
    String(manifest.recipientCount),
    manifest.approvalId,
    manifest.manifestHash,
    authorizerUserId,
    nonce,
    String(expiresAt),
  ].join(FS);

  return {
    challengeHash: await sha256Hex(payload),
    manifestHash: manifest.manifestHash,
    nonce,
    expiresAt,
    authorizerUserId,
    batchId: manifest.batchId,
    display: {
      batchReference: manifest.batchReference,
      recipientCount: manifest.recipientCount,
      totalAmountCents: manifest.totalAmountCents,
      approvalId: manifest.approvalId,
    },
  };
}

export interface ChallengeVerificationInput {
  /** The challenge as stored server-side when the ceremony opened. */
  stored: AuthorizationChallenge & { consumedAt: number | null };
  /** The manifest rebuilt from *current* database state at release time. */
  current: Manifest;
  /** The user presenting the signature. */
  presentingUserId: string;
  now: number;
}

/**
 * Final gate before release. Every check here has a corresponding attack:
 *   - expiry       → replaying a screenshot of yesterday's ceremony
 *   - consumption  → replaying the same signed challenge twice (double disbursement)
 *   - user binding → an L3 handing their challenge to a colleague to finish
 *   - manifest     → editing amounts or recipients between approval and release
 */
export function verifyChallengeBinding(input: ChallengeVerificationInput): void {
  const { stored, current, presentingUserId, now } = input;

  if (stored.consumedAt !== null) {
    throw stateError('CHALLENGE_ALREADY_CONSUMED', 'This authorization challenge has already been used', {
      consumedAt: stored.consumedAt,
    });
  }
  if (now > stored.expiresAt) {
    throw stateError('CHALLENGE_EXPIRED', 'This authorization challenge has expired; start a new authorization', {
      expiresAt: stored.expiresAt,
    });
  }
  if (stored.authorizerUserId !== presentingUserId) {
    throw stateError(
      'CHALLENGE_ACTOR_MISMATCH',
      'This authorization challenge was issued to a different user',
    );
  }
  if (stored.batchId !== current.batchId) {
    throw stateError('CHALLENGE_BATCH_MISMATCH', 'This authorization challenge belongs to a different batch');
  }
  if (stored.manifestHash !== current.manifestHash) {
    throw stateError(
      'MANIFEST_CHANGED',
      'The batch has changed since authorization began; the previous authorization is void and a new approval is required',
      { authorizedManifest: stored.manifestHash, currentManifest: current.manifestHash },
    );
  }
}
