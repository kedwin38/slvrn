/**
 * The payment release ceremony (spec 5.4, 7.5, 19).
 *
 * This is the single path by which money can leave the organisation, and it is written to
 * be read by an auditor. Release requires, in order and without exception:
 *
 *   1. L3 authority, checked server-side against the permission matrix;
 *   2. an intact approval chain, with the L2 approval bound to the current batch version;
 *   3. separation of duties — the authorizer did not create, edit or approve the batch;
 *   4. no declared conflict of interest over any recipient or department in the batch;
 *   5. a manifest rebuilt from *current* database state that hashes identically to the one
 *      authorized when the ceremony opened;
 *   6. fresh authentication (spec 8.2);
 *   7. a WebAuthn signature over the challenge;
 *   8. the SOLVAREN Authorization PIN;
 *   9. organisation policy limits and the risk gate;
 *  10. a valid batch state, reached through the state machine.
 *
 * Every one of those is a separate failure with its own message and its own audit event.
 * There is no branch that skips a step, no administrative override, and no parameter that
 * disables a check — spec 7.5: "No single password, session, API request, database record
 * or user-interface action is sufficient to release money."
 */

import {
  buildManifest,
  buildChallenge,
  verifyChallengeBinding,
  assertTransition,
  assertNotSelfAuthorization,
  assertNoDeclaredConflict,
  assertReleasePolicy,
  instructionFingerprint,
  randomToken,
  reference,
  CHALLENGE_TTL_MS,
  stateError,
  notFoundError,
  policyError,
  type Manifest,
  type BatchState,
  type OrganizationPolicy,
  type RiskAssessment,
} from '@solvaren/core';
import { inTransaction, requireLock, type Sql } from '../db/client.js';
import { writeAuditEvent } from '../db/audit-writer.js';
import { assertFreshAuthentication, assertWebAuthnSession } from './auth.js';
import { permissionsOfActor as permissionsOf } from './permissions.js';
import { verifyAuthorizationPin } from './crypto.js';
import { loadPolicy } from './policy-store.js';
import { assessBatch } from './risk-service.js';
import type { AuthenticatedActor, Env } from '../env.js';

export interface BatchRow {
  id: string;
  organization_id: string;
  batch_reference: string;
  state: BatchState;
  version: number;
  instruction_count: number;
  total_amount_cents: string;
  created_by_user_id: string;
  submitted_by_user_id: string | null;
  approved_by_user_id: string | null;
  authorized_by_user_id: string | null;
  last_material_edit_at: string | null;
  submitted_at: string | null;
}

export interface OpenCeremonyResult {
  challengeId: string;
  challengeHash: string;
  /** base64url challenge the browser passes to `navigator.credentials.get`. */
  webauthnChallenge: string;
  expiresAt: string;
  manifest: {
    manifestHash: string;
    batchReference: string;
    recipientCount: number;
    totalAmountCents: number;
    approvalId: string;
    batchVersion: number;
  };
  /** Statements the authorizer must tick before signing (NFR-UX-001). */
  acknowledgementsRequired: string[];
  risk: RiskAssessment;
}

/**
 * Open the authorization ceremony.
 *
 * Everything that can be checked before asking a human to touch their security key is
 * checked here, so that a release fails on policy *before* the ceremony rather than after
 * the officer has already signed.
 */
export async function openAuthorizationCeremony(params: {
  sql: Sql;
  actor: AuthenticatedActor;
  batchId: string;
  correlationId: string;
  securityContext: Record<string, unknown>;
}): Promise<OpenCeremonyResult> {
  const { sql, actor, batchId, correlationId } = params;

  return inTransaction(sql, async (tx) => {
    // Serialise ceremonies for this batch: two L3 officers opening one payroll at the same
    // moment is precisely the race that produces a double release.
    await requireLock(tx, 'batch', batchId);

    const batch = await loadBatch(tx, actor.organizationId, batchId);

    // ---- State ----------------------------------------------------------
    assertTransition(batch.state, 'BEGIN_AUTHORIZATION', {
      actor: { level: actor.level, permissions: permissionsOf(actor) },
    });

    // ---- Approval chain --------------------------------------------------
    const approval = await loadCurrentApproval(tx, batch);

    // ---- Separation of duties -------------------------------------------
    const editors = await tx<{ user_id: string }[]>`
      SELECT user_id FROM batch_editors WHERE batch_id = ${batch.id}
    `;
    assertNotSelfAuthorization({
      actorUserId: actor.userId,
      actorLevel: actor.level,
      participants: {
        createdByUserId: batch.created_by_user_id,
        editedByUserIds: editors.map((e) => e.user_id),
        approvedByUserId: batch.approved_by_user_id,
        submittedByUserId: batch.submitted_by_user_id,
      },
    });

    // ---- Conflict of interest -------------------------------------------
    const scope = await tx<{ recipient_id: string; department_id: string | null }[]>`
      SELECT DISTINCT recipient_id, department_id
        FROM payment_instructions
       WHERE batch_id = ${batch.id}
    `;
    const conflicts = await tx<
      {
        user_id: string;
        scope_type: 'RECIPIENT' | 'DEPARTMENT' | 'ORGANIZATION';
        scope_id: string | null;
        reason: string;
      }[]
    >`
      SELECT user_id, scope_type, scope_id, reason
        FROM conflict_registrations
       WHERE organization_id = ${actor.organizationId}
         AND user_id = ${actor.userId}
         AND withdrawn_at IS NULL
    `;
    assertNoDeclaredConflict({
      actorUserId: actor.userId,
      conflicts: conflicts.map((c) => ({
        userId: c.user_id,
        scopeType: c.scope_type,
        scopeId: c.scope_id,
        reason: c.reason,
      })),
      recipientIds: scope.map((s) => s.recipient_id),
      departmentIds: scope.map((s) => s.department_id).filter((d): d is string => d !== null),
    });

    // ---- Manifest --------------------------------------------------------
    const manifest = await buildBatchManifest(tx, batch, approval.approval_reference);

    // ---- Risk and policy -------------------------------------------------
    const policy = await loadPolicy(tx, actor.organizationId);
    const risk = await assessBatch(tx, batch, policy);
    const dispositioned = await tx<{ count: string }[]>`
      SELECT COUNT(*) AS count
        FROM risk_findings
       WHERE batch_id = ${batch.id} AND batch_version = ${batch.version}
         AND disposition <> 'OPEN'
    `;
    const disbursedToday = await tx<{ total: string | null }[]>`
      SELECT COALESCE(SUM(total_cents), 0) AS total
        FROM daily_disbursement_totals
       WHERE organization_id = ${actor.organizationId}
         AND disbursement_date = (now() AT TIME ZONE 'Africa/Nairobi')::DATE
    `;
    const maxInstruction = await tx<{ max: string | null }[]>`
      SELECT MAX(amount_cents) AS max FROM payment_instructions WHERE batch_id = ${batch.id}
    `;

    const policyResult = assertReleasePolicy({
      policy,
      instructionCount: batch.instruction_count,
      totalAmountCents: Number(batch.total_amount_cents),
      maxInstructionAmountCents: Number(maxInstruction[0]?.max ?? 0),
      risk,
      dispositionedFindingCount: Number(dispositioned[0]?.count ?? 0),
      disbursedTodayCents: Number(disbursedToday[0]?.total ?? 0),
    });

    // ---- Issue the challenge --------------------------------------------
    const nonce = randomToken(32);
    const expiresAt = new Date(Date.now() + CHALLENGE_TTL_MS);
    const challenge = await buildChallenge({
      manifest,
      nonce,
      expiresAt: expiresAt.getTime(),
      authorizerUserId: actor.userId,
    });
    // The WebAuthn challenge is derived from the manifest digest, so the authenticator
    // signs over something cryptographically tied to the exact payment set.
    const webauthnChallenge = challenge.challengeHash;

    const inserted = await tx<{ id: string }[]>`
      INSERT INTO authorization_challenges (
        organization_id, batch_id, approval_id, authorizer_user_id, manifest_hash,
        challenge_hash, manifest_canonical_form, nonce, batch_version, recipient_count,
        total_amount_cents, webauthn_challenge, expires_at
      ) VALUES (
        ${actor.organizationId}, ${batch.id}, ${approval.id}, ${actor.userId},
        ${manifest.manifestHash}, ${challenge.challengeHash}, ${manifest.canonicalForm},
        ${nonce}, ${batch.version}, ${manifest.recipientCount}, ${manifest.totalAmountCents},
        ${webauthnChallenge}, ${expiresAt}
      )
      RETURNING id
    `;

    await tx`
      UPDATE payment_batches SET state = 'AUTHORIZATION_PENDING' WHERE id = ${batch.id}
    `;

    await writeAuditEvent(tx, {
      organizationId: actor.organizationId,
      actorId: actor.userId,
      actorLevel: actor.level,
      eventClass: 'PAYMENT',
      action: 'payment.authorization.opened',
      objectType: 'PaymentBatch',
      objectId: batch.id,
      outcome: 'SUCCESS',
      previousState: { state: batch.state },
      newState: { state: 'AUTHORIZATION_PENDING' },
      correlationId,
      securityContext: params.securityContext,
      detail: {
        manifestHash: manifest.manifestHash,
        batchVersion: batch.version,
        recipientCount: manifest.recipientCount,
        totalAmountCents: manifest.totalAmountCents,
        riskScore: risk.score,
        riskBand: risk.band,
        approvalReference: approval.approval_reference,
      },
    });

    return {
      challengeId: inserted[0]!.id,
      challengeHash: challenge.challengeHash,
      webauthnChallenge,
      expiresAt: expiresAt.toISOString(),
      manifest: {
        manifestHash: manifest.manifestHash,
        batchReference: manifest.batchReference,
        recipientCount: manifest.recipientCount,
        totalAmountCents: manifest.totalAmountCents,
        approvalId: approval.approval_reference,
        batchVersion: batch.version,
      },
      acknowledgementsRequired: policyResult.acknowledgementsRequired,
      risk,
    };
  });
}

export interface ReleaseInput {
  sql: Sql;
  env: Env;
  actor: AuthenticatedActor;
  batchId: string;
  challengeId: string;
  /** Verified WebAuthn assertion result — verification itself happens in the route. */
  webauthnVerified: boolean;
  webauthnCredentialId: string | null;
  authorizationPin: string;
  acknowledgements: string[];
  correlationId: string;
  securityContext: Record<string, unknown>;
}

export interface ReleaseResult {
  batchId: string;
  batchReference: string;
  instructionsQueued: number;
  totalAmountCents: number;
  manifestHash: string;
  releasedAt: string;
}

/**
 * Complete the ceremony and release the batch.
 *
 * The manifest is rebuilt from live database rows rather than trusted from the ceremony
 * record. That is the whole mechanism behind spec 23's "Change a payment amount after
 * Level 3 review and confirm the prior signature is invalid": if anything changed, the
 * rebuilt digest differs and `verifyChallengeBinding` refuses.
 */
export async function releaseBatch(input: ReleaseInput): Promise<ReleaseResult> {
  const { sql, actor, batchId, challengeId, correlationId } = input;

  // ---- Session-level gates, before touching the database ------------------
  assertFreshAuthentication(actor);
  assertWebAuthnSession(actor);

  if (!input.webauthnVerified) {
    throw stateError(
      'WEBAUTHN_SIGNATURE_REQUIRED',
      'Payment release requires a verified security key signature over this batch',
    );
  }

  return inTransaction(sql, async (tx) => {
    await requireLock(tx, 'batch', batchId);

    const batch = await loadBatch(tx, actor.organizationId, batchId);

    assertTransition(batch.state, 'AUTHORIZE', {
      actor: { level: actor.level, permissions: permissionsOf(actor) },
    });

    // ---- SPAC PIN --------------------------------------------------------
    const pinRows = await tx<{ authorization_pin_hash: string | null }[]>`
      SELECT authorization_pin_hash FROM users WHERE id = ${actor.userId} LIMIT 1
    `;
    const pinOk = await verifyAuthorizationPin(
      input.authorizationPin,
      actor.userId,
      pinRows[0]?.authorization_pin_hash ?? null,
    );
    if (!pinOk) {
      // Audited as a denial in its own transaction-visible event, then refused.
      await writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'SECURITY',
        action: 'payment.release.pin_rejected',
        objectType: 'PaymentBatch',
        objectId: batchId,
        outcome: 'DENIED',
        correlationId,
        securityContext: input.securityContext,
        detail: { challengeId },
      });
      throw stateError(
        'AUTHORIZATION_PIN_INVALID',
        'The SOLVAREN Authorization PIN was not correct. This attempt has been recorded.',
      );
    }

    // ---- Challenge binding ----------------------------------------------
    const challengeRows = await tx<
      {
        id: string;
        batch_id: string;
        approval_id: string;
        authorizer_user_id: string;
        manifest_hash: string;
        challenge_hash: string;
        nonce: string;
        batch_version: number;
        recipient_count: number;
        total_amount_cents: string;
        expires_at: string;
        consumed_at: string | null;
        abandoned_at: string | null;
        approval_reference: string;
      }[]
    >`
      SELECT ac.*, a.approval_reference
        FROM authorization_challenges ac
        JOIN approvals a ON a.id = ac.approval_id
       WHERE ac.id = ${challengeId}
         AND ac.organization_id = ${actor.organizationId}
       LIMIT 1
    `;
    const stored = challengeRows[0];
    if (!stored) {
      throw notFoundError('CHALLENGE_NOT_FOUND', 'That authorization ceremony could not be found');
    }
    if (stored.abandoned_at) {
      throw stateError(
        'CHALLENGE_ABANDONED',
        'That authorization ceremony was abandoned. Start a new one.',
      );
    }

    // Rebuild from live state — never from the stored copy.
    const currentManifest = await buildBatchManifest(tx, batch, stored.approval_reference);

    verifyChallengeBinding({
      stored: {
        challengeHash: stored.challenge_hash,
        manifestHash: stored.manifest_hash,
        nonce: stored.nonce,
        expiresAt: new Date(stored.expires_at).getTime(),
        authorizerUserId: stored.authorizer_user_id,
        batchId: stored.batch_id,
        display: {
          batchReference: batch.batch_reference,
          recipientCount: stored.recipient_count,
          totalAmountCents: Number(stored.total_amount_cents),
          approvalId: stored.approval_reference,
        },
        consumedAt: stored.consumed_at ? new Date(stored.consumed_at).getTime() : null,
      },
      current: currentManifest,
      presentingUserId: actor.userId,
      now: Date.now(),
    });

    // ---- Separation of duties, re-checked at release ---------------------
    // Re-checked rather than trusted from the open step: an L2 approval could have been
    // recorded in between, and the approver must still not be the authorizer.
    const editors = await tx<{ user_id: string }[]>`
      SELECT user_id FROM batch_editors WHERE batch_id = ${batch.id}
    `;
    assertNotSelfAuthorization({
      actorUserId: actor.userId,
      actorLevel: actor.level,
      participants: {
        createdByUserId: batch.created_by_user_id,
        editedByUserIds: editors.map((e) => e.user_id),
        approvedByUserId: batch.approved_by_user_id,
        submittedByUserId: batch.submitted_by_user_id,
      },
    });

    // ---- Policy, re-evaluated at release --------------------------------
    const policy = await loadPolicy(tx, actor.organizationId);
    const risk = await assessBatch(tx, batch, policy);
    const dispositioned = await tx<{ count: string }[]>`
      SELECT COUNT(*) AS count FROM risk_findings
       WHERE batch_id = ${batch.id} AND batch_version = ${batch.version} AND disposition <> 'OPEN'
    `;
    const disbursedToday = await tx<{ total: string | null }[]>`
      SELECT COALESCE(SUM(total_cents), 0) AS total
        FROM daily_disbursement_totals
       WHERE organization_id = ${actor.organizationId}
         AND disbursement_date = (now() AT TIME ZONE 'Africa/Nairobi')::DATE
    `;
    const maxInstruction = await tx<{ max: string | null }[]>`
      SELECT MAX(amount_cents) AS max FROM payment_instructions WHERE batch_id = ${batch.id}
    `;
    const policyResult = assertReleasePolicy({
      policy,
      instructionCount: batch.instruction_count,
      totalAmountCents: Number(batch.total_amount_cents),
      maxInstructionAmountCents: Number(maxInstruction[0]?.max ?? 0),
      risk,
      dispositionedFindingCount: Number(dispositioned[0]?.count ?? 0),
      disbursedTodayCents: Number(disbursedToday[0]?.total ?? 0),
    });

    // Every required acknowledgement must have been ticked, and the text must match —
    // a client that sends an empty array, or invents its own, does not get a release.
    for (const required of policyResult.acknowledgementsRequired) {
      if (!input.acknowledgements.includes(required)) {
        throw policyError(
          'ACKNOWLEDGEMENT_REQUIRED',
          'Every risk and value acknowledgement must be confirmed before release',
          { missing: required },
        );
      }
    }

    // ---- Burn the challenge ---------------------------------------------
    // Conditional UPDATE: if another request consumed it between our read and now, this
    // affects zero rows and the release aborts rather than double-releasing.
    const consumed = await tx<{ id: string }[]>`
      UPDATE authorization_challenges
         SET consumed_at = now(),
             signature_verified_at = now(),
             pin_verified_at = now(),
             webauthn_credential_id = ${input.webauthnCredentialId}
       WHERE id = ${stored.id} AND consumed_at IS NULL
      RETURNING id
    `;
    if (consumed.length === 0) {
      throw stateError(
        'CHALLENGE_ALREADY_CONSUMED',
        'This authorization was already completed. The batch has not been released twice.',
      );
    }

    // ---- Record the authorization ---------------------------------------
    const releasedAt = new Date();
    const authorizationReference = reference('APR');
    await tx`
      INSERT INTO approvals (
        organization_id, approval_reference, batch_id, batch_version, actor_user_id,
        actor_level, action, reason, risk_acknowledged
      ) VALUES (
        ${actor.organizationId}, ${authorizationReference}, ${batch.id}, ${batch.version},
        ${actor.userId}, ${actor.level}, 'AUTHORIZE',
        ${'Final payment authorization'}, ${policyResult.acknowledgementsRequired.length > 0}
      )
    `;

    await tx`
      UPDATE payment_batches
         SET state = 'AUTHORIZED',
             authorized_by_user_id = ${actor.userId},
             authorized_at = ${releasedAt},
             released_at = ${releasedAt},
             risk_score = ${risk.score},
             risk_band = ${risk.band}
       WHERE id = ${batch.id}
    `;

    // ---- Claim idempotency and enqueue execution ------------------------
    //
    // Both happen inside this transaction, which is the single most important consequence
    // of backing the queue with PostgreSQL.
    //
    // The claim has always been made here, so that a redelivery cannot produce a second
    // claim and therefore cannot produce a second payment. What could not be done before
    // was enqueueing here: the queue was a separate system, so the release committed and
    // *then* the messages were sent. A process that died in between left a batch marked
    // authorized, with idempotency claims, and no messages — a payroll that silently never
    // ran, and one that could not simply be re-released because the claims already existed.
    //
    // Now the claim and the job that consumes it commit together, or neither does.
    const instructions = await tx<
      { id: string; recipient_id: string; msisdn_snapshot: string; amount_cents: string }[]
    >`
      SELECT id, recipient_id, msisdn_snapshot, amount_cents
        FROM payment_instructions
       WHERE batch_id = ${batch.id}
       ORDER BY id
    `;

    for (const instruction of instructions) {
      const fingerprint = await instructionFingerprint({
        organizationId: actor.organizationId,
        batchId: batch.id,
        instructionId: instruction.id,
        batchVersion: batch.version,
        msisdn: instruction.msisdn_snapshot,
        amountCents: Number(instruction.amount_cents),
        manifestHash: currentManifest.manifestHash,
      });
      await tx`
        INSERT INTO idempotency_claims (fingerprint, organization_id, instruction_id, state)
        VALUES (${fingerprint}, ${actor.organizationId}, ${instruction.id}, 'CLAIMED')
        ON CONFLICT (fingerprint) DO NOTHING
      `;

      await input.env.queue.send(
        {
          queue: 'payments',
          body: {
            type: 'EXECUTE_INSTRUCTION',
            organizationId: actor.organizationId,
            batchId: batch.id,
            instructionId: instruction.id,
            batchVersion: batch.version,
            manifestHash: currentManifest.manifestHash,
            fingerprint,
            challengeId: stored.id,
            correlationId,
            attempt: 0,
          },
        },
        tx,
      );
    }

    await writeAuditEvent(tx, {
      organizationId: actor.organizationId,
      actorId: actor.userId,
      actorLevel: actor.level,
      eventClass: 'PAYMENT',
      action: 'payment.release.authorized',
      objectType: 'PaymentBatch',
      objectId: batch.id,
      outcome: 'SUCCESS',
      previousState: { state: 'AUTHORIZATION_PENDING' },
      newState: { state: 'AUTHORIZED' },
      correlationId,
      securityContext: input.securityContext,
      detail: {
        manifestHash: currentManifest.manifestHash,
        challengeId: stored.id,
        authorizationReference,
        batchVersion: batch.version,
        recipientCount: currentManifest.recipientCount,
        totalAmountCents: currentManifest.totalAmountCents,
        webauthnCredentialId: input.webauthnCredentialId,
        acknowledgements: policyResult.acknowledgementsRequired,
        riskScore: risk.score,
        riskBand: risk.band,
        approvedBy: batch.approved_by_user_id,
      },
    });

    // The jobs are committed by this same transaction, so QUEUED is now an honest
    // description of the batch rather than a hope. Written after the audit event so the
    // event still records the AUTHORIZED transition it describes.
    await tx`
      UPDATE payment_batches
         SET state = 'QUEUED'
       WHERE id = ${batch.id} AND state = 'AUTHORIZED'
    `;

    return {
      batchId: batch.id,
      batchReference: batch.batch_reference,
      instructionsQueued: instructions.length,
      totalAmountCents: currentManifest.totalAmountCents,
      manifestHash: currentManifest.manifestHash,
      releasedAt: releasedAt.toISOString(),
    };
  });
}

/** Abandon an open ceremony, returning the batch to L3_READY. */
export async function abandonCeremony(params: {
  sql: Sql;
  actor: AuthenticatedActor;
  batchId: string;
  reason: string;
  correlationId: string;
  securityContext: Record<string, unknown>;
}): Promise<void> {
  const { sql, actor, batchId, correlationId } = params;
  await inTransaction(sql, async (tx) => {
    await requireLock(tx, 'batch', batchId);
    const batch = await loadBatch(tx, actor.organizationId, batchId);

    assertTransition(batch.state, 'ABANDON_AUTHORIZATION', {
      actor: { level: actor.level, permissions: permissionsOf(actor) },
    });

    await tx`
      UPDATE authorization_challenges
         SET abandoned_at = now()
       WHERE batch_id = ${batchId} AND consumed_at IS NULL AND abandoned_at IS NULL
    `;
    await tx`UPDATE payment_batches SET state = 'L3_READY' WHERE id = ${batchId}`;

    await writeAuditEvent(tx, {
      organizationId: actor.organizationId,
      actorId: actor.userId,
      actorLevel: actor.level,
      eventClass: 'PAYMENT',
      action: 'payment.authorization.abandoned',
      objectType: 'PaymentBatch',
      objectId: batchId,
      outcome: 'SUCCESS',
      previousState: { state: batch.state },
      newState: { state: 'L3_READY' },
      correlationId,
      securityContext: params.securityContext,
      detail: { reason: params.reason },
    });
  });
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

export async function loadBatch(
  tx: Sql,
  organizationId: string,
  batchId: string,
): Promise<BatchRow> {
  const rows = await tx<BatchRow[]>`
    SELECT id, organization_id, batch_reference, state, version, instruction_count,
           total_amount_cents, created_by_user_id, submitted_by_user_id, approved_by_user_id,
           authorized_by_user_id, last_material_edit_at, submitted_at
      FROM payment_batches
     WHERE id = ${batchId} AND organization_id = ${organizationId}
     FOR UPDATE
  `;
  const batch = rows[0];
  if (!batch) {
    // Scoped by organization_id in the query itself, so a cross-tenant id is simply
    // not found — no existence oracle.
    throw notFoundError('BATCH_NOT_FOUND', 'That payment batch could not be found');
  }
  return batch;
}

/** Load the L2 approval governing the batch's *current* version. */
async function loadCurrentApproval(
  tx: Sql,
  batch: BatchRow,
): Promise<{ id: string; approval_reference: string; batch_version: number }> {
  const rows = await tx<{ id: string; approval_reference: string; batch_version: number }[]>`
    SELECT id, approval_reference, batch_version
      FROM approvals
     WHERE batch_id = ${batch.id} AND action = 'APPROVE'
     ORDER BY created_at DESC
     LIMIT 1
  `;
  const approval = rows[0];
  if (!approval) {
    throw stateError(
      'APPROVAL_MISSING',
      'This batch has no Level 2 finance approval on record and cannot be authorized',
    );
  }
  if (approval.batch_version !== batch.version) {
    // The batch was edited after approval. Spec 19: the approval version is invalidated.
    throw stateError(
      'APPROVAL_STALE',
      `This batch has been edited since it was approved (approved version ${approval.batch_version}, current version ${batch.version}). It must be re-reviewed by Finance Control before it can be authorized.`,
      { approvedVersion: approval.batch_version, currentVersion: batch.version },
    );
  }
  return approval;
}

/** Rebuild the manifest from live instruction rows. */
export async function buildBatchManifest(
  tx: Sql,
  batch: BatchRow,
  approvalReference: string,
): Promise<Manifest> {
  const instructions = await tx<
    { id: string; recipient_id: string; msisdn_snapshot: string; amount_cents: string }[]
  >`
    SELECT id, recipient_id, msisdn_snapshot, amount_cents
      FROM payment_instructions
     WHERE batch_id = ${batch.id}
     ORDER BY id
  `;

  return buildManifest({
    organizationId: batch.organization_id,
    batchId: batch.id,
    batchReference: batch.batch_reference,
    batchVersion: batch.version,
    approvalId: approvalReference,
    approvedBatchVersion: batch.version,
    instructions: instructions.map((i) => ({
      instructionId: i.id,
      recipientId: i.recipient_id,
      msisdn: i.msisdn_snapshot,
      amountCents: Number(i.amount_cents),
    })),
  });
}

export type { OrganizationPolicy };
