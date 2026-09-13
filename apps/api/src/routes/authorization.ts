/**
 * Payment authorization and release routes (spec 5.4, 7.5).
 *
 * Two endpoints, both L3-only, both thin: the ceremony logic lives in
 * `services/authorization.ts` so that it can be read and tested as one continuous piece of
 * security reasoning rather than being distributed across HTTP handlers.
 *
 * The release endpoint is the only place in the platform that enqueues payment work.
 */

import { Hono } from 'hono';
import { z } from 'zod';
import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import {
  formatCents,
  authenticationError,
  notFoundError,
  isValidIdempotencyKey,
  validationError,
} from '@solvaren/core';
import {
  requireAuth,
  requirePermissions,
  requireExactLevel,
  actorOf,
} from '../middleware/security.js';
import { withConnection, inTransaction } from '../db/client.js';
import { writeAuditEvent } from '../db/audit-writer.js';
import {
  openAuthorizationCeremony,
  releaseBatch,
  abandonCeremony,
} from '../services/authorization.js';
import type { AppContext } from '../env.js';

export const authorizationRoutes = new Hono<AppContext>();

authorizationRoutes.use('*', requireAuth);
// Every route below is executive authority. Declared once, at the top, rather than
// repeated per handler where it could be forgotten on a new route.
authorizationRoutes.use('*', requireExactLevel('L3'));

/**
 * POST /authorization/batches/:id/begin — open the ceremony.
 *
 * Returns the manifest summary the authorizer must confirm, the WebAuthn challenge, and
 * the acknowledgements policy requires. No money moves here.
 */
authorizationRoutes.post(
  '/batches/:id/begin',
  requirePermissions('payment:authorize'),
  async (c) => {
    const actor = actorOf(c);
    const batchId = c.req.param('id');

    const result = await withConnection(c.env, (sql) =>
      openAuthorizationCeremony({
        sql,
        actor,
        batchId,
        correlationId: c.get('correlationId'),
        securityContext: c.get('securityContext'),
      }),
    );

    return c.json({
      ...result,
      // NFR-UX-001: the amount, recipient count and batch reference must be unmistakable
      // before an irreversible action.
      confirmation: {
        headline: `Release KES ${formatCents(result.manifest.totalAmountCents)} to ${result.manifest.recipientCount} recipients`,
        batchReference: result.manifest.batchReference,
        manifestDigestShort: result.manifest.manifestHash.slice(0, 16),
        warning:
          'Once released, these payments are submitted to M-PESA and cannot be recalled from SOLVAREN. Reversals are handled on the M-PESA organisation portal.',
      },
    });
  },
);

const releaseSchema = z.object({
  challengeId: z.string().uuid(),
  /** WebAuthn assertion over the challenge issued by /begin. */
  webauthnResponse: z.record(z.unknown()),
  authorizationPin: z.string().min(6).max(12),
  acknowledgements: z.array(z.string().max(500)).max(20).default([]),
});

/**
 * POST /authorization/batches/:id/release — complete the ceremony and release.
 *
 * The WebAuthn assertion is verified here, against the challenge stored when the ceremony
 * opened, and the verified result is handed to the release service. The service performs
 * every other check and refuses if `webauthnVerified` is not true, so no route can release
 * a payment by skipping this step.
 */
authorizationRoutes.post(
  '/batches/:id/release',
  requirePermissions('payment:release'),
  async (c) => {
    const actor = actorOf(c);
    const batchId = c.req.param('id');
    const body = releaseSchema.parse(await c.req.json());
    const correlationId = c.get('correlationId');

    // An idempotency key on the release endpoint means a double-clicked button or a retried
    // request cannot open a second release attempt.
    const idempotencyKey = c.req.header('Idempotency-Key');
    if (!isValidIdempotencyKey(idempotencyKey)) {
      throw validationError(
        'IDEMPOTENCY_KEY_REQUIRED',
        'Payment release requires an Idempotency-Key header of 16 to 255 characters',
      );
    }

    const outcome = await withConnection(c.env, async (sql) => {
      // ---- Verify the WebAuthn assertion over the ceremony challenge --------
      const challenges = await sql<
        { webauthn_challenge: string; authorizer_user_id: string; consumed_at: string | null }[]
      >`
      SELECT webauthn_challenge, authorizer_user_id, consumed_at
        FROM authorization_challenges
       WHERE id = ${body.challengeId} AND organization_id = ${actor.organizationId}
       LIMIT 1
    `;
      const challenge = challenges[0];
      if (!challenge) {
        throw notFoundError(
          'CHALLENGE_NOT_FOUND',
          'That authorization ceremony could not be found',
        );
      }
      if (challenge.authorizer_user_id !== actor.userId) {
        throw authenticationError(
          'CHALLENGE_ACTOR_MISMATCH',
          'This authorization ceremony was opened by a different user',
        );
      }

      const response = body.webauthnResponse as Record<string, unknown> & { id?: string };
      const credentialId = typeof response.id === 'string' ? response.id : '';

      const credentials = await sql<
        {
          id: string;
          credential_id: string;
          public_key: Uint8Array;
          signature_counter: string;
          transports: string[];
        }[]
      >`
      SELECT id, credential_id, public_key, signature_counter, transports
        FROM webauthn_credentials
       WHERE user_id = ${actor.userId} AND credential_id = ${credentialId} AND status = 'ACTIVE'
       LIMIT 1
    `;
      const credential = credentials[0];
      if (!credential) {
        throw authenticationError(
          'WEBAUTHN_CREDENTIAL_UNKNOWN',
          'That authenticator is not registered for payment authorization on this account',
        );
      }

      let verified = false;
      try {
        const verification = await verifyAuthenticationResponse({
          response: body.webauthnResponse as never,
          // The challenge is the manifest-bound digest issued by /begin, so the signature
          // is cryptographically tied to this exact payment set (spec 7.5).
          expectedChallenge: challenge.webauthn_challenge,
          expectedOrigin: c.env.APP_ORIGIN,
          expectedRPID: c.env.WEBAUTHN_RP_ID,
          requireUserVerification: true,
          credential: {
            id: credential.credential_id,
            publicKey: new Uint8Array(credential.public_key),
            counter: Number(credential.signature_counter),
            transports: credential.transports as never,
          },
        });
        verified = verification.verified;
        if (verified) {
          await sql`
          UPDATE webauthn_credentials
             SET signature_counter = ${verification.authenticationInfo.newCounter}, last_used_at = now()
           WHERE id = ${credential.id}
        `;
        }
      } catch {
        verified = false;
      }

      if (!verified) {
        await inTransaction(sql, (tx) =>
          writeAuditEvent(tx, {
            organizationId: actor.organizationId,
            actorId: actor.userId,
            actorLevel: actor.level,
            eventClass: 'SECURITY',
            action: 'payment.release.webauthn_rejected',
            objectType: 'PaymentBatch',
            objectId: batchId,
            outcome: 'DENIED',
            correlationId,
            securityContext: c.get('securityContext'),
            detail: { challengeId: body.challengeId },
          }),
        );
        throw authenticationError(
          'WEBAUTHN_SIGNATURE_INVALID',
          'The security key signature could not be verified. This attempt has been recorded.',
        );
      }

      // ---- Release ----------------------------------------------------------
      const released = await releaseBatch({
        sql,
        env: c.env,
        actor,
        batchId,
        challengeId: body.challengeId,
        webauthnVerified: true,
        webauthnCredentialId: credential.id,
        authorizationPin: body.authorizationPin,
        acknowledgements: body.acknowledgements,
        correlationId,
        securityContext: c.get('securityContext'),
      });

      // Execution is enqueued inside the release transaction (see releaseBatch), so there
      // is nothing to do here. Doing it from the route would reintroduce the window where
      // a batch is authorized but its payments were never queued.

      return released;
    });

    return c.json(
      {
        released: true,
        batchId: outcome.batchId,
        batchReference: outcome.batchReference,
        instructionsQueued: outcome.instructionsQueued,
        totalAmountCents: outcome.totalAmountCents,
        manifestHash: outcome.manifestHash,
        releasedAt: outcome.releasedAt,
        message: `KES ${formatCents(outcome.totalAmountCents)} released to ${outcome.instructionsQueued} recipients. Payments are now being submitted to M-PESA; follow their progress in Transactions.`,
      },
      202,
    );
  },
);

/** POST /authorization/batches/:id/abandon — close an open ceremony without releasing. */
authorizationRoutes.post(
  '/batches/:id/abandon',
  requirePermissions('payment:authorize'),
  async (c) => {
    const actor = actorOf(c);
    const batchId = c.req.param('id');
    const body = z
      .object({ reason: z.string().trim().max(500).optional() })
      .parse(await c.req.json().catch(() => ({})));

    await withConnection(c.env, (sql) =>
      abandonCeremony({
        sql,
        actor,
        batchId,
        reason: body.reason ?? 'Abandoned by the authorizer',
        correlationId: c.get('correlationId'),
        securityContext: c.get('securityContext'),
      }),
    );

    return c.json({ abandoned: true, state: 'L3_READY' });
  },
);
