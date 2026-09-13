/**
 * Daraja callback ingress (spec 9.4).
 *
 * This is the only unauthenticated-by-session route in the platform, which makes it the
 * most exposed surface SOLVAREN has. It is therefore deliberately the *dumbest* route:
 * authenticate, persist the raw body, enqueue, return 200. It makes no state decisions,
 * touches no ledger row, and cannot create a transaction.
 *
 * Defences, in order of application:
 *
 *  1. **Path-scoped organisation.** The organisation comes from the URL, not the payload,
 *     so a forged body cannot direct a result at another tenant.
 *  2. **Shared-secret authentication.** A per-organisation secret in the path segment,
 *     compared in constant time. Cloudflare WAF additionally restricts this route to
 *     Safaricom's published source ranges (see infra/terraform).
 *  3. **Replay protection by content digest.** Identical bodies are recognised and
 *     recorded as duplicates instead of reprocessed (spec 23).
 *  4. **Size limit before parse**, so an oversized body cannot exhaust the isolate.
 *  5. **Always 200.** Daraja does not retry, so a 500 from us loses the result permanently;
 *     the body is already stored, and our own processing failure is our problem to fix.
 */

import { Hono, type Context } from 'hono';
import { resultCallbackSchema } from '@solvaren/daraja';
import { stableStringify } from '@solvaren/core';
import { withConnection, inTransaction } from '../db/client.js';
import { writeAuditEvent } from '../db/audit-writer.js';
import { loadCallbackSecret } from '../services/daraja-config.js';
import { timingSafeEqual, sha256Base64Url } from '../services/crypto.js';
import type { AppContext, CallbackQueueMessage } from '../env.js';

export const callbackRoutes = new Hono<AppContext>();

/** Daraja result bodies are small; anything larger is not a legitimate callback. */
const MAX_CALLBACK_BYTES = 64 * 1024;

type CallbackKind = 'B2C_RESULT' | 'B2C_TIMEOUT' | 'TRANSACTION_STATUS' | 'ACCOUNT_BALANCE';

/**
 * A single handler behind four paths. Splitting by path rather than by payload content
 * means we never have to infer the callback type from attacker-influenced data.
 */
/** Always-200 acknowledgement. Daraja performs no retries, so we never signal failure. */
const ACK = { ResultCode: 0, ResultDesc: 'Accepted' } as const;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

async function ingest(c: Context<AppContext>, kind: CallbackKind): Promise<Response> {
  const organizationId = c.req.param('organizationId') ?? '';
  const presentedSecret = c.req.param('secret') ?? c.req.header('X-Solvaren-Callback-Token') ?? '';
  const correlationId = c.get('correlationId');

  // Validate the shape before it reaches a query. A malformed organisation id cannot
  // match anything, and rejecting it here keeps junk out of the security-event table.
  if (!UUID_PATTERN.test(organizationId)) {
    return c.json(ACK, 200);
  }

  // ---- Size, before parsing ------------------------------------------------
  const declaredLength = Number(c.req.header('Content-Length') ?? '0');
  if (declaredLength > MAX_CALLBACK_BYTES) {
    return c.json(ACK, 200);
  }

  const rawBody = await c.req.text();
  if (rawBody.length > MAX_CALLBACK_BYTES) {
    return c.json(ACK, 200);
  }

  await withConnection(c.env, c.executionCtx, async (sql) => {
    // ---- Authenticate ------------------------------------------------------
    const expectedSecret = await loadCallbackSecret(sql, c.env, organizationId);
    const globalSecret = c.env.CALLBACK_SHARED_SECRET;

    const authenticated =
      (expectedSecret !== null && timingSafeEqual(presentedSecret, expectedSecret)) ||
      (globalSecret !== undefined && timingSafeEqual(presentedSecret, globalSecret));

    if (!authenticated) {
      // Recorded as a security event, not as a callback. Nothing is enqueued.
      await inTransaction(sql, async (tx) => {
        await tx`
          INSERT INTO security_events (organization_id, event_type, severity, description, ip, detail)
          VALUES (
            ${organizationId}, 'CALLBACK_AUTH_FAILED', 'CRITICAL',
            ${'A provider callback was received with an invalid or missing shared secret'},
            ${c.get('securityContext').ip},
            ${tx.json({ kind, bodyBytes: rawBody.length })}
          )
        `;
      }).catch(() => {
        // An unknown organisation id has no row to attach the event to; the WAF logs it.
      });
      // Deliberately indistinguishable from success: an attacker probing the endpoint
      // learns nothing about whether the organisation or the secret was wrong.
      return;
    }

    // ---- Parse -------------------------------------------------------------
    let payload: unknown;
    try {
      payload = JSON.parse(rawBody);
    } catch {
      await inTransaction(sql, async (tx) => {
        await tx`
          INSERT INTO security_events (organization_id, event_type, severity, description, ip, detail)
          VALUES (${organizationId}, 'CALLBACK_MALFORMED', 'WARNING',
                  ${'A provider callback body was not valid JSON'}, ${c.get('securityContext').ip},
                  ${tx.json({ kind })})
        `;
      });
      return;
    }

    const parsed = resultCallbackSchema.safeParse(payload);
    if (!parsed.success) {
      const rejectedDigest = await sha256Base64Url(rawBody);
      await inTransaction(sql, async (tx) => {
        await tx`
          INSERT INTO provider_callbacks (
            organization_id, callback_type, payload_digest, raw_payload, source_ip,
            processed_at, processing_outcome, processing_note
          ) VALUES (
            ${organizationId}, ${kind}, ${rejectedDigest},
            ${tx.json(payload as never)}, ${c.get('securityContext').ip}, now(), 'REJECTED',
            ${'The callback did not match the expected Daraja Result envelope'}
          )
          ON CONFLICT (payload_digest) DO NOTHING
        `;
      });
      return;
    }

    // ---- Persist and enqueue ------------------------------------------------
    // The digest covers the canonical form of the parsed body, so a re-delivery with
    // different whitespace is still recognised as the same message.
    const digest = await sha256Base64Url(stableStringify(payload));
    const result = parsed.data.Result;

    const inserted = await sql<{ id: string }[]>`
      INSERT INTO provider_callbacks (
        organization_id, callback_type, originator_conversation_id, conversation_id,
        result_code, payload_digest, raw_payload, source_ip
      ) VALUES (
        ${organizationId}, ${kind}, ${result.OriginatorConversationID ?? null},
        ${result.ConversationID ?? null}, ${String(result.ResultCode)}, ${digest},
        ${sql.json(payload as never)}, ${c.get('securityContext').ip}
      )
      ON CONFLICT (payload_digest) DO NOTHING
      RETURNING id
    `;

    if (!inserted[0]) {
      // Exact duplicate delivery. Recorded on the original row; nothing reprocessed.
      await sql`
        UPDATE provider_callbacks
           SET processing_note = COALESCE(processing_note, '') || ' | duplicate re-delivery ' || now()::text
         WHERE payload_digest = ${digest}
      `;
      return;
    }

    const callbackId = inserted[0].id;
    const message: CallbackQueueMessage = {
      type: 'PROCESS_CALLBACK',
      callbackId,
      organizationId,
      callbackType: kind,
      correlationId,
    };
    await c.env.CALLBACK_QUEUE.send(message);

    await inTransaction(sql, (tx) =>
      writeAuditEvent(tx, {
        organizationId,
        actorId: 'system:daraja',
        actorLevel: null,
        eventClass: 'INTEGRATION',
        action: 'daraja.callback.received',
        objectType: 'ProviderCallback',
        objectId: callbackId,
        outcome: 'SUCCESS',
        correlationId,
        securityContext: c.get('securityContext'),
        detail: {
          kind,
          resultCode: String(result.ResultCode),
          originatorConversationId: result.OriginatorConversationID,
        },
      }),
    );
  });

  // Always acknowledge. Daraja performs no retries, so a non-200 loses the result forever.
  return c.json(ACK, 200);
}

callbackRoutes.post('/daraja/callback/:organizationId/:secret', (c) => ingest(c, 'B2C_RESULT'));
callbackRoutes.post('/daraja/timeout/:organizationId/:secret', (c) => ingest(c, 'B2C_TIMEOUT'));
callbackRoutes.post('/daraja/status-callback/:organizationId/:secret', (c) =>
  ingest(c, 'TRANSACTION_STATUS'),
);
callbackRoutes.post('/daraja/balance-callback/:organizationId/:secret', (c) =>
  ingest(c, 'ACCOUNT_BALANCE'),
);
