/**
 * Payment executor: the queue consumer that submits authorized instructions to Daraja.
 *
 * The governing rule of this file is that **an unknown outcome is never resolved by
 * guessing**. Three states are possible after we attempt a submission:
 *
 *   - we know it was accepted  -> record SUBMITTED, wait for the callback;
 *   - we know it never left    -> record FAILED, safe to reissue as a new instruction;
 *   - we do not know           -> record TIMEOUT and open a reconciliation case.
 *
 * The third case is the one that matters. A worker that retries on "do not know" pays an
 * employee twice; a worker that gives up leaves them unpaid. Neither is acceptable, so the
 * outcome is established by querying the Transaction Status API, not by assumption
 * (spec 9.3, NFR-REL-002, NFR-REL-003).
 */

import {
  instructionFingerprint,
  decideOnExistingClaim,
  resolveFailure,
  assertTxnTransition,
  originatorConversationId,
  centsToDarajaAmount,
  SolvarenError,
  providerError,
  type IdempotencyRecord,
} from '@solvaren/core';
import { DarajaClient, type B2cCommandId } from '@solvaren/daraja';
import { withConnection, inTransaction, requireLock, type Sql } from '../db/client.js';
import { writeAuditEvent } from '../db/audit-writer.js';
import { loadDarajaClient } from '../services/daraja-config.js';
import { acquirePermit } from '../rate-limiter.js';
import { loadFailureOverrides } from '../services/failure-map.js';
import type { Env, PaymentQueueMessage, ReconciliationQueueMessage } from '../env.js';

/** Guards against an instruction being retried indefinitely by the queue. */
const MAX_EXECUTION_ATTEMPTS = 3;

export async function handlePaymentBatch(
  batch: MessageBatch<PaymentQueueMessage>,
  env: Env,
  ctx: ExecutionContext,
): Promise<void> {
  await withConnection(env, ctx, async (sql) => {
    for (const message of batch.messages) {
      try {
        await executeInstruction(sql, env, message.body);
        message.ack();
      } catch (err) {
        const solvaren = err instanceof SolvarenError ? err : null;

        // A state or policy error is deterministic: retrying changes nothing, so the
        // message is acked and the failure is already recorded on the transaction.
        if (solvaren && (solvaren.category === 'STATE' || solvaren.category === 'POLICY')) {
          console.warn(
            JSON.stringify({
              level: 'warn',
              message: 'Instruction execution refused; not retrying',
              code: solvaren.code,
              instructionId: message.body.instructionId,
              correlationId: message.body.correlationId,
            }),
          );
          message.ack();
          continue;
        }

        // A local throttle is not a failure of the payment; back off and try again
        // without counting it against the attempt budget.
        if (solvaren?.code === 'RATE_LIMIT_LOCAL') {
          const retryAfterMs = Number(solvaren.details?.retryAfterMs ?? 1000);
          message.retry({ delaySeconds: Math.max(1, Math.ceil(retryAfterMs / 1000)) });
          continue;
        }

        if (message.body.attempt >= MAX_EXECUTION_ATTEMPTS) {
          // Exhausted: dead-letter it and make the ambiguity explicit rather than silent.
          await markForReconciliation(
            sql,
            env,
            message.body,
            'SLV_SUBMIT_FAILED',
            'The payment could not be submitted after repeated attempts and its outcome is unknown',
          );
          message.ack();
          continue;
        }

        // Exponential backoff, capped: a Daraja spike-arrest response needs breathing room.
        message.retry({ delaySeconds: Math.min(300, 10 * 2 ** message.body.attempt) });
      }
    }
  });
}

/**
 * Execute one instruction.
 *
 * The idempotency claim is transitioned to SUBMITTED and committed *before* the HTTP call.
 * That ordering is deliberate and is the difference between a recoverable and an
 * unrecoverable failure: if the worker dies mid-call, the committed claim tells the next
 * worker "a request may have reached M-PESA — go and find out", instead of "nothing
 * happened, send it again".
 */
export async function executeInstruction(
  sql: Sql,
  env: Env,
  message: PaymentQueueMessage,
): Promise<void> {
  // Throttle before claiming anything. Exceeding the Daraja TPS contract returns
  // 500.003.03 for the whole burst, which would leave a run of payments in an ambiguous
  // state for no benefit — far better to wait our turn.
  const permit = await acquirePermit(env.RATE_LIMITER, message.organizationId);
  if (!permit.allowed) {
    throw providerError(
      'RATE_LIMIT_LOCAL',
      'Submission throttled to stay within the M-PESA rate contract',
      { retryAfterMs: permit.retryAfterMs },
    );
  }

  const context = await prepareSubmission(sql, env, message);
  if (context.skip) return;

  const { client, request, transactionId, instruction } = context;

  let ack: Awaited<ReturnType<DarajaClient['sendB2cPayment']>> | null = null;
  let submissionError: SolvarenError | null = null;

  try {
    ack = await client.sendB2cPayment(request);
  } catch (err) {
    submissionError = err instanceof SolvarenError ? err : null;
    if (!submissionError) throw err;
  }

  if (ack) {
    // Accepted. The real outcome arrives asynchronously on the ResultURL.
    await inTransaction(sql, async (tx) => {
      await tx`
        UPDATE transactions
           SET status = 'AWAITING_CALLBACK',
               conversation_id = ${ack.ConversationID ?? null},
               status_source = 'SYNC_ACK',
               submitted_at = now()
         WHERE id = ${transactionId} AND status = 'SUBMITTED'
      `;
      await tx`
        UPDATE payment_instructions SET status = 'AWAITING_CALLBACK' WHERE id = ${instruction.id}
      `;
      await writeAuditEvent(tx, {
        organizationId: message.organizationId,
        actorId: 'system:payment-executor',
        actorLevel: null,
        eventClass: 'INTEGRATION',
        action: 'daraja.b2c.accepted',
        objectType: 'Transaction',
        objectId: transactionId,
        outcome: 'SUCCESS',
        correlationId: message.correlationId,
        detail: {
          conversationId: ack.ConversationID,
          originatorConversationId: request.OriginatorConversationID,
          amountCents: instruction.amount_cents,
        },
      });
    });
    return;
  }

  // ---- Submission failed. Was it before or after M-PESA saw it? -----------
  const error = submissionError!;
  const providerCode = (error.details?.errorCode as string | undefined) ?? null;

  // These mean the request may well have been processed. Never conclude failure.
  const ambiguous =
    error.code === 'DARAJA_TIMEOUT' ||
    error.code === 'DARAJA_UNREACHABLE' ||
    providerCode === '500.002.1001' || // duplicate originator id — the first one may have paid
    providerCode === '500.003.1001' ||
    providerCode === '500.001.1001' ||
    (typeof error.details?.httpStatus === 'number' && error.details.httpStatus >= 500);

  if (ambiguous) {
    await markForReconciliation(
      sql,
      env,
      message,
      providerCode === '500.002.1001' ? '500.002.1001' : 'SLV_TIMEOUT',
      error.message,
    );
    return;
  }

  // A clean rejection: M-PESA refused the request itself, so no money moved.
  const overrides = await loadFailureOverrides(sql, message.organizationId);
  const resolved = resolveFailure(providerCode ?? 'SLV_SUBMIT_FAILED', error.message, overrides);

  await inTransaction(sql, async (tx) => {
    assertTxnTransition({
      from: 'SUBMITTED',
      to: 'FAILED',
      source: 'SYNC_ACK',
      failureCode: resolved.failureCode,
    });
    await tx`
      UPDATE transactions
         SET status = 'FAILED',
             failure_code = ${resolved.failureCode},
             failure_reason = ${resolved.failureReason},
             failure_class = ${resolved.failureClass},
             provider_result_description = ${error.message},
             status_source = 'SYNC_ACK',
             completed_at = now()
       WHERE id = ${transactionId}
    `;
    await tx`UPDATE payment_instructions SET status = 'FAILED' WHERE id = ${instruction.id}`;
    await tx`
      UPDATE idempotency_claims SET state = 'SETTLED', updated_at = now()
       WHERE instruction_id = ${instruction.id}
    `;
    await writeAuditEvent(tx, {
      organizationId: message.organizationId,
      actorId: 'system:payment-executor',
      actorLevel: null,
      eventClass: 'INTEGRATION',
      action: 'daraja.b2c.rejected',
      objectType: 'Transaction',
      objectId: transactionId,
      outcome: 'FAILURE',
      correlationId: message.correlationId,
      detail: {
        failureCode: resolved.failureCode,
        failureReason: resolved.failureReason,
        failureClass: resolved.failureClass,
      },
    });
  });

  await maybeSettleBatch(sql, env, message.organizationId, message.batchId, message.correlationId);
}

interface SubmissionContext {
  skip: boolean;
  client: DarajaClient;
  request: {
    OriginatorConversationID: string;
    InitiatorName: string;
    SecurityCredential: string;
    CommandID: B2cCommandId;
    Amount: string;
    PartyA: string;
    PartyB: string;
    Remarks: string;
    QueueTimeOutURL: string;
    ResultURL: string;
    Occassion?: string;
  };
  transactionId: string;
  instruction: { id: string; amount_cents: string; msisdn_snapshot: string };
}

/**
 * Verify the message against live state, claim idempotency, and create the transaction row.
 *
 * Committed before the provider call, so the claim survives a worker death.
 */
async function prepareSubmission(
  sql: Sql,
  env: Env,
  message: PaymentQueueMessage,
): Promise<SubmissionContext> {
  const prepared = await inTransaction(sql, async (tx) => {
    await requireLock(tx, 'instruction', message.instructionId);

    const rows = await tx<
      {
        id: string;
        amount_cents: string;
        msisdn_snapshot: string;
        remarks: string;
        occasion: string | null;
        status: string;
        batch_state: string;
        batch_version: number;
      }[]
    >`
      SELECT pi.id, pi.amount_cents, pi.msisdn_snapshot, pi.remarks, pi.occasion, pi.status,
             b.state AS batch_state, b.version AS batch_version
        FROM payment_instructions pi
        JOIN payment_batches b ON b.id = pi.batch_id
       WHERE pi.id = ${message.instructionId}
         AND pi.organization_id = ${message.organizationId}
       FOR UPDATE OF pi
    `;
    const instruction = rows[0];
    if (!instruction) return { skip: true as const };

    // The batch must still be in an execution state. A cancelled or held batch whose
    // message is still on the queue must not pay.
    if (!['AUTHORIZED', 'QUEUED', 'SUBMITTED', 'PROCESSING'].includes(instruction.batch_state)) {
      return { skip: true as const };
    }

    // The message carries the batch version it was authorized under. If the batch has been
    // edited since, this message describes a payment that is no longer authorized.
    if (instruction.batch_version !== message.batchVersion) {
      return { skip: true as const };
    }

    // Re-derive the fingerprint and compare with the one in the message: a message whose
    // fields were altered in transit does not match and is refused.
    const fingerprint = await instructionFingerprint({
      organizationId: message.organizationId,
      batchId: message.batchId,
      instructionId: instruction.id,
      batchVersion: message.batchVersion,
      msisdn: instruction.msisdn_snapshot,
      amountCents: Number(instruction.amount_cents),
      manifestHash: message.manifestHash,
    });
    if (fingerprint !== message.fingerprint) {
      await writeAuditEvent(tx, {
        organizationId: message.organizationId,
        actorId: 'system:payment-executor',
        actorLevel: null,
        eventClass: 'SECURITY',
        action: 'payment.execution.fingerprint_mismatch',
        objectType: 'PaymentInstruction',
        objectId: instruction.id,
        outcome: 'DENIED',
        correlationId: message.correlationId,
        detail: { expected: fingerprint, received: message.fingerprint },
      });
      return { skip: true as const };
    }

    // ---- Idempotency -----------------------------------------------------
    const claims = await tx<
      {
        fingerprint: string;
        state: IdempotencyRecord['state'];
        originator_conversation_id: string | null;
        claimed_at: string;
        updated_at: string;
      }[]
    >`
      SELECT fingerprint, state, originator_conversation_id, claimed_at, updated_at
        FROM idempotency_claims
       WHERE instruction_id = ${instruction.id}
       FOR UPDATE
    `;
    const claim = claims[0];
    const decision = decideOnExistingClaim(
      claim
        ? {
            fingerprint: claim.fingerprint,
            state: claim.state,
            originatorConversationId: claim.originator_conversation_id,
            transactionId: null,
            claimedAt: new Date(claim.claimed_at).getTime(),
            updatedAt: new Date(claim.updated_at).getTime(),
          }
        : null,
    );

    if (decision.action === 'SKIP_ALREADY_SETTLED') return { skip: true as const };

    if (decision.action === 'RECONCILE_FIRST') {
      // A request already went to M-PESA and we never learned the outcome. Establish it
      // by query; do not send another.
      return { skip: true as const, reconcile: true as const, reason: decision.reason };
    }

    // ---- Create the transaction row -------------------------------------
    const config = await tx<{ short_code: string }[]>`
      SELECT short_code FROM daraja_configurations
       WHERE organization_id = ${message.organizationId} AND status = 'ENABLED'
       LIMIT 1
    `;
    if (!config[0]) {
      await tx`
        UPDATE transactions SET status = 'FAILED',
               failure_code = 'SLV_INTEGRATION_DISABLED',
               failure_reason = 'The Daraja integration was disabled before this instruction could be submitted',
               failure_class = 'CREDENTIAL', status_source = 'SYSTEM', completed_at = now()
         WHERE instruction_id = ${instruction.id} AND status NOT IN ('SUCCESS', 'FAILED')
      `;
      return { skip: true as const };
    }

    const originatorId = originatorConversationId(config[0].short_code, instruction.id);

    const inserted = await tx<{ id: string }[]>`
      INSERT INTO transactions (
        organization_id, instruction_id, batch_id, status, originator_conversation_id,
        request_fingerprint, amount_cents, status_source, submitted_at
      ) VALUES (
        ${message.organizationId}, ${instruction.id}, ${message.batchId}, 'SUBMITTED',
        ${originatorId}, ${fingerprint}, ${Number(instruction.amount_cents)}, 'SYSTEM', now()
      )
      ON CONFLICT (originator_conversation_id) DO NOTHING
      RETURNING id
    `;
    if (!inserted[0]) return { skip: true as const };

    await tx`
      UPDATE idempotency_claims
         SET state = 'SUBMITTED', originator_conversation_id = ${originatorId}, updated_at = now()
       WHERE instruction_id = ${instruction.id}
    `;
    await tx`UPDATE payment_instructions SET status = 'SUBMITTED' WHERE id = ${instruction.id}`;
    await tx`
      UPDATE payment_batches SET state = 'PROCESSING'
       WHERE id = ${message.batchId} AND state IN ('AUTHORIZED', 'QUEUED', 'SUBMITTED')
    `;

    return {
      skip: false as const,
      transactionId: inserted[0].id,
      originatorId,
      instruction,
    };
  });

  if (prepared.skip) {
    if ('reconcile' in prepared && prepared.reconcile) {
      await enqueueReconciliation(env, message, prepared.reason);
    }
    return { skip: true } as SubmissionContext;
  }

  // ---- Build the provider request (outside the transaction) ---------------
  const { client, credentials, config } = await loadDarajaClient(sql, env, message.organizationId);

  return {
    skip: false,
    client,
    transactionId: prepared.transactionId,
    instruction: prepared.instruction,
    request: {
      OriginatorConversationID: prepared.originatorId,
      InitiatorName: credentials.initiatorName,
      SecurityCredential: credentials.securityCredential,
      CommandID: config.commandId,
      Amount: centsToDarajaAmount(Number(prepared.instruction.amount_cents)),
      PartyA: credentials.shortCode,
      PartyB: prepared.instruction.msisdn_snapshot,
      Remarks: prepared.instruction.remarks.slice(0, 100),
      QueueTimeOutURL: config.queueTimeoutUrl,
      ResultURL: config.resultUrl,
      ...(prepared.instruction.occasion
        ? { Occassion: prepared.instruction.occasion.slice(0, 100) }
        : {}),
    },
  };
}

/**
 * Move a transaction into TIMEOUT and open a reconciliation case.
 * Used whenever the provider outcome is unknown — never as a shortcut for "failed".
 */
async function markForReconciliation(
  sql: Sql,
  env: Env,
  message: PaymentQueueMessage,
  failureCode: string,
  detail: string,
): Promise<void> {
  const overrides = await loadFailureOverrides(sql, message.organizationId);
  const resolved = resolveFailure(failureCode, detail, overrides);

  await inTransaction(sql, async (tx) => {
    const rows = await tx<{ id: string; status: string }[]>`
      SELECT id, status FROM transactions
       WHERE instruction_id = ${message.instructionId}
       ORDER BY created_at DESC LIMIT 1
      FOR UPDATE
    `;
    const transaction = rows[0];
    if (!transaction) return;
    if (['SUCCESS', 'FAILED', 'CANCELLED'].includes(transaction.status)) return;

    await tx`
      UPDATE transactions
         SET status = 'TIMEOUT',
             failure_code = ${resolved.failureCode},
             failure_reason = ${resolved.failureReason},
             failure_class = ${resolved.failureClass},
             provider_result_description = ${detail},
             status_source = 'SYSTEM'
       WHERE id = ${transaction.id}
    `;
    await tx`UPDATE payment_instructions SET status = 'TIMEOUT' WHERE id = ${message.instructionId}`;

    await tx`
      INSERT INTO reconciliation_cases (
        organization_id, transaction_id, case_reference, state, opened_reason, next_query_at
      ) VALUES (
        ${message.organizationId}, ${transaction.id},
        ${'REC-' + transaction.id.slice(0, 8).toUpperCase()}, 'OPEN', ${detail},
        now() + interval '2 minutes'
      )
      ON CONFLICT DO NOTHING
    `;

    await writeAuditEvent(tx, {
      organizationId: message.organizationId,
      actorId: 'system:payment-executor',
      actorLevel: null,
      eventClass: 'INTEGRATION',
      action: 'daraja.b2c.outcome_unknown',
      objectType: 'Transaction',
      objectId: transaction.id,
      outcome: 'FAILURE',
      correlationId: message.correlationId,
      detail: {
        failureCode: resolved.failureCode,
        note: 'Outcome unknown; reconciliation opened. No resubmission will occur.',
      },
    });
  });

  await enqueueReconciliation(env, message, detail);
}

async function enqueueReconciliation(
  env: Env,
  message: PaymentQueueMessage,
  reason: string,
): Promise<void> {
  const payload: ReconciliationQueueMessage = {
    type: 'RECONCILE_TRANSACTION',
    organizationId: message.organizationId,
    correlationId: message.correlationId,
  };
  await env.RECONCILIATION_QUEUE.send(payload, { delaySeconds: 120 });
  console.info(
    JSON.stringify({
      level: 'info',
      message: 'Reconciliation enqueued rather than resubmitting',
      instructionId: message.instructionId,
      reason,
      correlationId: message.correlationId,
    }),
  );
}

/**
 * Settle the batch once every instruction has reached a terminal state.
 * A batch with any failure settles PARTIAL_SUCCESS, never SUCCESS — a roll-up that reads
 * "success" while three people went unpaid is the exact invisibility spec 6 forbids.
 */
export async function maybeSettleBatch(
  sql: Sql,
  _env: Env,
  organizationId: string,
  batchId: string,
  correlationId: string,
): Promise<void> {
  await inTransaction(sql, async (tx) => {
    await requireLock(tx, 'batch', batchId);

    const rows = await tx<
      {
        state: string;
        total: string;
        success: string;
        failed: string;
        timeout: string;
        in_flight: string;
      }[]
    >`
      SELECT b.state,
             COUNT(t.id) AS total,
             COUNT(t.id) FILTER (WHERE t.status = 'SUCCESS')  AS success,
             COUNT(t.id) FILTER (WHERE t.status = 'FAILED')   AS failed,
             COUNT(t.id) FILTER (WHERE t.status = 'TIMEOUT')  AS timeout,
             COUNT(t.id) FILTER (WHERE t.status IN ('PENDING','SUBMITTED','AWAITING_CALLBACK','PROCESSING','RECONCILING')) AS in_flight
        FROM payment_batches b
        LEFT JOIN transactions t ON t.batch_id = b.id
       WHERE b.id = ${batchId} AND b.organization_id = ${organizationId}
       GROUP BY b.state
    `;
    const summary = rows[0];
    if (!summary || summary.state !== 'PROCESSING') return;

    const instructionCount = await tx<{ count: string }[]>`
      SELECT COUNT(*) AS count FROM payment_instructions WHERE batch_id = ${batchId}
    `;
    const expected = Number(instructionCount[0]?.count ?? 0);
    const seen = Number(summary.total);
    const inFlight = Number(summary.in_flight);

    // Not every instruction has a transaction yet, or some are still moving.
    if (seen < expected || inFlight > 0) return;

    const success = Number(summary.success);
    const failed = Number(summary.failed);
    const timeout = Number(summary.timeout);

    // Anything unresolved keeps the batch in TIMEOUT, where the operator can see it.
    const nextState =
      timeout > 0
        ? 'TIMEOUT'
        : failed === 0
          ? 'SUCCESS'
          : success === 0
            ? 'FAILED'
            : 'PARTIAL_SUCCESS';

    await tx`
      UPDATE payment_batches SET state = ${nextState}, settled_at = now()
       WHERE id = ${batchId} AND state = 'PROCESSING'
    `;

    await writeAuditEvent(tx, {
      organizationId,
      actorId: 'system:payment-executor',
      actorLevel: null,
      eventClass: 'PAYMENT',
      action: 'payment.batch.settled',
      objectType: 'PaymentBatch',
      objectId: batchId,
      outcome: failed > 0 || timeout > 0 ? 'FAILURE' : 'SUCCESS',
      previousState: { state: 'PROCESSING' },
      newState: { state: nextState },
      correlationId,
      detail: { success, failed, timeout, total: seen },
    });
  });
}
