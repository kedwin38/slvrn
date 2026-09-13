/**
 * Provider callback processing (spec 9.4, 6.1).
 *
 * The ingress route does the minimum — authenticate, persist the raw body, enqueue — and
 * this consumer does the interpretation. That split matters: Daraja does not retry a
 * callback it failed to deliver, so the endpoint must return 200 quickly and must never
 * fail because of a downstream problem in our own processing.
 *
 * Duplicate handling is explicit. Daraja can re-deliver, and a replayed callback is also an
 * attack (spec 23: "Submit duplicate callback payloads and confirm transaction state
 * remains correct"). Each payload is deduplicated by digest, and a callback that agrees
 * with an already-settled transaction is recorded as a duplicate rather than reapplied.
 */

import {
  parseB2cResult,
  parseTransactionStatusResult,
  parseAccountBalanceResult,
  interpretTransactionStatus,
} from '@solvaren/daraja';
import { assertTxnTransition, resolveFailure, type TxnState } from '@solvaren/core';
import { withConnection, inTransaction, requireLock, type Sql } from '../db/client.js';
import { writeAuditEvent } from '../db/audit-writer.js';
import { loadFailureOverrides } from '../services/failure-map.js';
import { maybeSettleBatch } from './payment-executor.js';
import type { CallbackQueueMessage, Env } from '../env.js';

export async function handleCallbackBatch(
  batch: MessageBatch<CallbackQueueMessage>,
  env: Env,
  ctx: ExecutionContext,
): Promise<void> {
  await withConnection(env, ctx, async (sql) => {
    for (const message of batch.messages) {
      try {
        await processCallback(sql, env, message.body);
        message.ack();
      } catch (err) {
        console.error(
          JSON.stringify({
            level: 'error',
            message: 'Callback processing failed',
            callbackId: message.body.callbackId,
            correlationId: message.body.correlationId,
            error: err instanceof Error ? err.message : String(err),
          }),
        );
        // The raw payload is already persisted, so a retry re-reads it rather than losing it.
        message.retry({ delaySeconds: 30 });
      }
    }
  });
}

export async function processCallback(
  sql: Sql,
  env: Env,
  message: CallbackQueueMessage,
): Promise<void> {
  const rows = await sql<
    { id: string; callback_type: string; raw_payload: unknown; processed_at: string | null }[]
  >`
    SELECT id, callback_type, raw_payload, processed_at
      FROM provider_callbacks
     WHERE id = ${message.callbackId} AND organization_id = ${message.organizationId}
     LIMIT 1
  `;
  const callback = rows[0];
  if (!callback) return;
  if (callback.processed_at) return; // already handled; a queue redelivery

  switch (callback.callback_type) {
    case 'B2C_RESULT':
    case 'B2C_TIMEOUT':
      await applyB2cResult(sql, env, message, callback.raw_payload, callback.callback_type === 'B2C_TIMEOUT');
      break;
    case 'TRANSACTION_STATUS':
      await applyTransactionStatus(sql, env, message, callback.raw_payload);
      break;
    case 'ACCOUNT_BALANCE':
      await applyAccountBalance(sql, message, callback.raw_payload);
      break;
  }
}

/** Apply a B2C ResultURL or QueueTimeOutURL delivery. */
async function applyB2cResult(
  sql: Sql,
  env: Env,
  message: CallbackQueueMessage,
  payload: unknown,
  isQueueTimeout: boolean,
): Promise<void> {
  const parsed = parseB2cResult(payload);
  const overrides = await loadFailureOverrides(sql, message.organizationId);

  let batchId: string | null = null;

  await inTransaction(sql, async (tx) => {
    // Match on OriginatorConversationID — our own identifier, generated per submission,
    // and the only field in the callback we know cannot have been chosen by someone else.
    const transactions = await tx<
      { id: string; batch_id: string; instruction_id: string; status: TxnState }[]
    >`
      SELECT id, batch_id, instruction_id, status
        FROM transactions
       WHERE organization_id = ${message.organizationId}
         AND originator_conversation_id = ${parsed.originatorConversationId}
       FOR UPDATE
    `;
    const transaction = transactions[0];

    if (!transaction) {
      // A callback we cannot match is retained as evidence and surfaced to operators.
      // It is never used to create a transaction: that would let anyone who can reach the
      // endpoint invent a payment record.
      await tx`
        UPDATE provider_callbacks
           SET processed_at = now(), processing_outcome = 'UNMATCHED',
               processing_note = ${'No transaction matches this OriginatorConversationID'}
         WHERE id = ${message.callbackId}
      `;
      await writeAuditEvent(tx, {
        organizationId: message.organizationId,
        actorId: 'system:callback-processor',
        actorLevel: null,
        eventClass: 'SECURITY',
        action: 'daraja.callback.unmatched',
        objectType: 'ProviderCallback',
        objectId: message.callbackId,
        outcome: 'FAILURE',
        correlationId: message.correlationId,
        detail: {
          originatorConversationId: parsed.originatorConversationId,
          resultCode: parsed.resultCode,
        },
      });
      return;
    }

    batchId = transaction.batch_id;
    await requireLock(tx, 'transaction', transaction.id);

    // ---- Already settled? -------------------------------------------------
    if (['SUCCESS', 'FAILED', 'CANCELLED'].includes(transaction.status)) {
      const agrees =
        (transaction.status === 'SUCCESS' && parsed.succeeded) ||
        (transaction.status === 'FAILED' && !parsed.succeeded);

      await tx`
        UPDATE provider_callbacks
           SET processed_at = now(), transaction_id = ${transaction.id},
               processing_outcome = ${agrees ? 'DUPLICATE' : 'IGNORED_SETTLED'},
               processing_note = ${
                 agrees
                   ? 'Duplicate delivery of an outcome already recorded'
                   : 'Callback contradicts a settled outcome; reconciliation case opened'
               }
         WHERE id = ${message.callbackId}
      `;

      if (!agrees) {
        // The ledger is not rewritten. A human decides what actually happened.
        await tx`
          INSERT INTO reconciliation_cases (
            organization_id, transaction_id, case_reference, state, opened_reason, discrepancy
          ) VALUES (
            ${message.organizationId}, ${transaction.id},
            ${'REC-' + transaction.id.slice(0, 8).toUpperCase()}, 'OPEN',
            ${`A provider callback reported result code ${parsed.resultCode} for a transaction already settled as ${transaction.status}`},
            TRUE
          )
          ON CONFLICT DO NOTHING
        `;
        await writeAuditEvent(tx, {
          organizationId: message.organizationId,
          actorId: 'system:callback-processor',
          actorLevel: null,
          eventClass: 'INTEGRATION',
          action: 'daraja.callback.contradicts_settled',
          objectType: 'Transaction',
          objectId: transaction.id,
          outcome: 'FAILURE',
          correlationId: message.correlationId,
          detail: {
            recordedStatus: transaction.status,
            callbackResultCode: parsed.resultCode,
            note: 'The ledger was NOT modified. A reconciliation case was opened for human review.',
          },
        });
      }
      return;
    }

    // ---- Apply the outcome ------------------------------------------------
    const targetStatus: TxnState = parsed.succeeded
      ? 'SUCCESS'
      : isQueueTimeout
        ? 'TIMEOUT'
        : 'FAILED';

    const resolved = parsed.succeeded
      ? null
      : resolveFailure(
          isQueueTimeout ? 'SLV_QUEUE_TIMEOUT' : parsed.resultCode,
          parsed.resultDescription,
          overrides,
        );

    assertTxnTransition({
      from: transaction.status,
      to: targetStatus,
      source: isQueueTimeout ? 'QUEUE_TIMEOUT' : 'CALLBACK',
      providerReceipt: parsed.transactionReceipt,
      failureCode: resolved?.failureCode ?? null,
    });

    await tx`
      UPDATE transactions
         SET status = ${targetStatus},
             conversation_id = COALESCE(${parsed.conversationId}, conversation_id),
             mpesa_receipt_number = COALESCE(${parsed.transactionReceipt}, mpesa_receipt_number),
             failure_code = ${resolved?.failureCode ?? null},
             failure_reason = ${resolved?.failureReason ?? null},
             failure_class = ${resolved?.failureClass ?? null},
             provider_result_description = ${parsed.resultDescription || null},
             status_source = ${isQueueTimeout ? 'QUEUE_TIMEOUT' : 'CALLBACK'},
             completed_at = ${targetStatus === 'TIMEOUT' ? null : (parsed.completedAt ?? new Date().toISOString())},
             last_status_check_at = now()
       WHERE id = ${transaction.id}
    `;

    await tx`
      UPDATE payment_instructions SET status = ${targetStatus} WHERE id = ${transaction.instruction_id}
    `;

    await tx`
      UPDATE idempotency_claims
         SET state = ${targetStatus === 'TIMEOUT' ? 'SUBMITTED' : 'SETTLED'}, updated_at = now()
       WHERE instruction_id = ${transaction.instruction_id}
    `;

    if (targetStatus === 'TIMEOUT') {
      await tx`
        INSERT INTO reconciliation_cases (
          organization_id, transaction_id, case_reference, state, opened_reason, next_query_at
        ) VALUES (
          ${message.organizationId}, ${transaction.id},
          ${'REC-' + transaction.id.slice(0, 8).toUpperCase()}, 'OPEN',
          ${'M-PESA reported the request timed out while queued'}, now() + interval '5 minutes'
        )
        ON CONFLICT DO NOTHING
      `;
    }

    // Balance figures ride along on a successful B2C callback — free, live, and exactly
    // what the L3 balance panel needs, without spending an Account Balance API call.
    if (parsed.utilityAccountBalanceCents !== null) {
      const asOf = parsed.completedAt ?? new Date().toISOString();
      for (const [accountType, cents] of [
        ['Utility Account', parsed.utilityAccountBalanceCents],
        ['Working Account', parsed.workingAccountBalanceCents],
        ['Charges Paid Account', parsed.chargesPaidAccountBalanceCents],
      ] as const) {
        if (cents === null) continue;
        await tx`
          INSERT INTO account_balance_snapshots
            (organization_id, account_type, available_cents, as_of, source)
          VALUES (${message.organizationId}, ${accountType}, ${cents}, ${asOf}, 'CALLBACK')
        `;
      }
    }

    await tx`
      UPDATE provider_callbacks
         SET processed_at = now(), transaction_id = ${transaction.id},
             processing_outcome = 'APPLIED', result_code = ${parsed.resultCode}
       WHERE id = ${message.callbackId}
    `;

    await writeAuditEvent(tx, {
      organizationId: message.organizationId,
      actorId: 'system:callback-processor',
      actorLevel: null,
      eventClass: 'INTEGRATION',
      action: parsed.succeeded ? 'daraja.callback.success' : 'daraja.callback.failure',
      objectType: 'Transaction',
      objectId: transaction.id,
      outcome: parsed.succeeded ? 'SUCCESS' : 'FAILURE',
      previousState: { status: transaction.status },
      newState: { status: targetStatus },
      correlationId: message.correlationId,
      detail: {
        resultCode: parsed.resultCode,
        receipt: parsed.transactionReceipt,
        failureCode: resolved?.failureCode,
        failureReason: resolved?.failureReason,
      },
    });
  });

  if (batchId) {
    await maybeSettleBatch(sql, env, message.organizationId, batchId, message.correlationId);
  }
}

/** Apply a Transaction Status API result (reconciliation sweep or on-demand refresh). */
async function applyTransactionStatus(
  sql: Sql,
  env: Env,
  message: CallbackQueueMessage,
  payload: unknown,
): Promise<void> {
  const parsed = parseTransactionStatusResult(payload);
  const outcome = interpretTransactionStatus(parsed.transactionStatus);
  const overrides = await loadFailureOverrides(sql, message.organizationId);
  let batchId: string | null = null;

  await inTransaction(sql, async (tx) => {
    const transactions = await tx<
      { id: string; batch_id: string; instruction_id: string; status: TxnState }[]
    >`
      SELECT id, batch_id, instruction_id, status
        FROM transactions
       WHERE organization_id = ${message.organizationId}
         AND (originator_conversation_id = ${parsed.originatorConversationId}
              OR mpesa_receipt_number = ${parsed.receiptNumber})
       FOR UPDATE
    `;
    const transaction = transactions[0];
    if (!transaction) {
      await tx`
        UPDATE provider_callbacks SET processed_at = now(), processing_outcome = 'UNMATCHED'
         WHERE id = ${message.callbackId}
      `;
      return;
    }
    batchId = transaction.batch_id;

    await tx`
      UPDATE transactions
         SET last_status_check_at = now(), status_check_count = status_check_count + 1
       WHERE id = ${transaction.id}
    `;

    // A settled transaction is never rewritten by a status query. Disagreement becomes a
    // discrepancy case (spec 4.3: historical transaction records are not alterable).
    if (['SUCCESS', 'FAILED', 'CANCELLED'].includes(transaction.status)) {
      const agrees =
        (transaction.status === 'SUCCESS' && outcome === 'SUCCESS') ||
        (transaction.status === 'FAILED' && outcome === 'FAILED');
      await tx`
        UPDATE provider_callbacks
           SET processed_at = now(), transaction_id = ${transaction.id},
               processing_outcome = ${agrees ? 'DUPLICATE' : 'IGNORED_SETTLED'}
         WHERE id = ${message.callbackId}
      `;
      if (!agrees && outcome !== 'UNKNOWN' && outcome !== 'PENDING') {
        await tx`
          INSERT INTO reconciliation_cases (
            organization_id, transaction_id, case_reference, state, opened_reason, discrepancy
          ) VALUES (
            ${message.organizationId}, ${transaction.id},
            ${'REC-' + transaction.id.slice(0, 8).toUpperCase()}, 'OPEN',
            ${`M-PESA reports "${parsed.transactionStatus}" for a transaction settled here as ${transaction.status}`},
            TRUE
          )
          ON CONFLICT DO NOTHING
        `;
      }
      return;
    }

    // Still moving at M-PESA: leave it in flight and let the sweep come back.
    if (outcome === 'PENDING' || outcome === 'UNKNOWN') {
      await tx`
        UPDATE reconciliation_cases
           SET state = 'QUERYING', query_attempts = query_attempts + 1,
               next_query_at = now() + (interval '5 minutes' * GREATEST(1, query_attempts)),
               evidence = evidence || ${tx.json([
                 { at: new Date().toISOString(), status: parsed.transactionStatus, resultCode: parsed.resultCode },
               ] as never)}
         WHERE transaction_id = ${transaction.id} AND state IN ('OPEN', 'QUERYING')
      `;
      await tx`
        UPDATE provider_callbacks SET processed_at = now(), transaction_id = ${transaction.id},
               processing_outcome = 'APPLIED'
         WHERE id = ${message.callbackId}
      `;
      return;
    }

    const targetStatus: TxnState = outcome === 'SUCCESS' ? 'SUCCESS' : 'FAILED';
    const resolved =
      outcome === 'FAILED'
        ? resolveFailure(
            parsed.resultCode !== '0' ? parsed.resultCode : 'SLV_NO_CALLBACK',
            parsed.resultDescription || `M-PESA reports the transaction as ${parsed.transactionStatus}`,
            overrides,
          )
        : null;

    assertTxnTransition({
      from: transaction.status,
      to: targetStatus,
      source: 'STATUS_QUERY',
      providerReceipt: parsed.receiptNumber,
      failureCode: resolved?.failureCode ?? null,
    });

    await tx`
      UPDATE transactions
         SET status = ${targetStatus},
             mpesa_receipt_number = COALESCE(${parsed.receiptNumber}, mpesa_receipt_number),
             failure_code = ${resolved?.failureCode ?? null},
             failure_reason = ${resolved?.failureReason ?? null},
             failure_class = ${resolved?.failureClass ?? null},
             provider_result_description = ${parsed.resultDescription || null},
             status_source = 'STATUS_QUERY',
             completed_at = ${parsed.finalisedAt ?? new Date().toISOString()}
       WHERE id = ${transaction.id}
    `;
    await tx`
      UPDATE payment_instructions SET status = ${targetStatus} WHERE id = ${transaction.instruction_id}
    `;
    await tx`
      UPDATE idempotency_claims SET state = 'SETTLED', updated_at = now()
       WHERE instruction_id = ${transaction.instruction_id}
    `;
    await tx`
      UPDATE reconciliation_cases
         SET state = ${outcome === 'SUCCESS' ? 'RESOLVED_SUCCESS' : 'RESOLVED_FAILED'},
             resolved_at = now(),
             resolution_note = ${`Resolved by Transaction Status API: ${parsed.transactionStatus}`}
       WHERE transaction_id = ${transaction.id} AND state IN ('OPEN', 'QUERYING')
    `;
    await tx`
      UPDATE provider_callbacks SET processed_at = now(), transaction_id = ${transaction.id},
             processing_outcome = 'APPLIED', result_code = ${parsed.resultCode}
       WHERE id = ${message.callbackId}
    `;

    await writeAuditEvent(tx, {
      organizationId: message.organizationId,
      actorId: 'system:reconciliation',
      actorLevel: null,
      eventClass: 'INTEGRATION',
      action: 'daraja.status_query.resolved',
      objectType: 'Transaction',
      objectId: transaction.id,
      outcome: outcome === 'SUCCESS' ? 'SUCCESS' : 'FAILURE',
      previousState: { status: transaction.status },
      newState: { status: targetStatus },
      correlationId: message.correlationId,
      detail: {
        providerStatus: parsed.transactionStatus,
        receipt: parsed.receiptNumber,
        failureCode: resolved?.failureCode,
      },
    });
  });

  if (batchId) {
    await maybeSettleBatch(sql, env, message.organizationId, batchId, message.correlationId);
  }
}

/** Apply an Account Balance callback for the L3 executive panel (spec 21). */
async function applyAccountBalance(
  sql: Sql,
  message: CallbackQueueMessage,
  payload: unknown,
): Promise<void> {
  const parsed = parseAccountBalanceResult(payload);
  const asOf = parsed.completedAt ?? new Date().toISOString();

  await inTransaction(sql, async (tx) => {
    for (const account of parsed.accounts) {
      await tx`
        INSERT INTO account_balance_snapshots (
          organization_id, account_type, currency, available_cents, uncleared_cents,
          reserved_cents, as_of, source
        ) VALUES (
          ${message.organizationId}, ${account.accountType}, ${account.currency},
          ${account.availableBalanceCents}, ${account.unclearedBalanceCents},
          ${account.reservedBalanceCents}, ${asOf}, 'SCHEDULED'
        )
      `;
    }
    await tx`
      UPDATE provider_callbacks SET processed_at = now(), processing_outcome = 'APPLIED',
             result_code = ${parsed.resultCode}
       WHERE id = ${message.callbackId}
    `;
  });
}
