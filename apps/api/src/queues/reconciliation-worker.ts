/**
 * Reconciliation and status sweeps (spec 9.5, TRK-007, TRK-008).
 *
 * This worker resolves the one question the payment executor deliberately refuses to guess
 * at: for a transaction whose outcome we never learned, did money move?
 *
 * It answers by querying the Daraja Transaction Status API and letting the *provider*
 * decide. It never resubmits a payment, never infers failure from silence, and never
 * rewrites a settled row — a status query that contradicts a settled outcome opens a
 * discrepancy case for a human instead.
 */

import { SolvarenError, randomToken } from '@solvaren/core';
import { withConnection, inTransaction, type Sql } from '../db/client.js';
import { writeAuditEvent } from '../db/audit-writer.js';
import { loadDarajaClient } from '../services/daraja-config.js';
import type { Env, ReconciliationQueueMessage, QueueBatch } from '../env.js';

/**
 * Give up querying after this many attempts and escalate to a human.
 *
 * An escalated case is not a resolved one: the transaction stays visible as unresolved in
 * the explorer, because "we stopped asking" is not an outcome.
 */
const MAX_QUERY_ATTEMPTS = 8;

/** How long a transaction may sit awaiting a callback before the sweep picks it up. */
const CALLBACK_GRACE_MINUTES = 10;

export async function handleReconciliationBatch(
  batch: QueueBatch<ReconciliationQueueMessage>,
  env: Env,
): Promise<void> {
  await withConnection(env, async (sql) => {
    for (const message of batch.messages) {
      try {
        switch (message.body.type) {
          case 'SWEEP_ORGANIZATION':
            await sweepOrganization(sql, env, message.body);
            break;
          case 'RECONCILE_TRANSACTION':
            await reconcileTransaction(sql, env, message.body);
            break;
          case 'REFRESH_BALANCE':
            await refreshAccountBalance(sql, env, message.body);
            break;
        }
        message.ack();
      } catch (err) {
        console.error(
          JSON.stringify({
            level: 'error',
            message: 'Reconciliation failed',
            type: message.body.type,
            organizationId: message.body.organizationId,
            correlationId: message.body.correlationId,
            error: err instanceof Error ? err.message : String(err),
          }),
        );
        message.retry({ delaySeconds: 120 });
      }
    }
  });
}

/**
 * Scheduled sweep: find everything stuck in flight and ask about it.
 *
 * Ordered oldest-check-first so a transaction is never starved by newer arrivals, and
 * bounded per run so one organisation with a large backlog cannot exhaust the Daraja rate
 * budget for everyone.
 */
export async function sweepOrganization(
  sql: Sql,
  env: Env,
  message: ReconciliationQueueMessage,
): Promise<void> {
  const stuck = await sql<{ id: string; status: string; originator_conversation_id: string }[]>`
    SELECT id, status, originator_conversation_id
      FROM transactions
     WHERE organization_id = ${message.organizationId}
       AND status IN ('SUBMITTED', 'AWAITING_CALLBACK', 'PROCESSING', 'TIMEOUT', 'RECONCILING')
       AND submitted_at < now() - (${CALLBACK_GRACE_MINUTES} * interval '1 minute')
       AND (last_status_check_at IS NULL OR last_status_check_at < now() - interval '5 minutes')
     ORDER BY last_status_check_at NULLS FIRST, submitted_at ASC
     LIMIT 50
  `;

  if (stuck.length === 0) return;

  // Open a case for anything in flight that does not have one yet, so the operator sees
  // it in the reconciliation queue rather than only as a stale row in the explorer.
  for (const transaction of stuck) {
    await sql`
      INSERT INTO reconciliation_cases (
        organization_id, transaction_id, case_reference, state, opened_reason, next_query_at
      ) VALUES (
        ${message.organizationId}, ${transaction.id},
        ${'REC-' + randomToken(10)}, 'OPEN',
        ${'No provider result received within the expected window'}, now()
      )
      ON CONFLICT DO NOTHING
    `;
  }

  for (const transaction of stuck) {
    await queryTransactionStatus(
      sql,
      env,
      message,
      transaction.id,
      transaction.originator_conversation_id,
    );
  }
}

/** On-demand refresh for one transaction (TRK-007, L2/L3). */
export async function reconcileTransaction(
  sql: Sql,
  env: Env,
  message: ReconciliationQueueMessage,
): Promise<void> {
  const rows = await sql<{ id: string; originator_conversation_id: string; status: string }[]>`
    SELECT t.id, t.originator_conversation_id, t.status
      FROM transactions t
      LEFT JOIN reconciliation_cases rc
             ON rc.transaction_id = t.id AND rc.state IN ('OPEN', 'QUERYING')
     WHERE t.organization_id = ${message.organizationId}
       AND (${message.transactionId ?? null}::uuid IS NULL OR t.id = ${message.transactionId ?? null}::uuid)
       AND t.status NOT IN ('SUCCESS', 'FAILED', 'CANCELLED')
       AND (rc.next_query_at IS NULL OR rc.next_query_at <= now())
     ORDER BY t.submitted_at ASC
     LIMIT 25
  `;

  for (const transaction of rows) {
    await queryTransactionStatus(
      sql,
      env,
      message,
      transaction.id,
      transaction.originator_conversation_id,
    );
  }
}

/**
 * Issue one Transaction Status query.
 *
 * The provider answers asynchronously on the ResultURL, so this function's job ends at
 * "asked". The answer is applied by the callback processor, through the same validated
 * state-transition path as an ordinary B2C result — there is no second, looser path by
 * which a reconciliation outcome can reach the ledger.
 */
async function queryTransactionStatus(
  sql: Sql,
  env: Env,
  message: ReconciliationQueueMessage,
  transactionId: string,
  originatorConversationId: string,
): Promise<void> {
  const attempts = await sql<{ query_attempts: number; id: string }[]>`
    SELECT id, query_attempts FROM reconciliation_cases
     WHERE transaction_id = ${transactionId} AND state IN ('OPEN', 'QUERYING')
     LIMIT 1
  `;
  const attemptCount = attempts[0]?.query_attempts ?? 0;

  if (attemptCount >= MAX_QUERY_ATTEMPTS) {
    await escalate(sql, message, transactionId, attemptCount);
    return;
  }

  let client;
  try {
    ({ client } = await loadDarajaClient(sql, env, message.organizationId));
  } catch (err) {
    // The integration is disabled or its secrets are unreadable. The transaction stays
    // unresolved and visible; it is not marked failed on our own configuration problem.
    console.warn(
      JSON.stringify({
        level: 'warn',
        message: 'Cannot reconcile: Daraja integration unavailable',
        organizationId: message.organizationId,
        error: err instanceof SolvarenError ? err.code : String(err),
      }),
    );
    return;
  }

  const config = await sql<
    { short_code: string; initiator_name: string; result_url: string; queue_timeout_url: string }[]
  >`
    SELECT short_code, initiator_name, result_url, queue_timeout_url
      FROM daraja_configurations
     WHERE organization_id = ${message.organizationId} AND status = 'ENABLED'
     LIMIT 1
  `;
  if (!config[0]) return;

  const { credentials } = await loadDarajaClient(sql, env, message.organizationId);

  try {
    await client.queryTransactionStatus({
      Initiator: credentials.initiatorName,
      SecurityCredential: credentials.securityCredential,
      CommandID: 'TransactionStatusQuery',
      OriginalConversationID: originatorConversationId,
      PartyA: credentials.shortCode,
      IdentifierType: '4',
      // Status results arrive on the same callback endpoint and are distinguished by the
      // path segment, so one authenticated ingress handles every provider delivery.
      ResultURL: config[0].result_url.replace('/callback/', '/status-callback/'),
      QueueTimeOutURL: config[0].queue_timeout_url,
      Remarks: 'SOLVAREN reconciliation sweep',
    });

    await sql`
      UPDATE reconciliation_cases
         SET state = 'QUERYING',
             query_attempts = query_attempts + 1,
             next_query_at = now() + (interval '5 minutes' * GREATEST(1, query_attempts + 1))
       WHERE transaction_id = ${transactionId} AND state IN ('OPEN', 'QUERYING')
    `;
    await sql`
      UPDATE transactions
         SET status = CASE WHEN status IN ('TIMEOUT', 'AWAITING_CALLBACK') THEN 'RECONCILING' ELSE status END,
             last_status_check_at = now(),
             status_check_count = status_check_count + 1
       WHERE id = ${transactionId}
         AND status NOT IN ('SUCCESS', 'FAILED', 'CANCELLED')
    `;
  } catch (err) {
    // A failed *query* tells us nothing about the payment. Record the attempt, back off,
    // and leave the transaction exactly as it was.
    await sql`
      UPDATE reconciliation_cases
         SET query_attempts = query_attempts + 1,
             next_query_at = now() + (interval '10 minutes' * GREATEST(1, query_attempts + 1)),
             evidence = evidence || ${sql.json([
               {
                 at: new Date().toISOString(),
                 outcome: 'QUERY_FAILED',
                 error: err instanceof SolvarenError ? err.code : 'UNKNOWN',
               },
             ] as never)}
       WHERE transaction_id = ${transactionId} AND state IN ('OPEN', 'QUERYING')
    `;
  }
}

/** Hand an unresolvable case to a human, loudly. */
async function escalate(
  sql: Sql,
  message: ReconciliationQueueMessage,
  transactionId: string,
  attempts: number,
): Promise<void> {
  await inTransaction(sql, async (tx) => {
    await tx`
      UPDATE reconciliation_cases
         SET state = 'ESCALATED',
             resolution_note = ${`Automatic reconciliation could not establish an outcome after ${attempts} status queries. Check the M-PESA organisation portal and resolve this case manually.`}
       WHERE transaction_id = ${transactionId} AND state IN ('OPEN', 'QUERYING')
    `;
    await tx`
      INSERT INTO security_events (organization_id, event_type, severity, description, detail)
      VALUES (
        ${message.organizationId}, 'RECONCILIATION_ESCALATED', 'WARNING',
        ${'A transaction outcome could not be established automatically and needs manual resolution'},
        ${tx.json({ transactionId, attempts })}
      )
    `;
    await writeAuditEvent(tx, {
      organizationId: message.organizationId,
      actorId: 'system:reconciliation-worker',
      actorLevel: null,
      eventClass: 'INTEGRATION',
      action: 'reconciliation.escalated',
      objectType: 'Transaction',
      objectId: transactionId,
      outcome: 'FAILURE',
      correlationId: message.correlationId,
      detail: { attempts, note: 'Manual resolution required; the ledger was not modified.' },
    });
  });
}

/**
 * Refresh the organisation M-PESA balance for the L3 executive panel (spec 21).
 *
 * Asynchronous like everything else on Daraja: this asks, and the callback answers. The
 * panel therefore always shows an "as of" timestamp and an awaiting-refresh state rather
 * than pretending the figure is live.
 */
export async function refreshAccountBalance(
  sql: Sql,
  env: Env,
  message: ReconciliationQueueMessage,
): Promise<void> {
  const { client, credentials, config } = await loadDarajaClient(sql, env, message.organizationId);

  await client.queryAccountBalance({
    Initiator: credentials.initiatorName,
    SecurityCredential: credentials.securityCredential,
    CommandID: 'AccountBalance',
    PartyA: credentials.shortCode,
    IdentifierType: '4',
    Remarks: 'SOLVAREN balance refresh',
    ResultURL: config.resultUrl.replace('/callback/', '/balance-callback/'),
    QueueTimeOutURL: config.queueTimeoutUrl,
  });

  await inTransaction(sql, async (tx) => {
    await writeAuditEvent(tx, {
      organizationId: message.organizationId,
      actorId: message.requestedByUserId ?? 'system:scheduler',
      actorLevel: message.requestedByUserId ? 'L3' : null,
      eventClass: 'INTEGRATION',
      action: 'daraja.balance.requested',
      objectType: 'Organization',
      objectId: message.organizationId,
      outcome: 'SUCCESS',
      correlationId: message.correlationId,
      detail: { onDemand: Boolean(message.requestedByUserId) },
    });
  });
}
