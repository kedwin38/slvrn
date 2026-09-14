/**
 * Reconciliation: status checks and investigations (spec §6.5, §9.3, §12 "Reconciliation reports").
 *
 * A reconciliation case exists because SOLVAREN does not know whether money moved. Daraja
 * accepted the request and then the callback never arrived, or a status query contradicted a
 * settled ledger row. That ambiguity is the single most expensive state in a disbursement
 * platform: guess "paid" and somebody goes unpaid, guess "failed" and somebody is paid twice.
 *
 * So this module deliberately offers *less* than an operator might expect:
 *
 *   - It can ask M-PESA again. The provider settles the ledger, never the operator.
 *   - It can record what a human established from the M-PESA organisation portal, as
 *     evidence on the case.
 *   - It can close a case as failed, because `assertTxnTransition` allows TIMEOUT → FAILED
 *     with a provider failure code and §6.2 requires that code to be present.
 *
 * It cannot mark a transaction SUCCESS. Spec §2: "No role can bypass the state machine or
 * convert an unauthorized transaction into a successful payment by directly manipulating
 * status data." The route to SUCCESS is a provider callback or a status query, and if the
 * provider never answers, the case closes as RESOLVED_MANUAL with the operator's evidence
 * attached while the ledger keeps saying, truthfully, that we never got an answer.
 */

import { Hono } from 'hono';
import { z } from 'zod';
import {
  assertTxnTransition,
  notFoundError,
  validationError,
  statusTone,
  resolveFailure,
  pageInfo,
  type TxnState,
} from '@solvaren/core';
import { requireAuth, requirePermissions, actorOf } from '../middleware/security.js';
import { withConnection, inTransaction } from '../db/client.js';
import { writeAuditEvent } from '../db/audit-writer.js';
import { loadFailureOverrides } from '../services/failure-map.js';
import type { AppContext } from '../env.js';

export const reconciliationRoutes = new Hono<AppContext>();
reconciliationRoutes.use('*', requireAuth);

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const OPEN_STATES = ['OPEN', 'QUERYING', 'ESCALATED'] as const;

const listQuerySchema = z.object({
  state: z
    .enum([
      'OPEN',
      'QUERYING',
      'RESOLVED_SUCCESS',
      'RESOLVED_FAILED',
      'RESOLVED_MANUAL',
      'ESCALATED',
    ])
    .optional(),
  /** The default view: everything still demanding a human decision. */
  outstanding: z.coerce.boolean().optional(),
  discrepancyOnly: z.coerce.boolean().optional(),
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(200).default(25),
});

interface CaseRow {
  id: string;
  case_reference: string;
  state: string;
  opened_reason: string;
  discrepancy: boolean;
  query_attempts: number;
  next_query_at: string | null;
  opened_at: string;
  resolved_at: string | null;
  resolution_note: string | null;
  resolved_by_name: string | null;
  evidence: unknown;
  transaction_id: string;
  txn_status: TxnState;
  failure_code: string | null;
  provider_result_description: string | null;
  mpesa_receipt_number: string | null;
  originator_conversation_id: string | null;
  conversation_id: string | null;
  amount_cents: string;
  recipient_name: string;
  msisdn: string;
  batch_id: string;
  batch_reference: string;
  total_count: string;
}

function presentCase(row: CaseRow, failureReason: string | null) {
  return {
    caseId: row.id,
    caseReference: row.case_reference,
    state: row.state,
    openedReason: row.opened_reason,
    discrepancy: row.discrepancy,
    queryAttempts: row.query_attempts,
    nextQueryAt: row.next_query_at,
    openedAt: row.opened_at,
    resolvedAt: row.resolved_at,
    resolvedBy: row.resolved_by_name,
    resolutionNote: row.resolution_note,
    evidence: row.evidence,
    transaction: {
      transactionId: row.transaction_id,
      status: row.txn_status,
      statusTone: statusTone(row.txn_status),
      failureCode: row.failure_code,
      failureReason,
      providerResultDescription: row.provider_result_description,
      mpesaReceiptNumber: row.mpesa_receipt_number,
      originatorConversationId: row.originator_conversation_id,
      conversationId: row.conversation_id,
      amountCents: Number(row.amount_cents),
      recipientName: row.recipient_name,
      msisdn: row.msisdn,
      batchId: row.batch_id,
      batchReference: row.batch_reference,
    },
  };
}

/**
 * GET /reconciliation/cases — the investigation queue.
 *
 * Ordered oldest-first on purpose. A reconciliation case does not get less urgent with age:
 * the employee who has not been paid has been waiting the longest, and a newest-first list
 * quietly buries exactly the cases that matter most.
 */
reconciliationRoutes.get('/cases', requirePermissions('reconciliation:read'), async (c) => {
  const actor = actorOf(c);
  const query = listQuerySchema.parse(c.req.query());
  const offset = (query.page - 1) * query.pageSize;

  const result = await withConnection(c.env, async (sql) => {
    const rows = await sql<CaseRow[]>`
      SELECT rc.id, rc.case_reference, rc.state, rc.opened_reason, rc.discrepancy,
             rc.query_attempts, rc.next_query_at, rc.opened_at, rc.resolved_at,
             rc.resolution_note, rc.evidence,
             u.full_name AS resolved_by_name,
             t.id AS transaction_id, t.status AS txn_status, t.failure_code,
             t.provider_result_description, t.mpesa_receipt_number,
             t.originator_conversation_id, t.conversation_id,
             pi.amount_cents, pi.msisdn_snapshot AS msisdn,
             r.full_name AS recipient_name,
             b.id AS batch_id, b.batch_reference,
             count(*) OVER ()::text AS total_count
        FROM reconciliation_cases rc
        JOIN transactions t           ON t.id = rc.transaction_id
        JOIN payment_instructions pi  ON pi.id = t.instruction_id
        JOIN recipients r             ON r.id = pi.recipient_id
        JOIN payment_batches b        ON b.id = t.batch_id
        LEFT JOIN users u             ON u.id = rc.resolved_by_user_id
       WHERE rc.organization_id = ${actor.organizationId}
         ${query.state ? sql`AND rc.state = ${query.state}` : sql``}
         ${query.outstanding ? sql`AND rc.state IN ('OPEN', 'QUERYING', 'ESCALATED')` : sql``}
         ${query.discrepancyOnly ? sql`AND rc.discrepancy IS TRUE` : sql``}
       ORDER BY rc.opened_at ASC
       LIMIT ${query.pageSize} OFFSET ${offset}
    `;

    const overrides = await loadFailureOverrides(sql, actor.organizationId);
    const totalRows = rows.length > 0 ? Number(rows[0]!.total_count) : 0;

    return {
      cases: rows.map((row) =>
        presentCase(
          row,
          row.failure_code
            ? resolveFailure(row.failure_code, row.provider_result_description, overrides)
                .failureReason
            : null,
        ),
      ),
      page: pageInfo(query, totalRows),
    };
  });

  return c.json(result);
});

/** GET /reconciliation/summary — the counters the dashboard and the action queue read. */
reconciliationRoutes.get('/summary', requirePermissions('reconciliation:read'), async (c) => {
  const actor = actorOf(c);

  const summary = await withConnection(c.env, async (sql) => {
    const rows = await sql<
      {
        state: string;
        cases: string;
        oldest_opened_at: Date | string | null;
        discrepancies: string;
      }[]
    >`
      SELECT state,
             count(*)::text AS cases,
             min(opened_at) AS oldest_opened_at,
             count(*) FILTER (WHERE discrepancy)::text AS discrepancies
        FROM reconciliation_cases
       WHERE organization_id = ${actor.organizationId}
       GROUP BY state
    `;

    const byState: Record<string, number> = {};
    let outstanding = 0;
    let discrepancies = 0;
    let oldestOutstandingAt: string | null = null;
    for (const row of rows) {
      byState[row.state] = Number(row.cases);
      discrepancies += Number(row.discrepancies);
      if ((OPEN_STATES as readonly string[]).includes(row.state)) {
        outstanding += Number(row.cases);
        // The driver returns a Date for a timestamptz whatever the row type says, so this
        // is normalised before it is compared or serialised.
        const opened =
          row.oldest_opened_at instanceof Date
            ? row.oldest_opened_at.toISOString()
            : (row.oldest_opened_at ?? null);
        if (opened && (!oldestOutstandingAt || opened < oldestOutstandingAt)) {
          oldestOutstandingAt = opened;
        }
      }
    }
    return { byState, outstanding, discrepancies, oldestOutstandingAt };
  });

  return c.json(summary);
});

/** GET /reconciliation/cases/:id — one case with its full evidence trail. */
reconciliationRoutes.get('/cases/:id', requirePermissions('reconciliation:read'), async (c) => {
  const actor = actorOf(c);
  const caseId = c.req.param('id');
  if (!UUID_PATTERN.test(caseId)) {
    throw notFoundError('RECONCILIATION_CASE_NOT_FOUND', 'That case could not be found');
  }

  const result = await withConnection(c.env, async (sql) => {
    const rows = await sql<CaseRow[]>`
      SELECT rc.id, rc.case_reference, rc.state, rc.opened_reason, rc.discrepancy,
             rc.query_attempts, rc.next_query_at, rc.opened_at, rc.resolved_at,
             rc.resolution_note, rc.evidence,
             u.full_name AS resolved_by_name,
             t.id AS transaction_id, t.status AS txn_status, t.failure_code,
             t.provider_result_description, t.mpesa_receipt_number,
             t.originator_conversation_id, t.conversation_id,
             pi.amount_cents, pi.msisdn_snapshot AS msisdn,
             r.full_name AS recipient_name,
             b.id AS batch_id, b.batch_reference,
             '1' AS total_count
        FROM reconciliation_cases rc
        JOIN transactions t           ON t.id = rc.transaction_id
        JOIN payment_instructions pi  ON pi.id = t.instruction_id
        JOIN recipients r             ON r.id = pi.recipient_id
        JOIN payment_batches b        ON b.id = t.batch_id
        LEFT JOIN users u             ON u.id = rc.resolved_by_user_id
       WHERE rc.id = ${caseId} AND rc.organization_id = ${actor.organizationId}
       LIMIT 1
    `;
    const row = rows[0];
    if (!row) {
      throw notFoundError('RECONCILIATION_CASE_NOT_FOUND', 'That case could not be found');
    }

    const overrides = await loadFailureOverrides(sql, actor.organizationId);
    const activity = await sql<
      { action: string; outcome: string; occurred_at: string; detail: unknown }[]
    >`
      SELECT action, outcome, occurred_at, detail
        FROM audit_events
       WHERE organization_id = ${actor.organizationId}
         AND object_type = 'Transaction' AND object_id = ${row.transaction_id}
       ORDER BY sequence ASC
    `;

    return {
      case: presentCase(
        row,
        row.failure_code
          ? resolveFailure(row.failure_code, row.provider_result_description, overrides)
              .failureReason
          : null,
      ),
      activity,
    };
  });

  return c.json(result);
});

/**
 * POST /reconciliation/cases/:id/query — ask M-PESA again, now.
 *
 * The sweep already backs off exponentially, which is right for a thousand cases and wrong
 * for the one an operator is looking at. This queues a single query for that case and
 * changes nothing else; the provider's answer, whenever it lands, settles the ledger.
 */
reconciliationRoutes.post(
  '/cases/:id/query',
  requirePermissions('reconciliation:resolve'),
  async (c) => {
    const actor = actorOf(c);
    const caseId = c.req.param('id');
    const correlationId = c.get('correlationId');
    if (!UUID_PATTERN.test(caseId)) {
      throw notFoundError('RECONCILIATION_CASE_NOT_FOUND', 'That case could not be found');
    }

    await withConnection(c.env, (sql) =>
      inTransaction(sql, async (tx) => {
        const rows = await tx<{ transaction_id: string; state: string }[]>`
          SELECT transaction_id, state FROM reconciliation_cases
           WHERE id = ${caseId} AND organization_id = ${actor.organizationId}
           FOR UPDATE
        `;
        const row = rows[0];
        if (!row) {
          throw notFoundError('RECONCILIATION_CASE_NOT_FOUND', 'That case could not be found');
        }
        if (!(OPEN_STATES as readonly string[]).includes(row.state)) {
          throw validationError(
            'RECONCILIATION_CASE_CLOSED',
            `This case is already ${row.state}. Re-querying a closed case cannot change a settled outcome.`,
          );
        }

        // Due now, so the sweep picks it up on its next pass rather than at the end of the
        // backoff the automatic attempts have built up.
        await tx`
          UPDATE reconciliation_cases SET next_query_at = now() WHERE id = ${caseId}
        `;

        await c.env.queue.send(
          {
            queue: 'reconciliation',
            body: {
              type: 'RECONCILE_TRANSACTION',
              organizationId: actor.organizationId,
              transactionId: row.transaction_id,
              requestedByUserId: actor.userId,
              correlationId,
            },
          },
          tx,
        );

        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'INTEGRATION',
          action: 'reconciliation.query.requested',
          objectType: 'Transaction',
          objectId: row.transaction_id,
          outcome: 'SUCCESS',
          correlationId,
          securityContext: c.get('securityContext'),
          detail: { caseId },
        });
      }),
    );

    return c.json({
      accepted: true,
      message:
        'A status query has been queued. M-PESA decides the outcome; the case updates when it answers.',
    });
  },
);

const resolveSchema = z
  .object({
    /**
     * `FAILED` writes the ledger, because the state machine permits TIMEOUT → FAILED with a
     * provider code. `MANUAL` records a finding without touching it. There is no `SUCCESS`:
     * a payment becomes SUCCESS by provider evidence or not at all.
     */
    outcome: z.enum(['FAILED', 'MANUAL']),
    failureCode: z.string().trim().min(1).max(32).optional(),
    /** M-PESA receipt read off the organisation portal, kept as evidence on the case. */
    providerReceipt: z.string().trim().max(64).optional(),
    note: z
      .string()
      .trim()
      .min(10, 'Say what you established and where you established it')
      .max(2000),
  })
  .refine((value) => value.outcome !== 'FAILED' || !!value.failureCode, {
    message: 'Closing a case as failed requires the provider failure code',
    path: ['failureCode'],
  });

/**
 * POST /reconciliation/cases/:id/resolve — close an investigation.
 *
 * Everything an operator establishes outside this system — a receipt read off the M-PESA
 * portal, a call to Safaricom support — arrives here as *evidence*, appended to the case and
 * never overwritten. `MANUAL` deliberately leaves the transaction where it is: if the
 * provider never told us the payment succeeded, the ledger should keep saying so, however
 * confident the operator is, because the ledger is what the auditor reads.
 */
reconciliationRoutes.post(
  '/cases/:id/resolve',
  requirePermissions('reconciliation:resolve'),
  async (c) => {
    const actor = actorOf(c);
    const caseId = c.req.param('id');
    const correlationId = c.get('correlationId');
    if (!UUID_PATTERN.test(caseId)) {
      throw notFoundError('RECONCILIATION_CASE_NOT_FOUND', 'That case could not be found');
    }
    const body = resolveSchema.parse(await c.req.json());

    const result = await withConnection(c.env, (sql) =>
      inTransaction(sql, async (tx) => {
        const rows = await tx<
          { transaction_id: string; state: string; txn_status: TxnState; case_reference: string }[]
        >`
          SELECT rc.transaction_id, rc.state, rc.case_reference, t.status AS txn_status
            FROM reconciliation_cases rc
            JOIN transactions t ON t.id = rc.transaction_id
           WHERE rc.id = ${caseId} AND rc.organization_id = ${actor.organizationId}
           FOR UPDATE OF rc
        `;
        const row = rows[0];
        if (!row) {
          throw notFoundError('RECONCILIATION_CASE_NOT_FOUND', 'That case could not be found');
        }
        if (!(OPEN_STATES as readonly string[]).includes(row.state)) {
          throw validationError(
            'RECONCILIATION_CASE_CLOSED',
            `This case was already closed as ${row.state}.`,
          );
        }

        const newState = body.outcome === 'FAILED' ? 'RESOLVED_FAILED' : 'RESOLVED_MANUAL';

        // Rejects the forged-SUCCESS path and the rewrite-a-settled-row path alike, from the
        // one place that knows the rules.
        if (body.outcome === 'FAILED') {
          assertTxnTransition({
            from: row.txn_status,
            to: 'FAILED',
            source: 'STATUS_QUERY',
            failureCode: body.failureCode,
          });
          await tx`
            UPDATE transactions
               SET status = 'FAILED',
                   failure_code = ${body.failureCode!},
                   failure_reason = ${`Established by manual reconciliation: ${body.note}`},
                   failure_class = 'AMBIGUOUS',
                   status_source = 'STATUS_QUERY',
                   completed_at = now()
             WHERE id = ${row.transaction_id}
          `;
        }

        await tx`
          UPDATE reconciliation_cases
             SET state = ${newState},
                 resolved_at = now(),
                 resolved_by_user_id = ${actor.userId},
                 resolution_note = ${body.note},
                 evidence = evidence || ${tx.json([
                   {
                     at: new Date().toISOString(),
                     outcome: `MANUAL_${body.outcome}`,
                     by: actor.userId,
                     note: body.note,
                     ...(body.providerReceipt ? { providerReceipt: body.providerReceipt } : {}),
                     ...(body.failureCode ? { failureCode: body.failureCode } : {}),
                   },
                 ] as never)}
           WHERE id = ${caseId}
        `;

        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'PAYMENT',
          action: 'reconciliation.resolved',
          objectType: 'Transaction',
          objectId: row.transaction_id,
          outcome: 'SUCCESS',
          previousState: { caseState: row.state, transactionStatus: row.txn_status },
          newState: {
            caseState: newState,
            transactionStatus: body.outcome === 'FAILED' ? 'FAILED' : row.txn_status,
          },
          correlationId,
          securityContext: c.get('securityContext'),
          detail: {
            caseId,
            caseReference: row.case_reference,
            note: body.note,
            providerReceipt: body.providerReceipt ?? null,
            ledgerWritten: body.outcome === 'FAILED',
          },
        });

        return { state: newState, transactionId: row.transaction_id };
      }),
    );

    return c.json({
      resolved: true,
      state: result.state,
      transactionId: result.transactionId,
      message:
        result.state === 'RESOLVED_FAILED'
          ? 'The case is closed and the transaction is recorded as failed with its provider code.'
          : 'The case is closed with your findings attached. The transaction status is unchanged, because M-PESA never confirmed an outcome.',
    });
  },
);
