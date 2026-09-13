/**
 * Dashboards and analytics (spec 12, 21).
 *
 * The executive panels are the sharpest access-control requirement in the specification:
 *
 *   AC-19 — "Dashboard balance and recent-transactions panels are served to Level 3 only
 *            (server-enforced)"
 *   21    — "Both panels are withheld from L1/L2 by server-side authorization; the
 *            underlying data APIs reject non-L3 callers."
 *
 * So the balance and recent-transactions endpoints carry `requireExactLevel('L3')` in
 * addition to their permission check. Not "L3 or above" — L3 is the top level, but writing
 * the exact check makes the intent unmistakable and means a future L4 would not silently
 * inherit access to the chief executive's balance panel.
 */

import { Hono } from 'hono';
import { authorizationError } from '@solvaren/core';
import {
  requireAuth,
  requirePermissions,
  requireExactLevel,
  actorOf,
} from '../middleware/security.js';
import { withConnection, inTransaction } from '../db/client.js';
import { writeAuditEvent } from '../db/audit-writer.js';
import type { AppContext, ReconciliationQueueMessage } from '../env.js';

export const dashboardRoutes = new Hono<AppContext>();
dashboardRoutes.use('*', requireAuth);

/**
 * GET /analytics/operational — the L1 dashboard (spec 12).
 * Batch counts, success and failure rates, processing times, failure drill-down.
 */
dashboardRoutes.get('/operational', requirePermissions('analytics:basic'), async (c) => {
  const actor = actorOf(c);

  const data = await withConnection(c.env, async (sql) => {
    const batches = await sql<{ state: string; count: string }[]>`
      SELECT state, COUNT(*) AS count
        FROM payment_batches
       WHERE organization_id = ${actor.organizationId}
         AND created_at > now() - interval '90 days'
       GROUP BY state
    `;

    const outcomes = await sql<
      { total: string; success: string; failed: string; timeout: string; in_flight: string }[]
    >`
      SELECT COUNT(*) AS total,
             COUNT(*) FILTER (WHERE status = 'SUCCESS') AS success,
             COUNT(*) FILTER (WHERE status = 'FAILED')  AS failed,
             COUNT(*) FILTER (WHERE status = 'TIMEOUT') AS timeout,
             COUNT(*) FILTER (WHERE status IN ('PENDING','SUBMITTED','AWAITING_CALLBACK','PROCESSING','RECONCILING')) AS in_flight
        FROM transactions
       WHERE organization_id = ${actor.organizationId}
         AND created_at > now() - interval '30 days'
    `;

    // Median rather than mean: one reconciliation case sitting open for three days would
    // drag a mean into uselessness.
    const timing = await sql<{ median_seconds: number | null; p95_seconds: number | null }[]>`
      SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (completed_at - submitted_at)))  AS median_seconds,
             percentile_cont(0.95) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (completed_at - submitted_at))) AS p95_seconds
        FROM transactions
       WHERE organization_id = ${actor.organizationId}
         AND status = 'SUCCESS' AND completed_at IS NOT NULL AND submitted_at IS NOT NULL
         AND created_at > now() - interval '30 days'
    `;

    const trend = await sql<{ day: string; total: string; failed: string }[]>`
      SELECT date_trunc('day', created_at AT TIME ZONE 'Africa/Nairobi')::DATE::text AS day,
             COUNT(*) AS total,
             COUNT(*) FILTER (WHERE status IN ('FAILED', 'TIMEOUT')) AS failed
        FROM transactions
       WHERE organization_id = ${actor.organizationId}
         AND created_at > now() - interval '30 days'
       GROUP BY 1 ORDER BY 1
    `;

    const attention = await sql<{ failed: string; timeout: string; reconciling: string }[]>`
      SELECT COUNT(*) FILTER (WHERE status = 'FAILED')  AS failed,
             COUNT(*) FILTER (WHERE status = 'TIMEOUT') AS timeout,
             COUNT(*) FILTER (WHERE status = 'RECONCILING') AS reconciling
        FROM transactions
       WHERE organization_id = ${actor.organizationId}
         AND created_at > now() - interval '30 days'
    `;

    const row = outcomes[0]!;
    const total = Number(row.total);

    return {
      batchesByState: Object.fromEntries(batches.map((b) => [b.state, Number(b.count)])),
      transactions: {
        total,
        success: Number(row.success),
        failed: Number(row.failed),
        timeout: Number(row.timeout),
        inFlight: Number(row.in_flight),
        successRate: total > 0 ? Number(row.success) / total : null,
        failureRate: total > 0 ? (Number(row.failed) + Number(row.timeout)) / total : null,
      },
      processingSeconds: {
        median: timing[0]?.median_seconds ?? null,
        p95: timing[0]?.p95_seconds ?? null,
      },
      dailyTrend: trend.map((t) => ({
        day: t.day,
        total: Number(t.total),
        failed: Number(t.failed),
      })),
      // Drives the dashboard's failure indicator, one click from the filtered explorer.
      needsAttention: {
        failed: Number(attention[0]?.failed ?? 0),
        timeout: Number(attention[0]?.timeout ?? 0),
        reconciling: Number(attention[0]?.reconciling ?? 0),
      },
    };
  });

  return c.json(data);
});

/** GET /analytics/financial — the L2 dashboard: departmental and payroll analytics. */
dashboardRoutes.get('/financial', requirePermissions('analytics:advanced'), async (c) => {
  const actor = actorOf(c);

  const data = await withConnection(c.env, async (sql) => {
    const departments = await sql<
      {
        department_name: string | null;
        period_month: string;
        paid_cents: string;
        paid_count: string;
        failed_count: string;
      }[]
    >`
      SELECT department_name, period_month::text, paid_cents, paid_count, failed_count
        FROM department_expenditure
       WHERE organization_id = ${actor.organizationId}
         AND period_month > (now() - interval '12 months')::DATE
       ORDER BY period_month DESC, paid_cents DESC
    `;

    const cycles = await sql<
      { period_month: string; total_cents: string; recipient_count: string }[]
    >`
      SELECT date_trunc('month', t.completed_at AT TIME ZONE 'Africa/Nairobi')::DATE::text AS period_month,
             SUM(pi.amount_cents) AS total_cents,
             COUNT(DISTINCT pi.recipient_id) AS recipient_count
        FROM transactions t
        JOIN payment_instructions pi ON pi.id = t.instruction_id
       WHERE t.organization_id = ${actor.organizationId}
         AND t.status = 'SUCCESS' AND t.completed_at > now() - interval '12 months'
       GROUP BY 1 ORDER BY 1 DESC
    `;

    const anomalies = await sql<{ severity: string; count: string }[]>`
      SELECT severity, COUNT(*) AS count
        FROM risk_findings
       WHERE organization_id = ${actor.organizationId} AND disposition = 'OPEN'
       GROUP BY severity
    `;

    const reconciliation = await sql<{ state: string; count: string }[]>`
      SELECT state, COUNT(*) AS count
        FROM reconciliation_cases
       WHERE organization_id = ${actor.organizationId}
       GROUP BY state
    `;

    // A naive month-over-month forecast: the mean of the trailing three settled cycles.
    // Deliberately simple and labelled as such — a confident-looking projection from a
    // model the finance team cannot inspect is worse than an honest average.
    const recent = cycles.slice(0, 3).map((cycle) => Number(cycle.total_cents));
    const forecastCents =
      recent.length > 0 ? Math.round(recent.reduce((a, b) => a + b, 0) / recent.length) : null;

    return {
      departmentExpenditure: departments.map((d) => ({
        departmentName: d.department_name ?? 'Unassigned',
        periodMonth: d.period_month,
        paidCents: Number(d.paid_cents),
        paidCount: Number(d.paid_count),
        failedCount: Number(d.failed_count),
      })),
      payrollCycles: cycles.map((cycle) => ({
        periodMonth: cycle.period_month,
        totalCents: Number(cycle.total_cents),
        recipientCount: Number(cycle.recipient_count),
      })),
      openFindingsBySeverity: Object.fromEntries(
        anomalies.map((a) => [a.severity, Number(a.count)]),
      ),
      reconciliationByState: Object.fromEntries(
        reconciliation.map((r) => [r.state, Number(r.count)]),
      ),
      forecast: {
        nextCycleCents: forecastCents,
        basis: 'Mean of the last three settled payment cycles',
        method: 'trailing-average',
      },
    };
  });

  return c.json(data);
});

/**
 * GET /analytics/executive/balance — the L3 balance panel (spec 21, AC-19).
 *
 * L3 ONLY, enforced here in the API. The UI also hides the panel, but as spec 4 puts it,
 * "a hidden button or disabled menu item is not an access control".
 */
dashboardRoutes.get(
  '/executive/balance',
  requireExactLevel('L3'),
  requirePermissions('dashboard:balance_panel'),
  async (c) => {
    const actor = actorOf(c);

    const data = await withConnection(c.env, async (sql) => {
      // DISTINCT ON gives the newest snapshot per account type in a single pass.
      const balances = await sql<
        {
          account_type: string;
          currency: string;
          available_cents: string;
          uncleared_cents: string;
          reserved_cents: string;
          as_of: string;
          source: string;
        }[]
      >`
        SELECT DISTINCT ON (account_type)
               account_type, currency, available_cents, uncleared_cents, reserved_cents, as_of, source
          FROM account_balance_snapshots
         WHERE organization_id = ${actor.organizationId}
         ORDER BY account_type, as_of DESC
      `;

      const pending = await sql<{ count: string }[]>`
        SELECT COUNT(*) AS count FROM provider_callbacks
         WHERE organization_id = ${actor.organizationId}
           AND callback_type = 'ACCOUNT_BALANCE' AND processed_at IS NULL
      `;

      return {
        accounts: balances.map((b) => ({
          accountType: b.account_type,
          currency: b.currency,
          availableCents: Number(b.available_cents),
          unclearedCents: Number(b.uncleared_cents),
          reservedCents: Number(b.reserved_cents),
          asOf: b.as_of,
          source: b.source,
        })),
        // The panel must show this: a figure without an "as of" invites an authorizer to
        // treat a stale balance as live before releasing a payroll.
        asOf: balances[0]?.as_of ?? null,
        awaitingRefresh: Number(pending[0]?.count ?? 0) > 0,
        note:
          balances.length === 0
            ? 'No balance has been retrieved yet. Request a refresh to query M-PESA.'
            : null,
      };
    });

    return c.json(data);
  },
);

/** POST /analytics/executive/balance/refresh — request a fresh Account Balance query. */
dashboardRoutes.post(
  '/executive/balance/refresh',
  requireExactLevel('L3'),
  requirePermissions('dashboard:balance_panel'),
  async (c) => {
    const actor = actorOf(c);
    const correlationId = c.get('correlationId');

    const message: ReconciliationQueueMessage = {
      type: 'REFRESH_BALANCE',
      organizationId: actor.organizationId,
      requestedByUserId: actor.userId,
      correlationId,
    };
    await c.env.queue.send({ queue: 'reconciliation', body: message });

    await withConnection(c.env, (sql) =>
      inTransaction(sql, (tx) =>
        writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'INTEGRATION',
          action: 'dashboard.balance.refresh_requested',
          objectType: 'Organization',
          objectId: actor.organizationId,
          outcome: 'SUCCESS',
          correlationId,
          securityContext: c.get('securityContext'),
          detail: {},
        }),
      ),
    );

    return c.json(
      {
        accepted: true,
        message:
          'A balance query has been sent to M-PESA. The panel updates when the result arrives.',
      },
      202,
    );
  },
);

/**
 * GET /analytics/executive/recent-transactions — the L3 recent-transactions panel.
 * L3 ONLY (spec 21, AC-19), drawn from the authoritative ledger.
 */
dashboardRoutes.get(
  '/executive/recent-transactions',
  requireExactLevel('L3'),
  requirePermissions('dashboard:recent_transactions_panel'),
  async (c) => {
    const actor = actorOf(c);
    const limit = Math.min(Number(new URL(c.req.url).searchParams.get('limit') ?? '20'), 100);

    const data = await withConnection(c.env, async (sql) => {
      const rows = await sql<
        {
          transaction_id: string;
          status: string;
          amount_cents: string;
          recipient_name: string;
          msisdn: string;
          mpesa_receipt_number: string | null;
          batch_reference: string;
          completed_at: string | null;
          created_at: string;
          failure_reason: string | null;
        }[]
      >`
        SELECT t.id AS transaction_id, t.status, pi.amount_cents,
               pi.recipient_name_snapshot AS recipient_name, pi.msisdn_snapshot AS msisdn,
               t.mpesa_receipt_number, b.batch_reference, t.completed_at, t.created_at,
               t.failure_reason
          FROM transactions t
          JOIN payment_instructions pi ON pi.id = t.instruction_id
          JOIN payment_batches b       ON b.id = t.batch_id
         WHERE t.organization_id = ${actor.organizationId}
         ORDER BY t.created_at DESC
         LIMIT ${limit}
      `;

      return {
        transactions: rows.map((r) => ({
          transactionId: r.transaction_id,
          status: r.status,
          amountCents: Number(r.amount_cents),
          recipientName: r.recipient_name,
          msisdn: r.msisdn,
          mpesaReceiptNumber: r.mpesa_receipt_number,
          batchReference: r.batch_reference,
          failureReason: r.failure_reason,
          at: r.completed_at ?? r.created_at,
        })),
      };
    });

    return c.json(data);
  },
);

/** GET /analytics/executive/briefing — the L3 organisation-wide intelligence view. */
dashboardRoutes.get('/executive/briefing', requirePermissions('analytics:executive'), async (c) => {
  const actor = actorOf(c);
  if (actor.level !== 'L3') {
    throw authorizationError(
      'LEVEL_RESTRICTED',
      'Executive intelligence is available to Level 3 only',
    );
  }

  const data = await withConnection(c.env, async (sql) => {
    const months = await sql<{ period: string; total_cents: string; count: string }[]>`
        SELECT date_trunc('month', t.completed_at AT TIME ZONE 'Africa/Nairobi')::DATE::text AS period,
               SUM(pi.amount_cents) AS total_cents, COUNT(*) AS count
          FROM transactions t
          JOIN payment_instructions pi ON pi.id = t.instruction_id
         WHERE t.organization_id = ${actor.organizationId}
           AND t.status = 'SUCCESS' AND t.completed_at > now() - interval '13 months'
         GROUP BY 1 ORDER BY 1 DESC
      `;

    const topDepartment = await sql<{ department_name: string | null; delta_cents: string }[]>`
        WITH current_month AS (
          SELECT d.name, COALESCE(SUM(pi.amount_cents), 0) AS total
            FROM transactions t
            JOIN payment_instructions pi ON pi.id = t.instruction_id
            LEFT JOIN departments d ON d.id = pi.department_id
           WHERE t.organization_id = ${actor.organizationId} AND t.status = 'SUCCESS'
             AND t.completed_at >= date_trunc('month', now())
           GROUP BY d.name
        ), previous_month AS (
          SELECT d.name, COALESCE(SUM(pi.amount_cents), 0) AS total
            FROM transactions t
            JOIN payment_instructions pi ON pi.id = t.instruction_id
            LEFT JOIN departments d ON d.id = pi.department_id
           WHERE t.organization_id = ${actor.organizationId} AND t.status = 'SUCCESS'
             AND t.completed_at >= date_trunc('month', now() - interval '1 month')
             AND t.completed_at <  date_trunc('month', now())
           GROUP BY d.name
        )
        SELECT COALESCE(c.name, p.name) AS department_name,
               (COALESCE(c.total, 0) - COALESCE(p.total, 0)) AS delta_cents
          FROM current_month c
          FULL OUTER JOIN previous_month p ON p.name = c.name
         ORDER BY (COALESCE(c.total, 0) - COALESCE(p.total, 0)) DESC
         LIMIT 1
      `;

    const findings = await sql<{ open: string; reviewed: string }[]>`
        SELECT COUNT(*) FILTER (WHERE disposition = 'OPEN')     AS open,
               COUNT(*) FILTER (WHERE disposition <> 'OPEN')    AS reviewed
          FROM risk_findings
         WHERE organization_id = ${actor.organizationId}
           AND created_at > now() - interval '30 days'
      `;

    const unresolved = await sql<{ count: string }[]>`
        SELECT COUNT(*) AS count FROM reconciliation_cases
         WHERE organization_id = ${actor.organizationId} AND state IN ('OPEN', 'QUERYING', 'ESCALATED')
      `;

    const thisMonth = months[0] ? Number(months[0].total_cents) : 0;
    const lastMonth = months[1] ? Number(months[1].total_cents) : 0;
    const changePercent = lastMonth > 0 ? ((thisMonth - lastMonth) / lastMonth) * 100 : null;

    return {
      monthlyDisbursement: months.map((m) => ({
        period: m.period,
        totalCents: Number(m.total_cents),
        transactionCount: Number(m.count),
      })),
      monthOverMonth: {
        currentCents: thisMonth,
        previousCents: lastMonth,
        changePercent: changePercent === null ? null : Number(changePercent.toFixed(1)),
        largestMover: topDepartment[0]
          ? {
              departmentName: topDepartment[0].department_name ?? 'Unassigned',
              deltaCents: Number(topDepartment[0].delta_cents),
            }
          : null,
      },
      risk: {
        openFindings: Number(findings[0]?.open ?? 0),
        reviewedFindings: Number(findings[0]?.reviewed ?? 0),
      },
      unresolvedReconciliationCases: Number(unresolved[0]?.count ?? 0),
    };
  });

  return c.json(data);
});
