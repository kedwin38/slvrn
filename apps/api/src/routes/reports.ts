/**
 * Reporting (spec §12 — twelve report families).
 *
 * Only one report existed before this file: the failed-transactions CSV. Everything the
 * specification asks a finance function to answer at month end — what did we spend, on whom,
 * which department, what failed and why, who did what, is the provider healthy — had no
 * answer in the product.
 *
 * Three rules shape the implementation:
 *
 *   1. Every figure is computed from the ledger by SQL in this file. Nothing is derived from
 *      a cached counter that could drift from the transactions it claims to summarise.
 *   2. A report is generated for an explicit period, and the period is printed on the
 *      artefact. A CSV headed only "September" is worthless as evidence.
 *   3. Generation is recorded in `export_records` and audited, exactly as the transaction
 *      export is. A management report carries salary data; who took a copy is a question the
 *      organisation must be able to answer.
 *
 * Families are gated by permission, not by hiding a menu item: `reports:operational` for the
 * team's own work, `reports:management` for money across departments and people, and
 * `reports:executive` for the organisation-wide picture.
 */

import { Hono } from 'hono';
import { z } from 'zod';
import {
  reference,
  validationError,
  notFoundError,
  renderReportCsv,
  exportFilename,
  formatCents,
  type ReportDocument,
  type ReportSection,
  type Permission,
} from '@solvaren/core';
import { requireAuth, actorOf } from '../middleware/security.js';
import { requirePermission, hasPermission } from '@solvaren/core';
import { withConnection, inTransaction, type Sql } from '../db/client.js';
import { writeAuditEvent } from '../db/audit-writer.js';
import { toActor } from '../services/auth.js';
import type { AppContext } from '../env.js';

export const reportRoutes = new Hono<AppContext>();
reportRoutes.use('*', requireAuth);

type ExportType =
  | 'FAILED_TRANSACTIONS'
  | 'ALL_TRANSACTIONS'
  | 'BATCH_REPORT'
  | 'RECONCILIATION'
  | 'AUDIT'
  | 'MANAGEMENT'
  | 'EXECUTIVE';

interface FamilyDefinition {
  family: string;
  title: string;
  description: string;
  permission: Permission;
  exportType: ExportType;
  build: (ctx: BuildContext) => Promise<Pick<ReportDocument, 'sections' | 'highlights'>>;
}

interface BuildContext {
  sql: Sql;
  organizationId: string;
  from: string;
  to: string;
}

const money = { format: 'money' as const };

function section(
  title: string,
  columns: ReportSection['columns'],
  rows: ReportSection['rows'],
): ReportSection {
  return { title, columns, rows };
}

/**
 * The twelve families of §12.1.
 *
 * Each one is a period-bounded query over the ledger. `to` is exclusive at the SQL level —
 * a report for "1 to 30 September" that silently drops the 30th because of a `<` on a
 * timestamp is the classic month-end reporting bug.
 */
const FAMILIES: readonly FamilyDefinition[] = [
  {
    family: 'payment',
    title: 'Payment report',
    description:
      'Every disbursement attempted in the period, with its outcome and provider receipt.',
    permission: 'reports:operational',
    exportType: 'ALL_TRANSACTIONS',
    async build({ sql, organizationId, from, to }) {
      const rows = await sql<
        {
          batch_reference: string;
          recipient_name: string;
          msisdn: string;
          department_name: string | null;
          amount_cents: string;
          status: string;
          failure_code: string | null;
          failure_reason: string | null;
          mpesa_receipt_number: string | null;
          created_at: string;
          completed_at: string | null;
        }[]
      >`
        SELECT b.batch_reference, r.full_name AS recipient_name,
               pi.msisdn_snapshot AS msisdn, d.name AS department_name, pi.amount_cents,
               t.status, t.failure_code, t.failure_reason, t.mpesa_receipt_number,
               t.created_at, t.completed_at
          FROM transactions t
          JOIN payment_instructions pi ON pi.id = t.instruction_id
          JOIN payment_batches b       ON b.id = t.batch_id
          JOIN recipients r            ON r.id = pi.recipient_id
          LEFT JOIN departments d      ON d.id = pi.department_id
         WHERE t.organization_id = ${organizationId}
           AND t.created_at >= ${from} AND t.created_at < ${to}
         ORDER BY t.created_at ASC
         LIMIT 20000
      `;
      const totals = await totalsFor(sql, organizationId, from, to);
      return {
        highlights: paymentHighlights(totals),
        sections: [
          section(
            'Disbursements',
            [
              { key: 'batch', label: 'Batch' },
              { key: 'recipient', label: 'Recipient' },
              { key: 'msisdn', label: 'Phone' },
              { key: 'department', label: 'Department' },
              { key: 'amount', label: 'Amount (KES)', ...money },
              { key: 'status', label: 'Status' },
              { key: 'failureCode', label: 'Failure code' },
              { key: 'failureReason', label: 'Failure reason' },
              { key: 'receipt', label: 'M-PESA receipt' },
              { key: 'createdAt', label: 'Created' },
              { key: 'completedAt', label: 'Completed' },
            ],
            rows.map((row) => ({
              batch: row.batch_reference,
              recipient: row.recipient_name,
              msisdn: row.msisdn,
              department: row.department_name,
              amount: Number(row.amount_cents),
              status: row.status,
              failureCode: row.failure_code,
              failureReason: row.failure_reason,
              receipt: row.mpesa_receipt_number,
              createdAt: row.created_at,
              completedAt: row.completed_at,
            })),
          ),
        ],
      };
    },
  },
  {
    family: 'financial',
    title: 'Financial report',
    description:
      'Disbursed, failed and in-flight value for the period, broken down by day and by batch.',
    permission: 'reports:management',
    exportType: 'MANAGEMENT',
    async build({ sql, organizationId, from, to }) {
      const daily = await sql<
        { day: string; paid_cents: string; failed_cents: string; payments: string }[]
      >`
        SELECT to_char(date_trunc('day', t.created_at), 'YYYY-MM-DD') AS day,
               COALESCE(sum(pi.amount_cents) FILTER (WHERE t.status = 'SUCCESS'), 0)::text AS paid_cents,
               COALESCE(sum(pi.amount_cents) FILTER (WHERE t.status = 'FAILED'), 0)::text AS failed_cents,
               count(*)::text AS payments
          FROM transactions t
          JOIN payment_instructions pi ON pi.id = t.instruction_id
         WHERE t.organization_id = ${organizationId}
           AND t.created_at >= ${from} AND t.created_at < ${to}
         GROUP BY 1 ORDER BY 1
      `;
      const batches = await sql<
        {
          batch_reference: string;
          state: string;
          instruction_count: string;
          total_cents: string;
          paid_cents: string;
          created_at: string;
        }[]
      >`
        SELECT b.batch_reference, b.state, count(pi.id)::text AS instruction_count,
               COALESCE(sum(pi.amount_cents), 0)::text AS total_cents,
               COALESCE(sum(pi.amount_cents) FILTER (WHERE t.status = 'SUCCESS'), 0)::text AS paid_cents,
               b.created_at
          FROM payment_batches b
          LEFT JOIN payment_instructions pi ON pi.batch_id = b.id
          LEFT JOIN transactions t          ON t.instruction_id = pi.id
         WHERE b.organization_id = ${organizationId}
           AND b.created_at >= ${from} AND b.created_at < ${to}
         GROUP BY b.id ORDER BY b.created_at ASC
      `;
      const totals = await totalsFor(sql, organizationId, from, to);
      return {
        highlights: paymentHighlights(totals),
        sections: [
          section(
            'Daily movement',
            [
              { key: 'day', label: 'Date' },
              { key: 'payments', label: 'Payments', format: 'number' },
              { key: 'paid', label: 'Disbursed (KES)', ...money },
              { key: 'failed', label: 'Failed value (KES)', ...money },
            ],
            daily.map((row) => ({
              day: row.day,
              payments: Number(row.payments),
              paid: Number(row.paid_cents),
              failed: Number(row.failed_cents),
            })),
          ),
          section(
            'By batch',
            [
              { key: 'reference', label: 'Batch' },
              { key: 'state', label: 'State' },
              { key: 'count', label: 'Instructions', format: 'number' },
              { key: 'total', label: 'Batch value (KES)', ...money },
              { key: 'paid', label: 'Disbursed (KES)', ...money },
              { key: 'createdAt', label: 'Created' },
            ],
            batches.map((row) => ({
              reference: row.batch_reference,
              state: row.state,
              count: Number(row.instruction_count),
              total: Number(row.total_cents),
              paid: Number(row.paid_cents),
              createdAt: row.created_at,
            })),
          ),
        ],
      };
    },
  },
  {
    family: 'payroll',
    title: 'Payroll report',
    description:
      'What each recipient was paid in the period, and the number they were paid on at the time.',
    permission: 'reports:management',
    exportType: 'MANAGEMENT',
    async build({ sql, organizationId, from, to }) {
      const rows = await sql<
        {
          recipient_name: string;
          msisdn: string;
          department_name: string | null;
          payments: string;
          paid_cents: string;
          failed: string;
          last_paid_at: string | null;
        }[]
      >`
        SELECT r.full_name AS recipient_name, r.msisdn, d.name AS department_name,
               count(*) FILTER (WHERE t.status = 'SUCCESS')::text AS payments,
               COALESCE(sum(pi.amount_cents) FILTER (WHERE t.status = 'SUCCESS'), 0)::text AS paid_cents,
               count(*) FILTER (WHERE t.status = 'FAILED')::text AS failed,
               max(t.completed_at) FILTER (WHERE t.status = 'SUCCESS') AS last_paid_at
          FROM transactions t
          JOIN payment_instructions pi ON pi.id = t.instruction_id
          JOIN recipients r            ON r.id = pi.recipient_id
          LEFT JOIN departments d      ON d.id = pi.department_id
         WHERE t.organization_id = ${organizationId}
           AND t.created_at >= ${from} AND t.created_at < ${to}
         GROUP BY r.id, d.name
         ORDER BY paid_cents DESC
      `;
      const totalPaid = rows.reduce((sum, row) => sum + Number(row.paid_cents), 0);
      return {
        highlights: [
          {
            label: 'Recipients paid',
            value: String(rows.filter((r) => Number(r.payments) > 0).length),
          },
          { label: 'Total disbursed', value: `KES ${formatCents(totalPaid)}` },
        ],
        sections: [
          section(
            'Per recipient',
            [
              { key: 'recipient', label: 'Recipient' },
              { key: 'msisdn', label: 'Phone' },
              { key: 'department', label: 'Department' },
              { key: 'payments', label: 'Successful payments', format: 'number' },
              { key: 'paid', label: 'Total paid (KES)', ...money },
              { key: 'failed', label: 'Failed attempts', format: 'number' },
              { key: 'lastPaidAt', label: 'Last paid' },
            ],
            rows.map((row) => ({
              recipient: row.recipient_name,
              msisdn: row.msisdn,
              department: row.department_name,
              payments: Number(row.payments),
              paid: Number(row.paid_cents),
              failed: Number(row.failed),
              lastPaidAt: row.last_paid_at,
            })),
          ),
        ],
      };
    },
  },
  {
    family: 'department',
    title: 'Department report',
    description: 'Spend per department against budget, for the period.',
    permission: 'reports:management',
    exportType: 'MANAGEMENT',
    async build({ sql, organizationId, from, to }) {
      const rows = await sql<
        {
          department_name: string | null;
          monthly_budget_cents: string | null;
          recipients: string;
          payments: string;
          paid_cents: string;
          failed_cents: string;
        }[]
      >`
        SELECT COALESCE(d.name, '(no department)') AS department_name,
               max(d.monthly_budget_cents)::text AS monthly_budget_cents,
               count(DISTINCT pi.recipient_id)::text AS recipients,
               count(*) FILTER (WHERE t.status = 'SUCCESS')::text AS payments,
               COALESCE(sum(pi.amount_cents) FILTER (WHERE t.status = 'SUCCESS'), 0)::text AS paid_cents,
               COALESCE(sum(pi.amount_cents) FILTER (WHERE t.status = 'FAILED'), 0)::text AS failed_cents
          FROM transactions t
          JOIN payment_instructions pi ON pi.id = t.instruction_id
          LEFT JOIN departments d      ON d.id = pi.department_id
         WHERE t.organization_id = ${organizationId}
           AND t.created_at >= ${from} AND t.created_at < ${to}
         GROUP BY d.name
         ORDER BY paid_cents DESC
      `;
      return {
        highlights: [{ label: 'Departments with activity', value: String(rows.length) }],
        sections: [
          section(
            'Department spend',
            [
              { key: 'department', label: 'Department' },
              { key: 'recipients', label: 'Recipients', format: 'number' },
              { key: 'payments', label: 'Payments', format: 'number' },
              { key: 'paid', label: 'Disbursed (KES)', ...money },
              { key: 'failed', label: 'Failed value (KES)', ...money },
              { key: 'budget', label: 'Monthly budget (KES)', ...money },
              { key: 'overBudget', label: 'Over budget' },
            ],
            rows.map((row) => {
              const paid = Number(row.paid_cents);
              const budget = row.monthly_budget_cents ? Number(row.monthly_budget_cents) : null;
              return {
                department: row.department_name,
                recipients: Number(row.recipients),
                payments: Number(row.payments),
                paid,
                failed: Number(row.failed_cents),
                budget,
                overBudget: budget === null ? 'no budget set' : paid > budget ? 'YES' : 'no',
              };
            }),
          ),
        ],
      };
    },
  },
  {
    family: 'reconciliation',
    title: 'Reconciliation report',
    description:
      'Ambiguous outcomes opened in the period, how they were settled, and what remains open.',
    permission: 'reports:management',
    exportType: 'RECONCILIATION',
    async build({ sql, organizationId, from, to }) {
      const rows = await sql<
        {
          case_reference: string;
          state: string;
          opened_reason: string;
          discrepancy: boolean;
          query_attempts: string;
          opened_at: string;
          resolved_at: string | null;
          resolved_by: string | null;
          resolution_note: string | null;
          amount_cents: string;
          recipient_name: string;
          txn_status: string;
        }[]
      >`
        SELECT rc.case_reference, rc.state, rc.opened_reason, rc.discrepancy,
               rc.query_attempts::text, rc.opened_at, rc.resolved_at,
               u.full_name AS resolved_by, rc.resolution_note,
               pi.amount_cents, r.full_name AS recipient_name, t.status AS txn_status
          FROM reconciliation_cases rc
          JOIN transactions t          ON t.id = rc.transaction_id
          JOIN payment_instructions pi ON pi.id = t.instruction_id
          JOIN recipients r            ON r.id = pi.recipient_id
          LEFT JOIN users u            ON u.id = rc.resolved_by_user_id
         WHERE rc.organization_id = ${organizationId}
           AND rc.opened_at >= ${from} AND rc.opened_at < ${to}
         ORDER BY rc.opened_at ASC
      `;
      const open = rows.filter((r) => ['OPEN', 'QUERYING', 'ESCALATED'].includes(r.state));
      return {
        highlights: [
          { label: 'Cases opened', value: String(rows.length) },
          {
            label: 'Still open',
            value: String(open.length),
            hint: 'Every one of these is a payment whose outcome the organisation does not know.',
          },
          {
            label: 'Ledger discrepancies',
            value: String(rows.filter((r) => r.discrepancy).length),
          },
        ],
        sections: [
          section(
            'Cases',
            [
              { key: 'reference', label: 'Case' },
              { key: 'recipient', label: 'Recipient' },
              { key: 'amount', label: 'Amount (KES)', ...money },
              { key: 'txnStatus', label: 'Ledger status' },
              { key: 'state', label: 'Case state' },
              { key: 'reason', label: 'Opened because' },
              { key: 'discrepancy', label: 'Discrepancy' },
              { key: 'attempts', label: 'Status queries', format: 'number' },
              { key: 'openedAt', label: 'Opened' },
              { key: 'resolvedAt', label: 'Resolved' },
              { key: 'resolvedBy', label: 'Resolved by' },
              { key: 'note', label: 'Resolution note' },
            ],
            rows.map((row) => ({
              reference: row.case_reference,
              recipient: row.recipient_name,
              amount: Number(row.amount_cents),
              txnStatus: row.txn_status,
              state: row.state,
              reason: row.opened_reason,
              discrepancy: row.discrepancy ? 'YES' : 'no',
              attempts: Number(row.query_attempts),
              openedAt: row.opened_at,
              resolvedAt: row.resolved_at,
              resolvedBy: row.resolved_by,
              note: row.resolution_note,
            })),
          ),
        ],
      };
    },
  },
  {
    family: 'risk',
    title: 'Risk report',
    description:
      'Deterministic and AI-advisory risk findings raised in the period, and how they were dispositioned.',
    permission: 'reports:management',
    exportType: 'MANAGEMENT',
    async build({ sql, organizationId, from, to }) {
      const rows = await sql<
        {
          signal_type: string;
          severity: string;
          summary: string;
          source: string;
          disposition: string;
          batch_reference: string | null;
          created_at: string;
          dispositioned_by: string | null;
          disposition_note: string | null;
        }[]
      >`
        SELECT rf.signal_type, rf.severity, rf.summary, rf.source, rf.disposition,
               b.batch_reference, rf.created_at,
               u.full_name AS dispositioned_by, rf.disposition_note
          FROM risk_findings rf
          LEFT JOIN payment_batches b ON b.id = rf.batch_id
          LEFT JOIN users u           ON u.id = rf.dispositioned_by_user_id
         WHERE rf.organization_id = ${organizationId}
           AND rf.created_at >= ${from} AND rf.created_at < ${to}
         ORDER BY rf.created_at ASC
      `;
      const bySeverity = (sev: string) => rows.filter((r) => r.severity === sev).length;
      return {
        highlights: [
          { label: 'Findings raised', value: String(rows.length) },
          { label: 'Critical', value: String(bySeverity('CRITICAL')) },
          { label: 'High', value: String(bySeverity('HIGH')) },
          {
            label: 'Still open',
            value: String(rows.filter((r) => r.disposition === 'OPEN').length),
          },
        ],
        sections: [
          section(
            'Findings',
            [
              { key: 'createdAt', label: 'Raised' },
              { key: 'batch', label: 'Batch' },
              { key: 'signal', label: 'Signal' },
              { key: 'severity', label: 'Severity' },
              { key: 'summary', label: 'Summary' },
              { key: 'source', label: 'Source' },
              { key: 'disposition', label: 'Disposition' },
              { key: 'by', label: 'Dispositioned by' },
              { key: 'note', label: 'Note' },
            ],
            rows.map((row) => ({
              createdAt: row.created_at,
              batch: row.batch_reference,
              signal: row.signal_type,
              severity: row.severity,
              summary: row.summary,
              // AI findings are labelled in the data, not only in the UI: §11 forbids an
              // advisory signal being mistaken for a deterministic policy result.
              source: row.source === 'AI_ADVISORY' ? 'AI ADVISORY (not deterministic)' : row.source,
              disposition: row.disposition,
              by: row.dispositioned_by,
              note: row.disposition_note,
            })),
          ),
        ],
      };
    },
  },
  {
    family: 'audit',
    title: 'Audit report',
    description: 'The immutable audit trail for the period, in chain order, as written.',
    permission: 'reports:management',
    exportType: 'AUDIT',
    async build({ sql, organizationId, from, to }) {
      const rows = await sql<
        {
          sequence: string;
          occurred_at: string;
          event_class: string;
          action: string;
          object_type: string;
          object_id: string | null;
          outcome: string;
          actor_id: string;
          actor_level: string | null;
          correlation_id: string | null;
        }[]
      >`
        SELECT sequence::text, occurred_at, event_class, action, object_type, object_id,
               outcome, actor_id, actor_level, correlation_id
          FROM audit_events
         WHERE organization_id = ${organizationId}
           AND occurred_at >= ${from} AND occurred_at < ${to}
         ORDER BY sequence ASC
         LIMIT 50000
      `;
      return {
        highlights: [
          { label: 'Events', value: String(rows.length) },
          {
            label: 'Denied actions',
            value: String(rows.filter((r) => r.outcome === 'DENIED').length),
          },
        ],
        sections: [
          section(
            'Audit events',
            [
              { key: 'sequence', label: 'Seq', format: 'number' },
              { key: 'occurredAt', label: 'When' },
              { key: 'class', label: 'Class' },
              { key: 'action', label: 'Action' },
              { key: 'objectType', label: 'Object' },
              { key: 'objectId', label: 'Object id' },
              { key: 'outcome', label: 'Outcome' },
              { key: 'actor', label: 'Actor' },
              { key: 'level', label: 'Level' },
              { key: 'correlationId', label: 'Correlation' },
            ],
            rows.map((row) => ({
              sequence: Number(row.sequence),
              occurredAt: row.occurred_at,
              class: row.event_class,
              action: row.action,
              objectType: row.object_type,
              objectId: row.object_id,
              outcome: row.outcome,
              actor: row.actor_id,
              level: row.actor_level,
              correlationId: row.correlation_id,
            })),
          ),
        ],
      };
    },
  },
  {
    family: 'user-activity',
    title: 'User activity report',
    description: 'What each account did in the period, and what was refused to it.',
    permission: 'reports:management',
    exportType: 'MANAGEMENT',
    async build({ sql, organizationId, from, to }) {
      const rows = await sql<
        {
          full_name: string | null;
          email: string | null;
          authority_level: string | null;
          actor_id: string;
          events: string;
          denied: string;
          releases: string;
          last_action_at: string;
        }[]
      >`
        SELECT u.full_name, u.email, u.authority_level, ae.actor_id,
               count(*)::text AS events,
               count(*) FILTER (WHERE ae.outcome = 'DENIED')::text AS denied,
               count(*) FILTER (WHERE ae.action LIKE 'payment.release%')::text AS releases,
               max(ae.occurred_at) AS last_action_at
          FROM audit_events ae
          LEFT JOIN users u ON u.id::text = ae.actor_id
         WHERE ae.organization_id = ${organizationId}
           AND ae.occurred_at >= ${from} AND ae.occurred_at < ${to}
         GROUP BY u.full_name, u.email, u.authority_level, ae.actor_id
         ORDER BY events DESC
      `;
      return {
        highlights: [{ label: 'Active accounts', value: String(rows.length) }],
        sections: [
          section(
            'Activity',
            [
              { key: 'name', label: 'User' },
              { key: 'email', label: 'Email' },
              { key: 'level', label: 'Level' },
              { key: 'events', label: 'Actions', format: 'number' },
              { key: 'denied', label: 'Refused', format: 'number' },
              { key: 'releases', label: 'Payment releases', format: 'number' },
              { key: 'lastActionAt', label: 'Last action' },
            ],
            rows.map((row) => ({
              // System actors ("system:reconciliation-worker") have no users row, and
              // showing them as blank would read as a missing user rather than a job.
              name: row.full_name ?? row.actor_id,
              email: row.email,
              level: row.authority_level,
              events: Number(row.events),
              denied: Number(row.denied),
              releases: Number(row.releases),
              lastActionAt: row.last_action_at,
            })),
          ),
        ],
      };
    },
  },
  {
    family: 'system-activity',
    title: 'System activity report',
    description:
      'Background job health and security events for the period — the platform reporting on itself.',
    permission: 'reports:management',
    exportType: 'MANAGEMENT',
    async build({ sql, organizationId, from, to }) {
      const jobs = await sql<
        { queue: string; status: string; jobs: string; avg_attempts: string | null }[]
      >`
        SELECT queue, status, count(*)::text AS jobs,
               round(avg(attempts), 2)::text AS avg_attempts
          FROM job_queue
         WHERE organization_id = ${organizationId}
           AND created_at >= ${from} AND created_at < ${to}
         GROUP BY queue, status
         ORDER BY queue, status
      `;
      const events = await sql<
        { event_type: string; severity: string; occurrences: string; unacknowledged: string }[]
      >`
        SELECT event_type, severity, count(*)::text AS occurrences,
               count(*) FILTER (WHERE acknowledged_at IS NULL)::text AS unacknowledged
          FROM security_events
         WHERE organization_id = ${organizationId}
           AND created_at >= ${from} AND created_at < ${to}
         GROUP BY event_type, severity
         ORDER BY occurrences DESC
      `;
      const dead = jobs
        .filter((j) => j.status === 'DEAD_LETTER')
        .reduce((sum, j) => sum + Number(j.jobs), 0);
      return {
        highlights: [
          {
            label: 'Dead-lettered jobs',
            value: String(dead),
            hint: 'Work the platform could not complete and stopped retrying.',
          },
          {
            label: 'Unacknowledged security events',
            value: String(events.reduce((sum, e) => sum + Number(e.unacknowledged), 0)),
          },
        ],
        sections: [
          section(
            'Background jobs',
            [
              { key: 'queue', label: 'Queue' },
              { key: 'status', label: 'Status' },
              { key: 'jobs', label: 'Jobs', format: 'number' },
              { key: 'attempts', label: 'Average attempts' },
            ],
            jobs.map((row) => ({
              queue: row.queue,
              status: row.status,
              jobs: Number(row.jobs),
              attempts: row.avg_attempts,
            })),
          ),
          section(
            'Security events',
            [
              { key: 'type', label: 'Event' },
              { key: 'severity', label: 'Severity' },
              { key: 'count', label: 'Occurrences', format: 'number' },
              { key: 'open', label: 'Unacknowledged', format: 'number' },
            ],
            events.map((row) => ({
              type: row.event_type,
              severity: row.severity,
              count: Number(row.occurrences),
              open: Number(row.unacknowledged),
            })),
          ),
        ],
      };
    },
  },
  {
    family: 'daraja',
    title: 'Daraja integration report',
    description:
      'Provider behaviour for the period: acceptance, callbacks, timeouts and the failure codes M-PESA returned.',
    permission: 'reports:management',
    exportType: 'MANAGEMENT',
    async build({ sql, organizationId, from, to }) {
      const outcomes = await sql<{ status: string; count: string; avg_seconds: string | null }[]>`
        SELECT t.status, count(*)::text AS count,
               round(avg(EXTRACT(EPOCH FROM (t.completed_at - t.submitted_at))), 1)::text AS avg_seconds
          FROM transactions t
         WHERE t.organization_id = ${organizationId}
           AND t.created_at >= ${from} AND t.created_at < ${to}
         GROUP BY t.status ORDER BY count DESC
      `;
      const codes = await sql<
        { failure_code: string; failure_reason: string | null; count: string }[]
      >`
        SELECT t.failure_code, min(t.failure_reason) AS failure_reason, count(*)::text AS count
          FROM transactions t
         WHERE t.organization_id = ${organizationId}
           AND t.created_at >= ${from} AND t.created_at < ${to}
           AND t.failure_code IS NOT NULL
         GROUP BY t.failure_code ORDER BY count DESC
      `;
      const callbacks = await sql<{ callback_type: string; count: string }[]>`
        SELECT callback_type, count(*)::text AS count
          FROM provider_callbacks
         WHERE organization_id = ${organizationId}
           AND received_at >= ${from} AND received_at < ${to}
         GROUP BY callback_type ORDER BY count DESC
      `;
      const total = outcomes.reduce((sum, row) => sum + Number(row.count), 0);
      const succeeded = Number(outcomes.find((row) => row.status === 'SUCCESS')?.count ?? '0');
      return {
        highlights: [
          { label: 'Requests submitted', value: String(total) },
          {
            label: 'Provider success rate',
            value: total === 0 ? 'n/a' : `${((succeeded / total) * 100).toFixed(1)}%`,
          },
        ],
        sections: [
          section(
            'Outcomes',
            [
              { key: 'status', label: 'Status' },
              { key: 'count', label: 'Transactions', format: 'number' },
              { key: 'seconds', label: 'Mean seconds to settle' },
            ],
            outcomes.map((row) => ({
              status: row.status,
              count: Number(row.count),
              seconds: row.avg_seconds,
            })),
          ),
          section(
            'Failure codes returned',
            [
              { key: 'code', label: 'Code' },
              { key: 'reason', label: 'Reason' },
              { key: 'count', label: 'Occurrences', format: 'number' },
            ],
            codes.map((row) => ({
              code: row.failure_code,
              reason: row.failure_reason,
              count: Number(row.count),
            })),
          ),
          section(
            'Callbacks received',
            [
              { key: 'type', label: 'Callback' },
              { key: 'count', label: 'Deliveries', format: 'number' },
            ],
            callbacks.map((row) => ({ type: row.callback_type, count: Number(row.count) })),
          ),
        ],
      };
    },
  },
  {
    family: 'executive',
    title: 'Executive report',
    description:
      'The organisation-wide picture for the period, with the prior period for comparison.',
    permission: 'reports:executive',
    exportType: 'EXECUTIVE',
    async build({ sql, organizationId, from, to }) {
      const current = await totalsFor(sql, organizationId, from, to);
      // The same span immediately before, so "up or down" is a computed fact rather than an
      // impression.
      const span = new Date(to).getTime() - new Date(from).getTime();
      const priorFrom = new Date(new Date(from).getTime() - span).toISOString();
      const prior = await totalsFor(sql, organizationId, priorFrom, from);

      const departments = await sql<{ name: string | null; paid_cents: string }[]>`
        SELECT COALESCE(d.name, '(no department)') AS name,
               COALESCE(sum(pi.amount_cents) FILTER (WHERE t.status = 'SUCCESS'), 0)::text AS paid_cents
          FROM transactions t
          JOIN payment_instructions pi ON pi.id = t.instruction_id
          LEFT JOIN departments d      ON d.id = pi.department_id
         WHERE t.organization_id = ${organizationId}
           AND t.created_at >= ${from} AND t.created_at < ${to}
         GROUP BY d.name ORDER BY paid_cents DESC LIMIT 10
      `;

      const control = await sql<
        { open_cases: string; open_risk: string; unack_security: string; dead_jobs: string }[]
      >`
        SELECT
          (SELECT count(*) FROM reconciliation_cases
            WHERE organization_id = ${organizationId} AND state IN ('OPEN','QUERYING','ESCALATED'))::text AS open_cases,
          (SELECT count(*) FROM risk_findings
            WHERE organization_id = ${organizationId} AND disposition = 'OPEN')::text AS open_risk,
          (SELECT count(*) FROM security_events
            WHERE organization_id = ${organizationId} AND acknowledged_at IS NULL
              AND severity IN ('WARNING','CRITICAL'))::text AS unack_security,
          (SELECT count(*) FROM job_queue
            WHERE organization_id = ${organizationId} AND status = 'DEAD_LETTER')::text AS dead_jobs
      `;
      const c0 = control[0]!;

      const delta = current.paidCents - prior.paidCents;
      const deltaPct =
        prior.paidCents === 0 ? null : ((delta / prior.paidCents) * 100).toFixed(1) + '%';

      return {
        highlights: [
          { label: 'Disbursed', value: `KES ${formatCents(current.paidCents)}` },
          {
            label: 'Versus prior period',
            value:
              deltaPct === null
                ? 'no comparable prior period'
                : `${delta >= 0 ? '+' : ''}KES ${formatCents(delta)} (${deltaPct})`,
          },
          { label: 'Payments', value: String(current.succeeded) },
          {
            label: 'Failure rate',
            value:
              current.total === 0
                ? 'n/a'
                : `${((current.failed / current.total) * 100).toFixed(1)}%`,
          },
          {
            label: 'Unresolved control items',
            value: String(
              Number(c0.open_cases) +
                Number(c0.open_risk) +
                Number(c0.unack_security) +
                Number(c0.dead_jobs),
            ),
          },
        ],
        sections: [
          section(
            'Period comparison',
            [
              { key: 'metric', label: 'Metric' },
              { key: 'current', label: 'This period' },
              { key: 'prior', label: 'Prior period' },
            ],
            [
              {
                metric: 'Disbursed (KES)',
                current: formatCents(current.paidCents),
                prior: formatCents(prior.paidCents),
              },
              {
                metric: 'Successful payments',
                current: current.succeeded,
                prior: prior.succeeded,
              },
              { metric: 'Failed payments', current: current.failed, prior: prior.failed },
              {
                metric: 'Value failed (KES)',
                current: formatCents(current.failedCents),
                prior: formatCents(prior.failedCents),
              },
            ],
          ),
          section(
            'Largest departments',
            [
              { key: 'department', label: 'Department' },
              { key: 'paid', label: 'Disbursed (KES)', ...money },
            ],
            departments.map((row) => ({ department: row.name, paid: Number(row.paid_cents) })),
          ),
          section(
            'Control posture',
            [
              { key: 'item', label: 'Item' },
              { key: 'count', label: 'Outstanding', format: 'number' },
              { key: 'meaning', label: 'Why it matters' },
            ],
            [
              {
                item: 'Open reconciliation cases',
                count: Number(c0.open_cases),
                meaning: 'Payments whose outcome is unknown',
              },
              {
                item: 'Open risk findings',
                count: Number(c0.open_risk),
                meaning: 'Flagged and not yet dispositioned',
              },
              {
                item: 'Unacknowledged security events',
                count: Number(c0.unack_security),
                meaning: 'Warnings and critical events nobody has reviewed',
              },
              {
                item: 'Dead-lettered jobs',
                count: Number(c0.dead_jobs),
                meaning: 'Work the platform gave up on',
              },
            ],
          ),
        ],
      };
    },
  },
  {
    family: 'ai-intelligence',
    title: 'AI intelligence report',
    description:
      'Advisory analyses produced in the period. Every line is model-generated narrative, not a computed figure.',
    permission: 'reports:executive',
    exportType: 'EXECUTIVE',
    async build({ sql, organizationId, from, to }) {
      const rows = await sql<
        {
          capability: string;
          model: string;
          created_at: string;
          summary: string | null;
          prompt_summary: string;
          requested_by: string | null;
        }[]
      >`
        SELECT ai.capability, ai.model, ai.created_at, ai.prompt_summary,
               left(COALESCE(ai.response_summary, ''), 500) AS summary,
               u.full_name AS requested_by
          FROM ai_interactions ai
          LEFT JOIN users u ON u.id = ai.user_id
         WHERE ai.organization_id = ${organizationId}
           AND ai.created_at >= ${from} AND ai.created_at < ${to}
         ORDER BY ai.created_at DESC
         LIMIT 500
      `;
      return {
        highlights: [
          { label: 'Analyses produced', value: String(rows.length) },
          {
            label: 'Authority',
            value: 'advisory only',
            hint: 'The AI layer cannot authorize, release, or alter a payment.',
          },
        ],
        sections: [
          section(
            'Analyses',
            [
              { key: 'createdAt', label: 'When' },
              { key: 'type', label: 'Analysis' },
              { key: 'model', label: 'Model' },
              { key: 'requestedBy', label: 'Requested by' },
              { key: 'asked', label: 'What was asked' },
              { key: 'summary', label: 'Summary (AI-generated)' },
            ],
            rows.map((row) => ({
              createdAt: row.created_at,
              asked: row.prompt_summary,
              type: row.capability,
              model: row.model,
              requestedBy: row.requested_by,
              summary: row.summary,
            })),
          ),
        ],
      };
    },
  },
];

interface PeriodTotals {
  total: number;
  succeeded: number;
  failed: number;
  paidCents: number;
  failedCents: number;
  inFlight: number;
}

async function totalsFor(
  sql: Sql,
  organizationId: string,
  from: string,
  to: string,
): Promise<PeriodTotals> {
  const rows = await sql<
    {
      total: string;
      succeeded: string;
      failed: string;
      paid_cents: string;
      failed_cents: string;
      in_flight: string;
    }[]
  >`
    SELECT count(*)::text AS total,
           count(*) FILTER (WHERE t.status = 'SUCCESS')::text AS succeeded,
           count(*) FILTER (WHERE t.status = 'FAILED')::text AS failed,
           count(*) FILTER (WHERE t.status NOT IN ('SUCCESS','FAILED','CANCELLED'))::text AS in_flight,
           COALESCE(sum(pi.amount_cents) FILTER (WHERE t.status = 'SUCCESS'), 0)::text AS paid_cents,
           COALESCE(sum(pi.amount_cents) FILTER (WHERE t.status = 'FAILED'), 0)::text AS failed_cents
      FROM transactions t
      JOIN payment_instructions pi ON pi.id = t.instruction_id
     WHERE t.organization_id = ${organizationId}
       AND t.created_at >= ${from} AND t.created_at < ${to}
  `;
  const row = rows[0]!;
  return {
    total: Number(row.total),
    succeeded: Number(row.succeeded),
    failed: Number(row.failed),
    inFlight: Number(row.in_flight),
    paidCents: Number(row.paid_cents),
    failedCents: Number(row.failed_cents),
  };
}

function paymentHighlights(totals: PeriodTotals): ReportDocument['highlights'] {
  return [
    { label: 'Disbursed', value: `KES ${formatCents(totals.paidCents)}` },
    { label: 'Successful payments', value: String(totals.succeeded) },
    { label: 'Failed payments', value: String(totals.failed) },
    { label: 'Value failed', value: `KES ${formatCents(totals.failedCents)}` },
    {
      label: 'Still in flight',
      value: String(totals.inFlight),
      hint: 'Submitted to M-PESA with no final outcome yet.',
    },
  ];
}

/**
 * GET /reports — the catalogue, filtered to what this caller may actually generate.
 *
 * Returning the full list and letting the console hide rows would put the authority decision
 * in the browser. The server decides; the console renders whatever it is given.
 */
reportRoutes.get('/', async (c) => {
  const actor = toActor(actorOf(c));
  return c.json({
    reports: FAMILIES.filter((family) => hasPermission(actor, family.permission)).map((family) => ({
      family: family.family,
      title: family.title,
      description: family.description,
      permission: family.permission,
    })),
  });
});

const periodSchema = z
  .object({
    from: z.string().datetime({ offset: true }).or(z.string().date()),
    to: z.string().datetime({ offset: true }).or(z.string().date()),
    format: z.enum(['json', 'csv']).default('json'),
  })
  .transform((value) => ({
    // A bare date means the whole day in the organisation's terms: `to` becomes the start of
    // the following day so the last day of a month is included rather than silently dropped.
    from: value.from.includes('T') ? value.from : `${value.from}T00:00:00.000Z`,
    to: value.to.includes('T')
      ? value.to
      : new Date(new Date(`${value.to}T00:00:00.000Z`).getTime() + 86_400_000).toISOString(),
    format: value.format,
  }));

reportRoutes.get('/:family', async (c) => {
  const actor = actorOf(c);
  const familyName = c.req.param('family').replace(/\.csv$/, '');
  const definition = FAMILIES.find((f) => f.family === familyName);
  if (!definition) {
    throw notFoundError('REPORT_NOT_FOUND', `There is no report called "${familyName}"`);
  }
  requirePermission(toActor(actor), definition.permission);

  const query = periodSchema.parse(c.req.query());
  if (new Date(query.to) <= new Date(query.from)) {
    throw validationError('REPORT_PERIOD_INVALID', 'The end of the period must be after its start');
  }

  const correlationId = c.get('correlationId');
  const generatedAt = new Date().toISOString();
  const exportReference = reference('EXP');

  const { document, organizationSlug, exportId } = await withConnection(c.env, async (sql) => {
    const built = await definition.build({
      sql,
      organizationId: actor.organizationId,
      from: query.from,
      to: query.to,
    });

    const document: ReportDocument = {
      family: definition.family,
      title: definition.title,
      description: definition.description,
      periodFrom: query.from,
      periodTo: query.to,
      sections: built.sections,
      highlights: built.highlights,
      narrative: null,
    };

    const rowCount = built.sections.reduce((sum, s) => sum + s.rows.length, 0);
    const filterDescription = `${definition.title} for ${query.from} to ${query.to}`;

    const organization = await sql<{ slug: string }[]>`
      SELECT slug FROM organizations WHERE id = ${actor.organizationId}
    `;

    /*
     * Recorded whether the caller asked for JSON or CSV. A management report read on screen
     * discloses the same salary data as one downloaded, and an access log that only notices
     * downloads answers the wrong question after a leak.
     */
    const exportId = await inTransaction(sql, async (tx) => {
      const rows = await tx<{ id: string }[]>`
        INSERT INTO export_records (
          organization_id, export_reference, export_type, requested_by_user_id,
          requested_by_level, filter_description, filter_json, row_count, status,
          completed_at, correlation_id
        ) VALUES (
          ${actor.organizationId}, ${exportReference}, ${definition.exportType}, ${actor.userId},
          ${actor.level}, ${filterDescription},
          ${tx.json({ family: definition.family, from: query.from, to: query.to, format: query.format })},
          ${rowCount}, 'COMPLETED', now(), ${correlationId}
        )
        RETURNING id
      `;
      await writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'DATA_EXPORT',
        action: 'report.generated',
        objectType: 'Report',
        objectId: rows[0]!.id,
        outcome: 'SUCCESS',
        correlationId,
        securityContext: c.get('securityContext'),
        detail: {
          family: definition.family,
          format: query.format,
          rowCount,
          periodFrom: query.from,
          periodTo: query.to,
        },
      });
      return rows[0]!.id;
    });

    return { document, organizationSlug: organization[0]?.slug ?? 'organization', exportId };
  });

  if (query.format === 'csv') {
    const csv = renderReportCsv(document, {
      exportId: exportReference,
      organizationId: actor.organizationId,
      generatedAt,
      generatedByUserId: actor.userId,
      generatedByLevel: actor.level,
      filterDescription: `${document.title}, ${query.from} to ${query.to}`,
      rowCount: document.sections.reduce((sum, s) => sum + s.rows.length, 0),
    });
    return new Response(csv, {
      headers: {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': `attachment; filename="${exportFilename(
          `report_${definition.family}`,
          organizationSlug,
          generatedAt,
        )}"`,
        'Cache-Control': 'no-store',
      },
    });
  }

  return c.json({ report: document, exportId, exportReference, generatedAt });
});
