/**
 * Recipient and department master data (spec §5.1, §11 "RECENTLY_MODIFIED_RECIPIENT").
 *
 * A recipient record is the answer to "who does this money go to", and changing the phone
 * number on one is the cheapest payment fraud there is: no batch is touched, no approval is
 * sought, and next payroll the salary lands in the attacker's wallet. Every control here
 * exists for that attack.
 *
 *   - Changing `msisdn` stamps `payment_details_modified_at/by`, which the risk engine reads
 *     to raise RECENTLY_MODIFIED_RECIPIENT on any batch paying that recipient soon after.
 *   - The change is audited with both the old and the new number, so the trail shows what it
 *     was changed *from* — an audit entry saying only "recipient updated" is worthless here.
 *   - Recipients are deactivated, never deleted. A deleted recipient takes its payment
 *     history with it, and that history is the evidence an auditor needs.
 */

import { Hono } from 'hono';
import { z } from 'zod';
import {
  tryNormalizeMsisdn,
  notFoundError,
  validationError,
  statusTone,
  pageInfo,
  type TxnState,
} from '@solvaren/core';
import { requireAuth, requirePermissions, actorOf } from '../middleware/security.js';
import { withConnection, inTransaction } from '../db/client.js';
import { writeAuditEvent } from '../db/audit-writer.js';
import type { AppContext } from '../env.js';

export const recipientRoutes = new Hono<AppContext>();
recipientRoutes.use('*', requireAuth);

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const listQuerySchema = z.object({
  search: z.string().trim().max(120).optional(),
  status: z.enum(['ACTIVE', 'INACTIVE', 'BLOCKED']).optional(),
  departmentId: z.string().uuid().optional(),
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(200).default(25),
});

const msisdnField = z
  .string()
  .trim()
  .min(1)
  .transform((value, ctx) => {
    const parsed = tryNormalizeMsisdn(value);
    if (!parsed.ok || !parsed.msisdn) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: parsed.reason ?? 'Invalid phone number',
      });
      return z.NEVER;
    }
    return parsed.msisdn;
  });

const createSchema = z.object({
  fullName: z.string().trim().min(2).max(160),
  msisdn: msisdnField,
  departmentId: z.string().uuid().nullish(),
  externalReference: z.string().trim().max(64).nullish(),
});

const updateSchema = z.object({
  fullName: z.string().trim().min(2).max(160).optional(),
  msisdn: msisdnField.optional(),
  departmentId: z.string().uuid().nullish(),
  externalReference: z.string().trim().max(64).nullish(),
  status: z.enum(['ACTIVE', 'INACTIVE', 'BLOCKED']).optional(),
  /**
   * Required when the phone number changes. Not ceremony: the note is what a reviewer reads
   * six months later when the risk signal fires and they have to decide whether this change
   * was legitimate.
   */
  reason: z.string().trim().max(500).optional(),
});

interface RecipientRow {
  id: string;
  full_name: string;
  msisdn: string;
  status: string;
  external_reference: string | null;
  department_id: string | null;
  department_name: string | null;
  created_at: string;
  updated_at: string;
  payment_details_modified_at: string;
  total_count: string;
}

function present(row: RecipientRow) {
  return {
    id: row.id,
    fullName: row.full_name,
    msisdn: row.msisdn,
    status: row.status,
    externalReference: row.external_reference,
    departmentId: row.department_id,
    departmentName: row.department_name,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    paymentDetailsModifiedAt: row.payment_details_modified_at,
  };
}

/** GET /recipients — the master list, searchable by name, number or reference. */
recipientRoutes.get('/', requirePermissions('recipients:read'), async (c) => {
  const actor = actorOf(c);
  const query = listQuerySchema.parse(c.req.query());
  const offset = (query.page - 1) * query.pageSize;
  const search = query.search ? `%${query.search}%` : null;

  const result = await withConnection(c.env, async (sql) => {
    const rows = await sql<RecipientRow[]>`
      SELECT r.id, r.full_name, r.msisdn, r.status, r.external_reference,
             r.department_id, d.name AS department_name,
             r.created_at, r.updated_at, r.payment_details_modified_at,
             count(*) OVER ()::text AS total_count
        FROM recipients r
        LEFT JOIN departments d ON d.id = r.department_id
       WHERE r.organization_id = ${actor.organizationId}
         ${query.status ? sql`AND r.status = ${query.status}` : sql``}
         ${query.departmentId ? sql`AND r.department_id = ${query.departmentId}` : sql``}
         ${
           search
             ? sql`AND (r.full_name ILIKE ${search} OR r.msisdn ILIKE ${search}
                        OR r.external_reference ILIKE ${search})`
             : sql``
         }
       ORDER BY r.full_name ASC
       LIMIT ${query.pageSize} OFFSET ${offset}
    `;
    const totalRows = rows.length > 0 ? Number(rows[0]!.total_count) : 0;
    return { recipients: rows.map(present), page: pageInfo(query, totalRows) };
  });

  return c.json(result);
});

/** GET /recipients/departments — for the department picker and the departmental reports. */
recipientRoutes.get('/departments', requirePermissions('departments:read'), async (c) => {
  const actor = actorOf(c);
  const departments = await withConnection(c.env, async (sql) => {
    const rows = await sql<
      {
        id: string;
        name: string;
        code: string | null;
        status: string;
        monthly_budget_cents: string | null;
        recipient_count: string;
      }[]
    >`
      SELECT d.id, d.name, d.code, d.status, d.monthly_budget_cents,
             count(r.id) FILTER (WHERE r.status = 'ACTIVE')::text AS recipient_count
        FROM departments d
        LEFT JOIN recipients r ON r.department_id = d.id
       WHERE d.organization_id = ${actor.organizationId}
       GROUP BY d.id
       ORDER BY d.name ASC
    `;
    return rows.map((row) => ({
      id: row.id,
      name: row.name,
      code: row.code,
      status: row.status,
      monthlyBudgetCents: row.monthly_budget_cents ? Number(row.monthly_budget_cents) : null,
      recipientCount: Number(row.recipient_count),
    }));
  });
  return c.json({ departments });
});

const departmentSchema = z.object({
  name: z.string().trim().min(2).max(120),
  code: z.string().trim().max(32).nullish(),
  monthlyBudgetCents: z.number().int().min(0).nullish(),
});

/** POST /recipients/departments — L2 and above; departments scope the management reports. */
recipientRoutes.post('/departments', requirePermissions('departments:write'), async (c) => {
  const actor = actorOf(c);
  const body = departmentSchema.parse(await c.req.json());
  const correlationId = c.get('correlationId');

  const department = await withConnection(c.env, (sql) =>
    inTransaction(sql, async (tx) => {
      const existing = await tx<{ id: string }[]>`
        SELECT id FROM departments
         WHERE organization_id = ${actor.organizationId} AND lower(name) = lower(${body.name})
      `;
      if (existing[0]) {
        throw validationError(
          'DEPARTMENT_EXISTS',
          `A department named "${body.name}" already exists.`,
        );
      }
      const rows = await tx<{ id: string; name: string }[]>`
        INSERT INTO departments (organization_id, name, code, monthly_budget_cents)
        VALUES (${actor.organizationId}, ${body.name}, ${body.code ?? null},
                ${body.monthlyBudgetCents ?? null})
        RETURNING id, name
      `;
      await writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'ADMINISTRATION',
        action: 'department.created',
        objectType: 'Department',
        objectId: rows[0]!.id,
        outcome: 'SUCCESS',
        newState: { name: body.name, code: body.code ?? null },
        correlationId,
        securityContext: c.get('securityContext'),
      });
      return rows[0]!;
    }),
  );

  return c.json({ department: { id: department.id, name: department.name } }, 201);
});

/** POST /recipients — add one recipient to the master data. */
recipientRoutes.post('/', requirePermissions('recipients:write'), async (c) => {
  const actor = actorOf(c);
  const body = createSchema.parse(await c.req.json());
  const correlationId = c.get('correlationId');

  const created = await withConnection(c.env, (sql) =>
    inTransaction(sql, async (tx) => {
      // `recipients_msisdn_unique` would catch this, but a 500 from a constraint violation
      // tells the operator nothing about which record already holds the number.
      const clash = await tx<{ id: string; full_name: string; status: string }[]>`
        SELECT id, full_name, status FROM recipients
         WHERE organization_id = ${actor.organizationId} AND msisdn = ${body.msisdn}
      `;
      if (clash[0]) {
        throw validationError(
          'RECIPIENT_MSISDN_EXISTS',
          `${body.msisdn} already belongs to ${clash[0].full_name} (${clash[0].status}). Two master records for one number is how the same person gets paid twice.`,
          { recipientId: clash[0].id },
        );
      }

      const rows = await tx<{ id: string }[]>`
        INSERT INTO recipients (
          organization_id, full_name, msisdn, department_id, external_reference,
          created_by_user_id, payment_details_modified_by
        ) VALUES (
          ${actor.organizationId}, ${body.fullName}, ${body.msisdn},
          ${body.departmentId ?? null}, ${body.externalReference ?? null},
          ${actor.userId}, ${actor.userId}
        )
        RETURNING id
      `;

      await writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'ADMINISTRATION',
        action: 'recipient.created',
        objectType: 'Recipient',
        objectId: rows[0]!.id,
        outcome: 'SUCCESS',
        newState: { fullName: body.fullName, msisdn: body.msisdn },
        correlationId,
        securityContext: c.get('securityContext'),
      });
      return rows[0]!;
    }),
  );

  return c.json({ recipient: { id: created.id } }, 201);
});

/**
 * PATCH /recipients/:id — amend master data.
 *
 * The phone number is handled apart from every other field, because it is the only one that
 * changes where the money goes.
 */
recipientRoutes.patch('/:id', requirePermissions('recipients:write'), async (c) => {
  const actor = actorOf(c);
  const recipientId = c.req.param('id');
  const correlationId = c.get('correlationId');
  if (!UUID_PATTERN.test(recipientId)) {
    throw notFoundError('RECIPIENT_NOT_FOUND', 'That recipient could not be found');
  }
  const body = updateSchema.parse(await c.req.json());

  const result = await withConnection(c.env, (sql) =>
    inTransaction(sql, async (tx) => {
      const rows = await tx<
        {
          id: string;
          full_name: string;
          msisdn: string;
          status: string;
          department_id: string | null;
          external_reference: string | null;
        }[]
      >`
        SELECT id, full_name, msisdn, status, department_id, external_reference
          FROM recipients
         WHERE id = ${recipientId} AND organization_id = ${actor.organizationId}
         FOR UPDATE
      `;
      const row = rows[0];
      if (!row) throw notFoundError('RECIPIENT_NOT_FOUND', 'That recipient could not be found');

      const msisdnChanged = body.msisdn !== undefined && body.msisdn !== row.msisdn;

      if (msisdnChanged) {
        if (!body.reason || body.reason.length < 10) {
          throw validationError(
            'RECIPIENT_MSISDN_REASON_REQUIRED',
            'Changing where a recipient is paid requires a reason. It is recorded with the old and the new number.',
          );
        }
        const clash = await tx<{ id: string; full_name: string }[]>`
          SELECT id, full_name FROM recipients
           WHERE organization_id = ${actor.organizationId} AND msisdn = ${body.msisdn!}
             AND id <> ${recipientId}
        `;
        if (clash[0]) {
          throw validationError(
            'RECIPIENT_MSISDN_EXISTS',
            `${body.msisdn} already belongs to ${clash[0].full_name}.`,
            { recipientId: clash[0].id },
          );
        }

        /*
         * An instruction already sitting in an unreleased batch snapshots the *old* number.
         * Changing the master record here would leave the batch paying the previous wallet
         * with no sign anything happened, so the operator is told which batches to re-check.
         */
        const pending = await tx<{ batch_reference: string; state: string }[]>`
          SELECT DISTINCT b.batch_reference, b.state
            FROM payment_instructions pi
            JOIN payment_batches b ON b.id = pi.batch_id
           WHERE pi.recipient_id = ${recipientId}
             AND b.organization_id = ${actor.organizationId}
             AND b.state IN ('DRAFT', 'VALIDATED', 'SUBMITTED_TO_L2', 'L2_REVIEW',
                             'L3_READY', 'AUTHORIZATION_PENDING', 'AUTHORIZED', 'HELD')
           ORDER BY b.batch_reference
        `;

        await tx`
          UPDATE recipients
             SET msisdn = ${body.msisdn!},
                 payment_details_modified_at = now(),
                 payment_details_modified_by = ${actor.userId}
           WHERE id = ${recipientId}
        `;

        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'ADMINISTRATION',
          action: 'recipient.payment_details_changed',
          objectType: 'Recipient',
          objectId: recipientId,
          outcome: 'SUCCESS',
          previousState: { msisdn: row.msisdn },
          newState: { msisdn: body.msisdn },
          correlationId,
          securityContext: c.get('securityContext'),
          detail: {
            reason: body.reason,
            openBatches: pending.map((b) => b.batch_reference),
          },
        });

        // WARNING and not INFO: this is the shape of the account-swap attack, and the
        // Security Centre's unacknowledged-events count is what makes it visible.
        await tx`
          INSERT INTO security_events (organization_id, user_id, event_type, severity, description, detail)
          VALUES (
            ${actor.organizationId}, ${actor.userId}, 'RECIPIENT_PAYMENT_DETAILS_CHANGED', 'WARNING',
            ${`The payment number for ${row.full_name} was changed`},
            ${tx.json({ recipientId, from: row.msisdn, to: body.msisdn, reason: body.reason })}
          )
        `;
      }

      const fullName = body.fullName ?? row.full_name;
      const status = body.status ?? row.status;
      const departmentId =
        body.departmentId === undefined ? row.department_id : (body.departmentId ?? null);
      const externalReference =
        body.externalReference === undefined
          ? row.external_reference
          : (body.externalReference ?? null);

      const detailsChanged =
        fullName !== row.full_name ||
        status !== row.status ||
        departmentId !== row.department_id ||
        externalReference !== row.external_reference;

      if (detailsChanged) {
        await tx`
          UPDATE recipients
             SET full_name = ${fullName}, status = ${status},
                 department_id = ${departmentId}, external_reference = ${externalReference}
           WHERE id = ${recipientId}
        `;
        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'ADMINISTRATION',
          action: status !== row.status ? 'recipient.status_changed' : 'recipient.updated',
          objectType: 'Recipient',
          objectId: recipientId,
          outcome: 'SUCCESS',
          previousState: {
            fullName: row.full_name,
            status: row.status,
            departmentId: row.department_id,
            externalReference: row.external_reference,
          },
          newState: { fullName, status, departmentId, externalReference },
          correlationId,
          securityContext: c.get('securityContext'),
          detail: body.reason ? { reason: body.reason } : undefined,
        });
      }

      return { msisdnChanged, detailsChanged };
    }),
  );

  return c.json({
    updated: true,
    paymentDetailsChanged: result.msisdnChanged,
    message: result.msisdnChanged
      ? 'The payment number was changed. Any batch prepared before now still carries the old number and will raise a risk signal at review.'
      : 'The recipient has been updated.',
  });
});

/**
 * GET /recipients/:id — one recipient with its payment history.
 *
 * The history is the point. "Has this person been paid twice this month" and "did the
 * number change just before that payment" are questions the master record alone cannot
 * answer, and both are asked during a fraud investigation.
 */
recipientRoutes.get('/:id', requirePermissions('recipients:read'), async (c) => {
  const actor = actorOf(c);
  const recipientId = c.req.param('id');
  if (!UUID_PATTERN.test(recipientId)) {
    throw notFoundError('RECIPIENT_NOT_FOUND', 'That recipient could not be found');
  }

  const result = await withConnection(c.env, async (sql) => {
    const rows = await sql<RecipientRow[]>`
      SELECT r.id, r.full_name, r.msisdn, r.status, r.external_reference,
             r.department_id, d.name AS department_name,
             r.created_at, r.updated_at, r.payment_details_modified_at, '1' AS total_count
        FROM recipients r
        LEFT JOIN departments d ON d.id = r.department_id
       WHERE r.id = ${recipientId} AND r.organization_id = ${actor.organizationId}
       LIMIT 1
    `;
    const row = rows[0];
    if (!row) throw notFoundError('RECIPIENT_NOT_FOUND', 'That recipient could not be found');

    const history = await sql<
      {
        transaction_id: string;
        status: TxnState;
        amount_cents: string;
        msisdn_snapshot: string;
        batch_reference: string;
        mpesa_receipt_number: string | null;
        failure_reason: string | null;
        created_at: string;
        completed_at: string | null;
      }[]
    >`
      SELECT t.id AS transaction_id, t.status, pi.amount_cents, pi.msisdn_snapshot,
             b.batch_reference, t.mpesa_receipt_number, t.failure_reason,
             t.created_at, t.completed_at
        FROM transactions t
        JOIN payment_instructions pi ON pi.id = t.instruction_id
        JOIN payment_batches b       ON b.id = t.batch_id
       WHERE pi.recipient_id = ${recipientId} AND t.organization_id = ${actor.organizationId}
       ORDER BY t.created_at DESC
       LIMIT 100
    `;

    const totals = await sql<{ paid_cents: string | null; payments: string }[]>`
      SELECT sum(pi.amount_cents) FILTER (WHERE t.status = 'SUCCESS')::text AS paid_cents,
             count(*) FILTER (WHERE t.status = 'SUCCESS')::text AS payments
        FROM transactions t
        JOIN payment_instructions pi ON pi.id = t.instruction_id
       WHERE pi.recipient_id = ${recipientId} AND t.organization_id = ${actor.organizationId}
    `;

    const changes = await sql<
      { action: string; occurred_at: string; previous_state: unknown; new_state: unknown }[]
    >`
      SELECT action, occurred_at, previous_state, new_state
        FROM audit_events
       WHERE organization_id = ${actor.organizationId}
         AND object_type = 'Recipient' AND object_id = ${recipientId}
       ORDER BY sequence DESC
       LIMIT 50
    `;

    return {
      recipient: present(row),
      totals: {
        successfulPayments: Number(totals[0]?.payments ?? '0'),
        totalPaidCents: Number(totals[0]?.paid_cents ?? '0'),
      },
      history: history.map((h) => ({
        transactionId: h.transaction_id,
        status: h.status,
        statusTone: statusTone(h.status),
        amountCents: Number(h.amount_cents),
        /** The number at the time of payment, which may differ from the number today. */
        paidToMsisdn: h.msisdn_snapshot,
        batchReference: h.batch_reference,
        mpesaReceiptNumber: h.mpesa_receipt_number,
        failureReason: h.failure_reason,
        createdAt: h.created_at,
        completedAt: h.completed_at,
      })),
      changes,
    };
  });

  return c.json(result);
});
