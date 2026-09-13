/**
 * Risk assessment against live data (spec 11).
 *
 * The scoring itself lives in @solvaren/core and is pure. This module's only job is to
 * gather the evidence it needs, and to persist findings so they can be dispositioned by a
 * human before release. Findings are written per batch *version*: an edit invalidates the
 * previous assessment along with the previous approval.
 */

import {
  assessBatchRisk,
  detectApprovalChainConcentration,
  DEFAULT_RISK_POLICY,
  type RiskAssessment,
  type RiskPolicy,
  type RecipientHistory,
  type InstructionForRisk,
  type OrganizationPolicy,
} from '@solvaren/core';
import { uuidSet, uuidArrayValue, type Sql } from '../db/client.js';

export interface RiskBatchRow {
  id: string;
  organization_id: string;
  version: number;
  last_material_edit_at: string | null;
  submitted_at: string | null;
  department_id?: string | null;
}

export async function assessBatch(
  tx: Sql,
  batch: RiskBatchRow,
  policy: OrganizationPolicy,
): Promise<RiskAssessment> {
  const instructions = await tx<
    { id: string; recipient_id: string; msisdn_snapshot: string; amount_cents: string; department_id: string | null }[]
  >`
    SELECT id, recipient_id, msisdn_snapshot, amount_cents, department_id
      FROM payment_instructions
     WHERE batch_id = ${batch.id}
  `;

  const recipientIds = instructions.map((i) => i.recipient_id);
  const history = new Map<string, RecipientHistory>();

  if (recipientIds.length > 0) {
    const rows = await tx<
      {
        recipient_id: string;
        mean_amount_cents: string;
        successful_payment_count: string;
        first_paid_at: string | null;
        recipient_created_at: string;
        payment_details_modified_at: string;
      }[]
    >`
      SELECT recipient_id, mean_amount_cents, successful_payment_count, first_paid_at,
             recipient_created_at, payment_details_modified_at
        FROM recipient_payment_history
       WHERE organization_id = ${batch.organization_id}
         AND recipient_id = ANY(${uuidSet(tx, recipientIds)})
    `;
    for (const row of rows) {
      history.set(row.recipient_id, {
        recipientId: row.recipient_id,
        meanAmountCents: Number(row.mean_amount_cents),
        paymentCount: Number(row.successful_payment_count),
        firstPaidAt: row.first_paid_at ? new Date(row.first_paid_at).getTime() : null,
        recipientCreatedAt: new Date(row.recipient_created_at).getTime(),
        recipientLastModifiedAt: new Date(row.payment_details_modified_at).getTime(),
      });
    }
  }

  // Trailing comparable batches for the total-deviation signal. Restricted to settled
  // batches, because comparing against another in-flight batch compares noise to noise.
  const priorTotals = await tx<{ total_amount_cents: string }[]>`
    SELECT total_amount_cents
      FROM payment_batches
     WHERE organization_id = ${batch.organization_id}
       AND id <> ${batch.id}
       AND state IN ('SUCCESS', 'PARTIAL_SUCCESS')
     ORDER BY settled_at DESC NULLS LAST
     LIMIT 6
  `;

  const unresolved = await tx<{ count: string }[]>`
    SELECT COUNT(*) AS count FROM reconciliation_cases
     WHERE organization_id = ${batch.organization_id} AND state IN ('OPEN', 'QUERYING')
  `;

  const pairs = await tx<{ approved_by_user_id: string; authorized_by_user_id: string; authorized_at: string }[]>`
    SELECT approved_by_user_id, authorized_by_user_id, authorized_at
      FROM payment_batches
     WHERE organization_id = ${batch.organization_id}
       AND approved_by_user_id IS NOT NULL AND authorized_by_user_id IS NOT NULL
     ORDER BY authorized_at DESC
     LIMIT 20
  `;
  const concentration = detectApprovalChainConcentration({
    recentPairs: pairs.map((p) => ({
      approverUserId: p.approved_by_user_id,
      authorizerUserId: p.authorized_by_user_id,
      at: new Date(p.authorized_at).getTime(),
    })),
  });

  const riskPolicy: RiskPolicy = {
    ...DEFAULT_RISK_POLICY,
    acknowledgementThreshold: DEFAULT_RISK_POLICY.acknowledgementThreshold,
    lateEditWindowMinutes: DEFAULT_RISK_POLICY.lateEditWindowMinutes,
  };

  const forRisk: InstructionForRisk[] = instructions.map((i) => ({
    instructionId: i.id,
    recipientId: i.recipient_id,
    msisdn: i.msisdn_snapshot,
    amountCents: Number(i.amount_cents),
    departmentId: i.department_id,
  }));

  const assessment = assessBatchRisk({
    instructions: forRisk,
    history,
    priorBatchTotalsCents: priorTotals.map((t) => Number(t.total_amount_cents)),
    now: Date.now(),
    lastMaterialEditAt: batch.last_material_edit_at ? new Date(batch.last_material_edit_at).getTime() : null,
    submittedAt: batch.submitted_at ? new Date(batch.submitted_at).getTime() : null,
    unresolvedReconciliationCount: Number(unresolved[0]?.count ?? 0),
    approvalConcentration: concentration.map((c) => ({
      pair: c.pair,
      shareOfRecent: c.shareOfRecent,
      occurrences: c.occurrences,
    })),
    policy: riskPolicy,
  });

  void policy; // organisation limits are applied by the policy engine, not the risk model
  return assessment;
}

/**
 * Persist findings for the current batch version.
 *
 * Existing findings for this version are left untouched so that a disposition already
 * recorded by a reviewer is not silently cleared by a re-assessment.
 */
export async function persistFindings(
  tx: Sql,
  batch: RiskBatchRow,
  assessment: RiskAssessment,
): Promise<void> {
  const existing = await tx<{ signal_type: string; summary: string }[]>`
    SELECT signal_type, summary FROM risk_findings
     WHERE batch_id = ${batch.id} AND batch_version = ${batch.version}
  `;
  const seen = new Set(existing.map((e) => `${e.signal_type}::${e.summary}`));

  for (const signal of assessment.signals) {
    if (seen.has(`${signal.type}::${signal.summary}`)) continue;
    await tx`
      INSERT INTO risk_findings (
        organization_id, batch_id, batch_version, signal_type, severity, summary,
        evidence, instruction_ids, source
      ) VALUES (
        ${batch.organization_id}, ${batch.id}, ${batch.version}, ${signal.type},
        ${signal.severity}, ${signal.summary}, ${tx.json(signal.evidence as never)},
        ${uuidArrayValue(tx, signal.instructionIds)}, 'DETERMINISTIC'
      )
    `;
  }
}
