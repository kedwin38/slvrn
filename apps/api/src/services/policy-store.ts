/**
 * Organisation policy loading (spec 20).
 *
 * Policy is read fresh on every release rather than cached: a limit an administrator
 * tightened five minutes ago must apply to the payroll being authorized now.
 */

import { DEFAULT_POLICY, policySchema, type OrganizationPolicy } from '@solvaren/core';
import type { Sql } from '../db/client.js';

export async function loadPolicy(sql: Sql, organizationId: string): Promise<OrganizationPolicy> {
  const rows = await sql<
    {
      max_instruction_amount_cents: string;
      max_batch_total_cents: string;
      max_batch_instructions: number;
      high_value_threshold_cents: string;
      cooling_off_seconds: number;
      blocking_risk_band: 'NEVER' | 'HIGH' | 'CRITICAL';
      allow_l1_failed_export: boolean;
      max_export_rows: number;
      daily_disbursement_ceiling_cents: string;
    }[]
  >`
    SELECT max_instruction_amount_cents, max_batch_total_cents, max_batch_instructions,
           high_value_threshold_cents, cooling_off_seconds, blocking_risk_band,
           allow_l1_failed_export, max_export_rows, daily_disbursement_ceiling_cents
      FROM policies
     WHERE organization_id = ${organizationId}
     LIMIT 1
  `;

  const row = rows[0];
  // An organisation with no policy row gets the platform defaults, which are the
  // conservative ones — never an absence of limits.
  if (!row) return DEFAULT_POLICY;

  return policySchema.parse({
    maxInstructionAmountCents: Number(row.max_instruction_amount_cents),
    maxBatchTotalCents: Number(row.max_batch_total_cents),
    maxBatchInstructions: row.max_batch_instructions,
    highValueThresholdCents: Number(row.high_value_threshold_cents),
    coolingOffSeconds: row.cooling_off_seconds,
    blockingRiskBand: row.blocking_risk_band,
    allowL1FailedExport: row.allow_l1_failed_export,
    maxExportRows: row.max_export_rows,
    dailyDisbursementCeilingCents: Number(row.daily_disbursement_ceiling_cents),
  });
}
