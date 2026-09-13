/**
 * Organization payment policy: limits, thresholds and approval rules (spec §4.3, §20).
 *
 * Policy is data, not code, so that an organization can tighten its own controls without a
 * deploy — but the *evaluation* is code, and it runs server-side on every release attempt.
 */

import { z } from 'zod';
import { policyError } from './errors.js';
import { formatCents, DARAJA_B2C_MAX_CENTS } from './money.js';
import type { RiskAssessment } from './risk.js';

export const policySchema = z.object({
  /** Largest single instruction the organization permits. Capped by the M-PESA limit. */
  maxInstructionAmountCents: z.number().int().min(1000).max(DARAJA_B2C_MAX_CENTS),
  /** Largest total a single batch may release. */
  maxBatchTotalCents: z.number().int().min(1000),
  /** Largest number of instructions in one batch. */
  maxBatchInstructions: z.number().int().min(1).max(20_000),
  /** Batch totals at or above this require a second L3 acknowledgement of the risk report. */
  highValueThresholdCents: z.number().int().min(0),
  /** Seconds that must elapse between the last material edit and submission. */
  coolingOffSeconds: z.number().int().min(0).max(86_400),
  /** Risk band at or above which release is blocked until findings are dispositioned. */
  blockingRiskBand: z.enum(['NEVER', 'HIGH', 'CRITICAL']),
  /** Whether L1 may download the failed-transactions CSV (§28). */
  allowL1FailedExport: z.boolean(),
  /** Maximum rows in a single synchronous export. */
  maxExportRows: z.number().int().min(100).max(100_000),
  /** Daily ceiling on total disbursement, as a circuit breaker. 0 disables. */
  dailyDisbursementCeilingCents: z.number().int().min(0),
});

export type OrganizationPolicy = z.infer<typeof policySchema>;

export const DEFAULT_POLICY: OrganizationPolicy = {
  maxInstructionAmountCents: DARAJA_B2C_MAX_CENTS,
  maxBatchTotalCents: 50_000_000_00,
  maxBatchInstructions: 5_000,
  highValueThresholdCents: 5_000_000_00,
  coolingOffSeconds: 300,
  blockingRiskBand: 'CRITICAL',
  allowL1FailedExport: true,
  maxExportRows: 50_000,
  dailyDisbursementCeilingCents: 0,
};

export interface PolicyEvaluationInput {
  policy: OrganizationPolicy;
  instructionCount: number;
  totalAmountCents: number;
  maxInstructionAmountCents: number;
  risk: RiskAssessment;
  /** Findings the reviewer has explicitly dispositioned (acknowledged or cleared). */
  dispositionedFindingCount: number;
  /** Total already disbursed today, for the circuit breaker. */
  disbursedTodayCents: number;
}

export interface PolicyEvaluation {
  allowed: boolean;
  violations: { code: string; message: string }[];
  /** Conditions the authorizer must explicitly acknowledge in the release ceremony. */
  acknowledgementsRequired: string[];
}

/**
 * Evaluate every policy gate. Returns a full list rather than failing on the first —
 * an operator fixing one limit only to discover another is a bad experience during a
 * payroll run.
 */
export function evaluateReleasePolicy(input: PolicyEvaluationInput): PolicyEvaluation {
  const { policy, risk } = input;
  const violations: { code: string; message: string }[] = [];
  const acknowledgementsRequired: string[] = [];

  if (input.instructionCount > policy.maxBatchInstructions) {
    violations.push({
      code: 'POLICY_BATCH_SIZE',
      message: `This batch has ${input.instructionCount} instructions; organization policy permits at most ${policy.maxBatchInstructions}.`,
    });
  }
  if (input.maxInstructionAmountCents > policy.maxInstructionAmountCents) {
    violations.push({
      code: 'POLICY_INSTRUCTION_LIMIT',
      message: `An instruction of KES ${formatCents(input.maxInstructionAmountCents)} exceeds the per-payment limit of KES ${formatCents(policy.maxInstructionAmountCents)}.`,
    });
  }
  if (input.totalAmountCents > policy.maxBatchTotalCents) {
    violations.push({
      code: 'POLICY_BATCH_TOTAL',
      message: `The batch total of KES ${formatCents(input.totalAmountCents)} exceeds the per-batch limit of KES ${formatCents(policy.maxBatchTotalCents)}.`,
    });
  }
  if (
    policy.dailyDisbursementCeilingCents > 0 &&
    input.disbursedTodayCents + input.totalAmountCents > policy.dailyDisbursementCeilingCents
  ) {
    violations.push({
      code: 'POLICY_DAILY_CEILING',
      message: `Releasing this batch would take today's disbursements to KES ${formatCents(input.disbursedTodayCents + input.totalAmountCents)}, above the daily ceiling of KES ${formatCents(policy.dailyDisbursementCeilingCents)}.`,
    });
  }

  const bandRank = { LOW: 0, ELEVATED: 1, HIGH: 2, CRITICAL: 3 } as const;
  const blockRank = policy.blockingRiskBand === 'NEVER' ? 99 : bandRank[policy.blockingRiskBand];
  const openFindings = risk.signals.length - input.dispositionedFindingCount;
  if (bandRank[risk.band] >= blockRank && openFindings > 0) {
    violations.push({
      code: 'POLICY_RISK_BLOCK',
      message: `This batch scored ${risk.score} (${risk.band}) with ${openFindings} finding(s) not yet dispositioned. Organization policy blocks release at ${policy.blockingRiskBand} until every finding is reviewed.`,
    });
  }

  if (input.totalAmountCents >= policy.highValueThresholdCents && policy.highValueThresholdCents > 0) {
    acknowledgementsRequired.push(
      `This is a high-value release of KES ${formatCents(input.totalAmountCents)} to ${input.instructionCount} recipients.`,
    );
  }
  if (risk.requiresAcknowledgement) {
    acknowledgementsRequired.push(
      `The risk assessment scored ${risk.score} (${risk.band}) with ${risk.signals.length} finding(s).`,
    );
  }

  return { allowed: violations.length === 0, violations, acknowledgementsRequired };
}

/** Throwing wrapper for the release path. */
export function assertReleasePolicy(input: PolicyEvaluationInput): PolicyEvaluation {
  const result = evaluateReleasePolicy(input);
  if (!result.allowed) {
    throw policyError('POLICY_VIOLATION', result.violations[0]!.message, { violations: result.violations });
  }
  return result;
}
