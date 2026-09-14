/**
 * Deterministic risk and fraud signals (spec §11).
 *
 * The decision model is: evidence → deterministic policy → (optional) AI analysis →
 * risk score + reasons → human review → auditable action. This module is the
 * *deterministic* half, and it is deliberately the half that can block. The AI layer in
 * `apps/api/src/services/ai.ts` may add narrative and additional soft signals, but it
 * cannot clear a finding raised here and it cannot authorize a payment (§11 AI CONTROL).
 *
 * Every signal is explainable: it carries the evidence that produced it, because
 * "risk score 78" is not something a finance officer can act on.
 */

import { formatCents } from './money.js';
import { maskMsisdn } from './msisdn.js';

export type RiskSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export const SEVERITY_WEIGHT: Record<RiskSeverity, number> = {
  INFO: 0,
  LOW: 5,
  MEDIUM: 15,
  HIGH: 30,
  CRITICAL: 50,
};

export type RiskSignalType =
  | 'DUPLICATE_INSTRUCTION'
  | 'AMOUNT_DEVIATION'
  | 'NEW_RECIPIENT'
  | 'RECENTLY_MODIFIED_RECIPIENT'
  | 'DEPARTMENT_VARIANCE'
  | 'UNUSUAL_TIMING'
  | 'LATE_EDIT'
  | 'BATCH_TOTAL_DEVIATION'
  | 'UNRESOLVED_RECONCILIATION'
  | 'APPROVAL_CHAIN_CONCENTRATION'
  | 'ROUND_NUMBER_CLUSTER';

export interface RiskSignal {
  type: RiskSignalType;
  severity: RiskSeverity;
  /** One sentence a finance officer can act on. */
  summary: string;
  /** Structured evidence backing the summary — rendered as a detail table in the UI. */
  evidence: Record<string, unknown>;
  /** Instruction ids the signal concerns, when it is row-level. */
  instructionIds: string[];
}

export interface RiskAssessment {
  score: number; // 0-100
  band: 'LOW' | 'ELEVATED' | 'HIGH' | 'CRITICAL';
  signals: RiskSignal[];
  /** True when organization policy requires explicit acknowledgement before approval. */
  requiresAcknowledgement: boolean;
}

export interface InstructionForRisk {
  instructionId: string;
  recipientId: string;
  msisdn: string;
  amountCents: number;
  departmentId: string | null;
}

export interface RecipientHistory {
  recipientId: string;
  /** Mean of prior successful payments to this recipient, in cents. */
  meanAmountCents: number;
  paymentCount: number;
  firstPaidAt: number | null;
  recipientCreatedAt: number;
  recipientLastModifiedAt: number;
}

export interface RiskInput {
  instructions: readonly InstructionForRisk[];
  history: ReadonlyMap<string, RecipientHistory>;
  /** Totals of the previous N comparable batches, for batch-level deviation. */
  priorBatchTotalsCents: readonly number[];
  now: number;
  lastMaterialEditAt: number | null;
  submittedAt: number | null;
  unresolvedReconciliationCount: number;
  approvalConcentration: readonly { pair: string; shareOfRecent: number; occurrences: number }[];
  policy: RiskPolicy;
}

export interface RiskPolicy {
  /** Flag when an amount deviates from the recipient's mean by more than this multiple. */
  amountDeviationMultiple: number;
  /** A recipient created within this many hours is "new". */
  newRecipientWindowHours: number;
  /** Batch total deviating from the trailing mean by more than this fraction is flagged. */
  batchTotalDeviationFraction: number;
  /** Edits within this many minutes of submission are "late". */
  lateEditWindowMinutes: number;
  /** Score at or above which explicit acknowledgement is required before approval. */
  acknowledgementThreshold: number;
  /** Business hours in the organization's timezone, as UTC hours. */
  businessHoursUtc: { start: number; end: number };
}

export const DEFAULT_RISK_POLICY: RiskPolicy = {
  amountDeviationMultiple: 2.5,
  newRecipientWindowHours: 72,
  batchTotalDeviationFraction: 0.25,
  lateEditWindowMinutes: 10,
  acknowledgementThreshold: 40,
  businessHoursUtc: { start: 4, end: 16 }, // ~07:00–19:00 East Africa Time
};

const HOUR_MS = 3_600_000;

function mean(values: readonly number[]): number {
  if (values.length === 0) return 0;
  return values.reduce((a, b) => a + b, 0) / values.length;
}

/** Pure, synchronous, fully deterministic assessment. Same input → same score, always. */
export function assessBatchRisk(input: RiskInput): RiskAssessment {
  const { instructions, history, policy, now } = input;
  const signals: RiskSignal[] = [];

  // ---- Duplicate instructions within the batch ----------------------------
  const byRecipientAmount = new Map<string, InstructionForRisk[]>();
  for (const i of instructions) {
    const key = `${i.msisdn}:${i.amountCents}`;
    byRecipientAmount.set(key, [...(byRecipientAmount.get(key) ?? []), i]);
  }
  for (const [, group] of byRecipientAmount) {
    if (group.length > 1) {
      const first = group[0]!;
      signals.push({
        type: 'DUPLICATE_INSTRUCTION',
        severity: group.length > 2 ? 'CRITICAL' : 'HIGH',
        summary: `${maskMsisdn(first.msisdn)} appears ${group.length} times with an identical amount of KES ${formatCents(first.amountCents)}.`,
        evidence: {
          msisdn: maskMsisdn(first.msisdn),
          amount: formatCents(first.amountCents),
          occurrences: group.length,
        },
        instructionIds: group.map((g) => g.instructionId),
      });
    }
  }

  // Same recipient, different amounts — legitimate (salary + expense claim) but worth a look.
  const byRecipient = new Map<string, InstructionForRisk[]>();
  for (const i of instructions) {
    byRecipient.set(i.recipientId, [...(byRecipient.get(i.recipientId) ?? []), i]);
  }
  for (const [recipientId, group] of byRecipient) {
    if (group.length > 1 && new Set(group.map((g) => g.amountCents)).size > 1) {
      signals.push({
        type: 'DUPLICATE_INSTRUCTION',
        severity: 'MEDIUM',
        summary: `This batch pays the same recipient ${group.length} separate times with different amounts.`,
        evidence: {
          recipientId,
          amounts: group.map((g) => formatCents(g.amountCents)),
        },
        instructionIds: group.map((g) => g.instructionId),
      });
    }
  }

  // ---- Per-recipient amount deviation and recipient novelty ---------------
  for (const i of instructions) {
    const h = history.get(i.recipientId);
    if (!h || h.paymentCount === 0) {
      const ageHours = h ? (now - h.recipientCreatedAt) / HOUR_MS : 0;
      signals.push({
        type: 'NEW_RECIPIENT',
        severity: h && ageHours <= policy.newRecipientWindowHours ? 'HIGH' : 'MEDIUM',
        summary: h
          ? `First payment to a recipient added ${Math.round(ageHours)} hours ago, for KES ${formatCents(i.amountCents)}.`
          : `First payment to this recipient, for KES ${formatCents(i.amountCents)}.`,
        evidence: {
          recipientId: i.recipientId,
          amount: formatCents(i.amountCents),
          recipientAgeHours: Math.round(ageHours),
        },
        instructionIds: [i.instructionId],
      });
      continue;
    }

    if (h.meanAmountCents > 0) {
      const ratio = i.amountCents / h.meanAmountCents;
      if (ratio >= policy.amountDeviationMultiple || ratio <= 1 / policy.amountDeviationMultiple) {
        const direction = ratio > 1 ? 'higher' : 'lower';
        signals.push({
          type: 'AMOUNT_DEVIATION',
          severity: ratio >= policy.amountDeviationMultiple * 2 ? 'HIGH' : 'MEDIUM',
          summary: `KES ${formatCents(i.amountCents)} is ${ratio.toFixed(1)}× ${direction} than this recipient's usual payment of KES ${formatCents(Math.round(h.meanAmountCents))}.`,
          evidence: {
            recipientId: i.recipientId,
            amount: formatCents(i.amountCents),
            historicalMean: formatCents(Math.round(h.meanAmountCents)),
            ratio: Number(ratio.toFixed(2)),
            priorPayments: h.paymentCount,
          },
          instructionIds: [i.instructionId],
        });
      }
    }

    const modifiedHoursAgo = (now - h.recipientLastModifiedAt) / HOUR_MS;
    if (modifiedHoursAgo <= policy.newRecipientWindowHours && h.paymentCount > 0) {
      signals.push({
        type: 'RECENTLY_MODIFIED_RECIPIENT',
        severity: 'HIGH',
        summary: `This recipient's master record was changed ${Math.round(modifiedHoursAgo)} hours ago — verify the destination number before approving.`,
        evidence: { recipientId: i.recipientId, modifiedHoursAgo: Math.round(modifiedHoursAgo) },
        instructionIds: [i.instructionId],
      });
    }
  }

  // ---- Batch-level total deviation ---------------------------------------
  const total = instructions.reduce((s, i) => s + i.amountCents, 0);
  if (input.priorBatchTotalsCents.length >= 2) {
    const baseline = mean(input.priorBatchTotalsCents);
    if (baseline > 0) {
      const delta = Math.abs(total - baseline) / baseline;
      if (delta >= policy.batchTotalDeviationFraction) {
        signals.push({
          type: 'BATCH_TOTAL_DEVIATION',
          severity: delta >= policy.batchTotalDeviationFraction * 2 ? 'HIGH' : 'MEDIUM',
          summary: `Batch total of KES ${formatCents(total)} differs from the recent average of KES ${formatCents(Math.round(baseline))} by ${Math.round(delta * 100)}%.`,
          evidence: {
            total: formatCents(total),
            recentAverage: formatCents(Math.round(baseline)),
            deviationPercent: Math.round(delta * 100),
            comparedBatches: input.priorBatchTotalsCents.length,
          },
          instructionIds: [],
        });
      }
    }
  }

  // ---- Late edit before submission ---------------------------------------
  if (input.lastMaterialEditAt !== null && input.submittedAt !== null) {
    const minutes = (input.submittedAt - input.lastMaterialEditAt) / 60_000;
    if (minutes >= 0 && minutes <= policy.lateEditWindowMinutes) {
      signals.push({
        type: 'LATE_EDIT',
        severity: 'MEDIUM',
        summary: `This batch was edited ${Math.round(minutes)} minutes before submission.`,
        evidence: { minutesBeforeSubmission: Math.round(minutes) },
        instructionIds: [],
      });
    }
  }

  // ---- Timing ------------------------------------------------------------
  const hourUtc = new Date(now).getUTCHours();
  if (hourUtc < policy.businessHoursUtc.start || hourUtc >= policy.businessHoursUtc.end) {
    signals.push({
      type: 'UNUSUAL_TIMING',
      severity: 'LOW',
      summary: "This batch is being processed outside the organization's normal business hours.",
      evidence: { hourUtc, businessHoursUtc: policy.businessHoursUtc },
      instructionIds: [],
    });
  }

  // ---- Outstanding reconciliation ----------------------------------------
  if (input.unresolvedReconciliationCount > 0) {
    signals.push({
      type: 'UNRESOLVED_RECONCILIATION',
      severity: input.unresolvedReconciliationCount > 5 ? 'HIGH' : 'MEDIUM',
      summary: `${input.unresolvedReconciliationCount} earlier transaction(s) have an unresolved outcome. Releasing more payments while outcomes are unknown makes reconciliation harder.`,
      evidence: { unresolvedCases: input.unresolvedReconciliationCount },
      instructionIds: [],
    });
  }

  // ---- Approval chain concentration --------------------------------------
  for (const c of input.approvalConcentration) {
    signals.push({
      type: 'APPROVAL_CHAIN_CONCENTRATION',
      severity: 'LOW',
      summary: `${Math.round(c.shareOfRecent * 100)}% of recent releases used the same approver/authorizer pair.`,
      evidence: { pair: c.pair, occurrences: c.occurrences, share: c.shareOfRecent },
      instructionIds: [],
    });
  }

  // ---- Score -------------------------------------------------------------
  // Diminishing returns per signal type: fifty "new recipient" rows in a genuine onboarding
  // batch should not score the same as fifty distinct classes of anomaly.
  const byType = new Map<RiskSignalType, RiskSignal[]>();
  for (const s of signals) byType.set(s.type, [...(byType.get(s.type) ?? []), s]);

  let raw = 0;
  for (const [, group] of byType) {
    const weights = group.map((s) => SEVERITY_WEIGHT[s.severity]).sort((a, b) => b - a);
    weights.forEach((w, index) => {
      raw += w / (index + 1);
    });
  }
  const score = Math.max(0, Math.min(100, Math.round(raw)));

  const band: RiskAssessment['band'] =
    score >= 75 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'ELEVATED' : 'LOW';

  return {
    score,
    band,
    signals: signals.sort((a, b) => SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity]),
    requiresAcknowledgement: score >= policy.acknowledgementThreshold,
  };
}
