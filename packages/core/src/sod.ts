/**
 * Separation of duties and collusion controls (spec §19).
 *
 * These rules are the reason a single compromised account cannot move money. They are
 * evaluated server-side at every workflow transition, and each returns a *reason* rather
 * than a bare boolean so the denial can be shown to the user and written to the audit log.
 */

import { policyError } from './errors.js';
import type { AuthorityLevel } from './rbac.js';

export interface BatchParticipants {
  createdByUserId: string;
  /** Everyone who has materially edited the instruction set. */
  editedByUserIds: readonly string[];
  /** L2 approver, once approved. */
  approvedByUserId: string | null;
  submittedByUserId: string | null;
}

export interface SodContext {
  actorUserId: string;
  actorLevel: AuthorityLevel;
  participants: BatchParticipants;
}

/**
 * Creator ≠ approver. The most basic fraud control there is: the person who decides who
 * gets paid may not also be the person who confirms it is correct.
 */
export function assertNotSelfApproval(ctx: SodContext): void {
  const { actorUserId, participants } = ctx;
  if (participants.createdByUserId === actorUserId) {
    throw policyError(
      'SOD_SELF_APPROVAL',
      'You created this batch and may not approve it. Approval must come from a different officer.',
      { control: 'creator-not-approver' },
    );
  }
  if (participants.submittedByUserId === actorUserId) {
    throw policyError(
      'SOD_SELF_SUBMISSION_APPROVAL',
      'You submitted this batch and may not approve it. Approval must come from a different officer.',
      { control: 'submitter-not-approver' },
    );
  }
  if (participants.editedByUserIds.includes(actorUserId)) {
    throw policyError(
      'SOD_MODIFIER_APPROVAL',
      'You edited this batch and may not approve it. Approval must come from a different officer.',
      { control: 'modifier-not-approver' },
    );
  }
}

/**
 * Modifier ≠ final authorizer. Distinct from the above: an L3 who fixed a typo in the
 * batch cannot then be the one who releases it.
 */
export function assertNotSelfAuthorization(ctx: SodContext): void {
  const { actorUserId, participants } = ctx;
  if (participants.createdByUserId === actorUserId) {
    throw policyError(
      'SOD_SELF_AUTHORIZATION',
      'You created this batch and may not give it final payment authorization.',
      { control: 'creator-not-authorizer' },
    );
  }
  if (participants.editedByUserIds.includes(actorUserId)) {
    throw policyError(
      'SOD_MODIFIER_AUTHORIZATION',
      'You edited this batch and may not give it final payment authorization.',
      { control: 'modifier-not-authorizer' },
    );
  }
  if (participants.approvedByUserId === actorUserId) {
    throw policyError(
      'SOD_APPROVER_AUTHORIZATION',
      'You performed the finance approval on this batch and may not also authorize its release.',
      { control: 'approver-not-authorizer' },
    );
  }
}

/**
 * Cooling-off: a material edit immediately before submission is the classic
 * "approve the clean version, pay the dirty one" pattern. The organization configures the
 * window; zero disables it.
 */
export function assertCoolingOff(params: {
  lastMaterialEditAt: number | null;
  now: number;
  coolingOffSeconds: number;
}): void {
  const { lastMaterialEditAt, now, coolingOffSeconds } = params;
  if (coolingOffSeconds <= 0 || lastMaterialEditAt === null) return;
  const elapsed = (now - lastMaterialEditAt) / 1000;
  if (elapsed < coolingOffSeconds) {
    const remaining = Math.ceil(coolingOffSeconds - elapsed);
    throw policyError(
      'SOD_COOLING_OFF',
      `This batch was edited ${Math.floor(elapsed)} seconds ago. Organization policy requires a ${coolingOffSeconds}-second cooling-off period before submission; ${remaining} seconds remain.`,
      { remainingSeconds: remaining, coolingOffSeconds },
    );
  }
}

/** Conflict-of-interest registry entry — an approver declared to be conflicted for a scope. */
export interface ConflictRegistration {
  userId: string;
  /** Recipient, department, or the whole organization. */
  scopeType: 'RECIPIENT' | 'DEPARTMENT' | 'ORGANIZATION';
  scopeId: string | null;
  reason: string;
}

export function assertNoDeclaredConflict(params: {
  actorUserId: string;
  conflicts: readonly ConflictRegistration[];
  recipientIds: readonly string[];
  departmentIds: readonly string[];
}): void {
  const { actorUserId, conflicts, recipientIds, departmentIds } = params;
  const mine = conflicts.filter((c) => c.userId === actorUserId);
  for (const c of mine) {
    const hit =
      c.scopeType === 'ORGANIZATION' ||
      (c.scopeType === 'RECIPIENT' && c.scopeId !== null && recipientIds.includes(c.scopeId)) ||
      (c.scopeType === 'DEPARTMENT' && c.scopeId !== null && departmentIds.includes(c.scopeId));
    if (hit) {
      throw policyError(
        'SOD_DECLARED_CONFLICT',
        `A conflict of interest is registered against you for this batch: ${c.reason}`,
        { scopeType: c.scopeType, scopeId: c.scopeId },
      );
    }
  }
}

/**
 * Collusion signal: the same small group approving and authorizing together, repeatedly.
 * This does not block anything — it raises a risk finding for human review, because the
 * legitimate version (a small finance team) and the illegitimate version look identical
 * from inside the data.
 */
export interface ApprovalPair {
  approverUserId: string;
  authorizerUserId: string;
  at: number;
}

export interface CollusionSignal {
  pair: string;
  occurrences: number;
  shareOfRecent: number;
  reason: string;
}

export function detectApprovalChainConcentration(params: {
  recentPairs: readonly ApprovalPair[];
  /** Fraction of recent releases above which a single pair is flagged. */
  concentrationThreshold?: number;
  minimumSample?: number;
}): CollusionSignal[] {
  const { recentPairs, concentrationThreshold = 0.8, minimumSample = 10 } = params;
  if (recentPairs.length < minimumSample) return [];

  const counts = new Map<string, number>();
  for (const p of recentPairs) {
    const key = `${p.approverUserId}→${p.authorizerUserId}`;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }

  const signals: CollusionSignal[] = [];
  for (const [pair, occurrences] of counts) {
    const share = occurrences / recentPairs.length;
    if (share >= concentrationThreshold) {
      signals.push({
        pair,
        occurrences,
        shareOfRecent: share,
        reason: `${Math.round(share * 100)}% of the last ${recentPairs.length} payment releases were approved and authorized by the same pair of officers. Consider widening the approval rota.`,
      });
    }
  }
  return signals;
}
