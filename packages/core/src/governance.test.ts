import { describe, it, expect } from 'vitest';
import {
  assertNotSelfApproval,
  assertNotSelfAuthorization,
  assertCoolingOff,
  assertNoDeclaredConflict,
  detectApprovalChainConcentration,
  type BatchParticipants,
} from './sod.js';
import { resolveFailure, listFailureReasons, FAILURE_REASONS } from './failure-reasons.js';
import {
  sealAuditEvent,
  verifyChain,
  redactForAudit,
  looksLikeSecret,
  stableStringify,
  GENESIS_HASH,
  REDACTED,
  type AuditEvent,
  type AuditEventInput,
} from './audit.js';
import {
  decideOnExistingClaim,
  instructionFingerprint,
  isValidIdempotencyKey,
} from './idempotency.js';
import { evaluateReleasePolicy, DEFAULT_POLICY } from './policy.js';
import type { RiskAssessment } from './risk.js';
import { SolvarenError } from './errors.js';
import { allowedCommandsForActor } from './batch-state.js';
import { capabilitiesFor, type Permission } from './rbac.js';

const participants = (o: Partial<BatchParticipants> = {}): BatchParticipants => ({
  createdByUserId: 'user-l1',
  editedByUserIds: [],
  approvedByUserId: null,
  submittedByUserId: 'user-l1',
  ...o,
});

describe('separation of duties (§19, §23)', () => {
  it('blocks the creator from approving their own batch', () => {
    expect(() =>
      assertNotSelfApproval({
        actorUserId: 'user-l1',
        actorLevel: 'L2',
        participants: participants(),
      }),
    ).toThrow(/created this batch and may not approve it/);
  });

  it('blocks a modifier from approving', () => {
    expect(() =>
      assertNotSelfApproval({
        actorUserId: 'user-l2a',
        actorLevel: 'L2',
        participants: participants({ editedByUserIds: ['user-l2a'] }),
      }),
    ).toThrow(/edited this batch/);
  });

  it('allows a genuinely independent approver', () => {
    expect(() =>
      assertNotSelfApproval({
        actorUserId: 'user-l2b',
        actorLevel: 'L2',
        participants: participants(),
      }),
    ).not.toThrow();
  });

  it('blocks the L2 approver from also giving final authorization', () => {
    expect(() =>
      assertNotSelfAuthorization({
        actorUserId: 'user-l2b',
        actorLevel: 'L3',
        participants: participants({ approvedByUserId: 'user-l2b' }),
      }),
    ).toThrow(/finance approval on this batch/);
  });

  it('blocks the creator and any modifier from final authorization', () => {
    expect(() =>
      assertNotSelfAuthorization({
        actorUserId: 'user-l1',
        actorLevel: 'L3',
        participants: participants(),
      }),
    ).toThrow(/created this batch/);
    expect(() =>
      assertNotSelfAuthorization({
        actorUserId: 'user-l3',
        actorLevel: 'L3',
        participants: participants({ editedByUserIds: ['user-l3'] }),
      }),
    ).toThrow(/edited this batch/);
  });

  it('allows an independent L3 to authorize', () => {
    expect(() =>
      assertNotSelfAuthorization({
        actorUserId: 'user-l3',
        actorLevel: 'L3',
        participants: participants({ approvedByUserId: 'user-l2b' }),
      }),
    ).not.toThrow();
  });
});

describe('cooling-off window', () => {
  const now = 1_800_000_000_000;

  it('blocks submission within the configured window and says how long remains', () => {
    try {
      assertCoolingOff({ lastMaterialEditAt: now - 60_000, now, coolingOffSeconds: 300 });
      expect.unreachable('should have blocked');
    } catch (err) {
      const e = err as SolvarenError;
      expect(e.code).toBe('SOD_COOLING_OFF');
      expect(e.details.remainingSeconds).toBe(240);
    }
  });

  it('permits submission once the window has elapsed', () => {
    expect(() =>
      assertCoolingOff({ lastMaterialEditAt: now - 301_000, now, coolingOffSeconds: 300 }),
    ).not.toThrow();
  });

  it('is disabled by a zero window or an unedited batch', () => {
    expect(() =>
      assertCoolingOff({ lastMaterialEditAt: now, now, coolingOffSeconds: 0 }),
    ).not.toThrow();
    expect(() =>
      assertCoolingOff({ lastMaterialEditAt: null, now, coolingOffSeconds: 300 }),
    ).not.toThrow();
  });
});

describe('conflict of interest registry', () => {
  const conflicts = [
    {
      userId: 'user-l3',
      scopeType: 'DEPARTMENT' as const,
      scopeId: 'dept-eng',
      reason: 'Spouse employed in Engineering',
    },
  ];

  it('blocks an approver conflicted for a department in the batch', () => {
    expect(() =>
      assertNoDeclaredConflict({
        actorUserId: 'user-l3',
        conflicts,
        recipientIds: [],
        departmentIds: ['dept-eng', 'dept-fin'],
      }),
    ).toThrow(/Spouse employed in Engineering/);
  });

  it('permits when the conflicted scope is not in the batch', () => {
    expect(() =>
      assertNoDeclaredConflict({
        actorUserId: 'user-l3',
        conflicts,
        recipientIds: [],
        departmentIds: ['dept-fin'],
      }),
    ).not.toThrow();
  });

  it('an organization-wide conflict blocks every batch', () => {
    expect(() =>
      assertNoDeclaredConflict({
        actorUserId: 'u',
        conflicts: [
          { userId: 'u', scopeType: 'ORGANIZATION', scopeId: null, reason: 'Under investigation' },
        ],
        recipientIds: [],
        departmentIds: [],
      }),
    ).toThrow(/Under investigation/);
  });
});

describe('collusion signal', () => {
  it('flags a dominant approver/authorizer pair without blocking', () => {
    const pairs = Array.from({ length: 12 }, (_, i) => ({
      approverUserId: i < 11 ? 'a' : 'b',
      authorizerUserId: i < 11 ? 'c' : 'd',
      at: i,
    }));
    const signals = detectApprovalChainConcentration({ recentPairs: pairs });
    expect(signals).toHaveLength(1);
    expect(signals[0]!.pair).toBe('a→c');
    expect(signals[0]!.reason).toMatch(/approval rota/);
  });

  it('stays silent on a small sample, where concentration means nothing', () => {
    const pairs = Array.from({ length: 4 }, (_, i) => ({
      approverUserId: 'a',
      authorizerUserId: 'c',
      at: i,
    }));
    expect(detectApprovalChainConcentration({ recentPairs: pairs })).toEqual([]);
  });
});

describe('failure reason dictionary (§6.2, TRK-002/009)', () => {
  it('maps the well-known B2C result codes to actionable explanations', () => {
    const insufficient = resolveFailure('1', 'The balance is insufficient for the transaction');
    expect(insufficient.failureReason).toMatch(/Utility account/);
    expect(insufficient.failureClass).toBe('FUNDING');
    expect(insufficient.operatorAction).toMatch(/Top up|Move funds|move funds/);
    expect(insufficient.mapped).toBe(true);

    expect(resolveFailure('2001').failureReason).toMatch(/initiator information is invalid/);
    expect(resolveFailure('2040').failureReason).toMatch(/not a registered M-PESA customer/);
    expect(resolveFailure('500.002.1001').failureClass).toBe('AMBIGUOUS');
  });

  it('TRK-002: an unknown code is never blank and never just "Error"', () => {
    const unknown = resolveFailure('9999', 'Some unmapped provider condition');
    expect(unknown.mapped).toBe(false);
    expect(unknown.failureReason).toContain('9999');
    expect(unknown.failureReason).toContain('Some unmapped provider condition');
    expect(unknown.failureReason.trim()).not.toBe('');
    expect(unknown.failureReason.trim().toLowerCase()).not.toBe('error');
  });

  it('explains an unknown code with no provider description, still showing the raw code', () => {
    const unknown = resolveFailure('X-77');
    expect(unknown.failureReason).toContain('X-77');
    expect(unknown.failureReason).toMatch(/not yet in the SOLVAREN failure dictionary/);
    expect(unknown.operatorAction).toMatch(/add a mapping/);
  });

  it('handles a missing code without producing an empty reason', () => {
    const none = resolveFailure(null, null);
    expect(none.failureCode).toBe('SLV_UNSPECIFIED');
    expect(none.failureReason).toMatch(/without a result code/);
  });

  it('TRK-009: an administrator override takes precedence over the compiled dictionary', () => {
    const resolved = resolveFailure('1', 'Balance insufficient', {
      '1': {
        reason: 'Utility float exhausted — treasury must fund before 09:00',
        class: 'FUNDING',
        operatorAction: 'Call treasury on extension 4102',
        transient: true,
      },
    });
    expect(resolved.failureReason).toMatch(/treasury must fund/);
    expect(resolved.dictionaryVersion).toMatch(/override/);
  });

  it('every dictionary entry is complete and actionable', () => {
    for (const entry of listFailureReasons()) {
      expect(entry.code.trim()).not.toBe('');
      expect(entry.reason.length).toBeGreaterThan(10);
      expect(entry.operatorAction.length).toBeGreaterThan(5);
      expect(entry.reason.toLowerCase()).not.toBe('error');
    }
    expect(Object.keys(FAILURE_REASONS).length).toBeGreaterThan(30);
  });
});

describe('audit hash chain (§14, Zone 7)', () => {
  const event = (n: number): AuditEventInput => ({
    eventId: `evt-${n}`,
    organizationId: 'org-1',
    actorId: 'user-l3',
    actorLevel: 'L3',
    eventClass: 'PAYMENT',
    action: 'payment.release',
    objectType: 'PaymentBatch',
    objectId: `batch-${n}`,
    outcome: 'SUCCESS',
    occurredAt: new Date(Date.UTC(2026, 8, 13, 10, n)).toISOString(),
    previousState: { state: 'AUTHORIZATION_PENDING' },
    newState: { state: 'AUTHORIZED' },
    correlationId: `cor-${n}`,
    securityContext: { ip: '203.0.113.9', deviceId: 'dev-1' },
    detail: { recipientCount: 187, totalAmountCents: 842_050_000 },
  });

  async function chainOf(count: number): Promise<AuditEvent[]> {
    const events: AuditEvent[] = [];
    let previousHash = GENESIS_HASH;
    for (let i = 0; i < count; i++) {
      const sealed = await sealAuditEvent(event(i), previousHash, i + 1);
      events.push(sealed);
      previousHash = sealed.eventHash;
    }
    return events;
  }

  it('verifies an intact chain', async () => {
    const result = await verifyChain(await chainOf(5));
    expect(result.valid).toBe(true);
    expect(result.eventsVerified).toBe(5);
  });

  it('detects an altered event and names it', async () => {
    const events = await chainOf(5);
    // Someone edits the released amount in the database after the fact.
    events[2] = { ...events[2]!, detail: { ...events[2]!.detail, totalAmountCents: 1 } };
    const result = await verifyChain(events);
    expect(result.valid).toBe(false);
    expect(result.brokenAtIndex).toBe(2);
    expect(result.brokenEventId).toBe('evt-2');
    expect(result.reason).toMatch(/altered after it was written/);
  });

  it('detects a deleted event by the break in the links', async () => {
    const events = await chainOf(5);
    events.splice(2, 1);
    const result = await verifyChain(events);
    expect(result.valid).toBe(false);
    expect(result.brokenAtIndex).toBe(2);
    expect(result.reason).toMatch(/removed, reordered or altered/);
  });

  it('detects reordering', async () => {
    const events = await chainOf(4);
    [events[1], events[2]] = [events[2]!, events[1]!];
    expect((await verifyChain(events)).valid).toBe(false);
  });

  it('hashes are stable across key insertion order', () => {
    expect(stableStringify({ b: 1, a: 2 })).toBe(stableStringify({ a: 2, b: 1 }));
    expect(stableStringify([{ z: 1, a: [3, 2] }])).toBe('[{"a":[3,2],"z":1}]');
  });
});

describe('secret redaction (NFR-SEC-003)', () => {
  it('redacts credential-shaped keys at every depth', () => {
    const redacted = redactForAudit({
      consumerKey: 'abc123',
      nested: { securityCredential: 'longbase64', safe: 'visible' },
      list: [{ initiator_password: 'p' }],
      accessKeyId: 'AKIA',
      authorizationPin: '1234',
    }) as Record<string, any>;

    expect(redacted.consumerKey).toBe(REDACTED);
    expect(redacted.nested.securityCredential).toBe(REDACTED);
    expect(redacted.nested.safe).toBe('visible');
    expect(redacted.list[0].initiator_password).toBe(REDACTED);
    expect(redacted.accessKeyId).toBe(REDACTED);
    expect(redacted.authorizationPin).toBe(REDACTED);
  });

  it('leaves non-secret payment data intact so audit remains useful', () => {
    const redacted = redactForAudit({
      amountCents: 45_000_00,
      msisdn: '2547****5678',
      batchId: 'b1',
    }) as any;
    expect(redacted.amountCents).toBe(45_000_00);
    expect(redacted.batchId).toBe('b1');
  });

  it('recognises credential-shaped strings for log guards', () => {
    expect(looksLikeSecret('Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abc')).toBe(true);
    expect(looksLikeSecret('Basic ' + 'a'.repeat(40))).toBe(true);
    expect(looksLikeSecret('A'.repeat(140) + '==')).toBe(true);
    expect(looksLikeSecret('batch SLV-2026-00981 released')).toBe(false);
  });

  it('truncates pathological nesting rather than recursing forever', () => {
    let deep: any = { value: 1 };
    for (let i = 0; i < 40; i++) deep = { nest: deep };
    expect(JSON.stringify(redactForAudit(deep))).toContain('TRUNCATED');
  });
});

describe('idempotency (§9.3, NFR-REL-003)', () => {
  const base = {
    organizationId: 'org-1',
    batchId: 'batch-1',
    instructionId: 'ins-1',
    batchVersion: 3,
    msisdn: '254712345678',
    amountCents: 45_000_00,
    manifestHash: 'A'.repeat(64),
  };

  it('is deterministic for identical input', async () => {
    expect(await instructionFingerprint(base)).toBe(await instructionFingerprint({ ...base }));
  });

  it.each([
    ['amount', { amountCents: 45_000_01 }],
    ['msisdn', { msisdn: '254712345679' }],
    ['batch version', { batchVersion: 4 }],
    ['manifest', { manifestHash: 'B'.repeat(64) }],
    ['instruction', { instructionId: 'ins-2' }],
  ])('changes when the %s changes', async (_label, patch) => {
    expect(await instructionFingerprint({ ...base, ...patch })).not.toBe(
      await instructionFingerprint(base),
    );
  });

  it('submits when there is no prior claim', () => {
    expect(decideOnExistingClaim(null).action).toBe('SUBMIT');
  });

  it('submits when a claim exists but nothing was ever sent', () => {
    expect(
      decideOnExistingClaim({
        fingerprint: 'f',
        state: 'CLAIMED',
        originatorConversationId: null,
        transactionId: null,
        claimedAt: 0,
        updatedAt: 0,
      }).action,
    ).toBe('SUBMIT');
  });

  it('NEVER resubmits after a request already reached M-PESA — it reconciles first', () => {
    const decision = decideOnExistingClaim({
      fingerprint: 'f',
      state: 'SUBMITTED',
      originatorConversationId: '600997-ABC-123',
      transactionId: 'txn-1',
      claimedAt: 0,
      updatedAt: 0,
    });
    expect(decision.action).toBe('RECONCILE_FIRST');
    expect(decision.reason).toMatch(/outcome is unknown/);
  });

  it('skips an already-settled instruction', () => {
    expect(
      decideOnExistingClaim({
        fingerprint: 'f',
        state: 'SETTLED',
        originatorConversationId: 'x',
        transactionId: 't',
        claimedAt: 0,
        updatedAt: 0,
      }).action,
    ).toBe('SKIP_ALREADY_SETTLED');
  });

  it('validates client idempotency keys', () => {
    expect(isValidIdempotencyKey('a'.repeat(32))).toBe(true);
    expect(isValidIdempotencyKey('short')).toBe(false);
    expect(isValidIdempotencyKey(null)).toBe(false);
    expect(isValidIdempotencyKey('has spaces and $ymbols!!!!!!!!!')).toBe(false);
  });
});

describe('release policy engine', () => {
  const risk = (overrides: Partial<RiskAssessment> = {}): RiskAssessment => ({
    score: 10,
    band: 'LOW',
    signals: [],
    requiresAcknowledgement: false,
    ...overrides,
  });

  const input = (o: Partial<Parameters<typeof evaluateReleasePolicy>[0]> = {}) => ({
    policy: DEFAULT_POLICY,
    instructionCount: 187,
    totalAmountCents: 8_420_500_00,
    maxInstructionAmountCents: 120_000_00,
    risk: risk(),
    dispositionedFindingCount: 0,
    disbursedTodayCents: 0,
    ...o,
  });

  it('permits a normal payroll release', () => {
    const result = evaluateReleasePolicy(input());
    expect(result.allowed).toBe(true);
    expect(result.violations).toEqual([]);
  });

  it('reports every violation at once rather than one at a time', () => {
    const result = evaluateReleasePolicy(
      input({
        instructionCount: 9_000,
        totalAmountCents: 90_000_000_00,
        maxInstructionAmountCents: 250_000_00,
        policy: { ...DEFAULT_POLICY, maxInstructionAmountCents: 100_000_00 },
      }),
    );
    expect(result.allowed).toBe(false);
    expect(result.violations.map((v) => v.code)).toEqual(
      expect.arrayContaining([
        'POLICY_BATCH_SIZE',
        'POLICY_INSTRUCTION_LIMIT',
        'POLICY_BATCH_TOTAL',
      ]),
    );
  });

  it('enforces the daily disbursement circuit breaker', () => {
    const result = evaluateReleasePolicy(
      input({
        policy: { ...DEFAULT_POLICY, dailyDisbursementCeilingCents: 10_000_000_00 },
        disbursedTodayCents: 9_000_000_00,
      }),
    );
    expect(result.violations.map((v) => v.code)).toContain('POLICY_DAILY_CEILING');
  });

  it('blocks release at the configured risk band until findings are dispositioned', () => {
    const critical = risk({ score: 90, band: 'CRITICAL', signals: [{} as any, {} as any] });
    const blocked = evaluateReleasePolicy(input({ risk: critical }));
    expect(blocked.allowed).toBe(false);
    expect(blocked.violations[0]!.code).toBe('POLICY_RISK_BLOCK');

    const dispositioned = evaluateReleasePolicy(
      input({ risk: critical, dispositionedFindingCount: 2 }),
    );
    expect(dispositioned.allowed).toBe(true);
  });

  it('requires explicit acknowledgement for high-value releases (NFR-UX-001)', () => {
    const result = evaluateReleasePolicy(input({ totalAmountCents: 8_420_500_00 }));
    expect(result.acknowledgementsRequired.join(' ')).toMatch(
      /high-value release of KES 8,420,500.00/,
    );
  });
});

describe('the commands a console may offer (§7.3)', () => {
  /** Exactly the permission set the server would grant this level, not a hand-written one. */
  const held = (level: 'L1' | 'L2' | 'L3'): ReadonlySet<Permission> => {
    const capabilities = capabilitiesFor({ level, status: 'ACTIVE' });
    return new Set((Object.keys(capabilities) as Permission[]).filter((p) => capabilities[p]));
  };

  it('never offers an L1 the approval that would collapse the two-person rule', () => {
    const commands = allowedCommandsForActor('SUBMITTED_TO_L2', { permissions: held('L1') });
    expect(commands).not.toContain('APPROVE_TO_L3');
    expect(commands).not.toContain('REJECT');
  });

  it('offers finance control exactly the decisions it is meant to take', () => {
    const commands = allowedCommandsForActor('SUBMITTED_TO_L2', { permissions: held('L2') });
    expect(commands).toContain('APPROVE_TO_L3');
    expect(commands).toContain('REJECT');
    expect(commands).toContain('HOLD');
  });

  it('does not offer the executive the L2 approval step', () => {
    // L3 approving on L2's behalf would make one person the whole chain.
    expect(allowedCommandsForActor('SUBMITTED_TO_L2', { permissions: held('L3') })).not.toContain(
      'APPROVE_TO_L3',
    );
  });

  it('offers release only to the executive, and only from L3_READY', () => {
    expect(allowedCommandsForActor('L3_READY', { permissions: held('L3') })).toContain(
      'BEGIN_AUTHORIZATION',
    );
    expect(allowedCommandsForActor('L3_READY', { permissions: held('L2') })).not.toContain(
      'BEGIN_AUTHORIZATION',
    );
    expect(allowedCommandsForActor('DRAFT', { permissions: held('L3') })).not.toContain(
      'BEGIN_AUTHORIZATION',
    );
  });

  it('lets an operator carry their own draft forward', () => {
    expect(allowedCommandsForActor('DRAFT', { permissions: held('L1') })).toContain('VALIDATE');
    expect(allowedCommandsForActor('VALIDATED', { permissions: held('L1') })).toContain(
      'SUBMIT_TO_L2',
    );
  });

  it('offers a way out of a hold, so a held batch is never a dead end', () => {
    expect(allowedCommandsForActor('HELD', { permissions: held('L2') })).toContain('RELEASE_HOLD');
    expect(allowedCommandsForActor('HELD', { permissions: held('L3') })).toContain('CANCEL');
  });

  it('never offers a system-only edge to any human', () => {
    for (const level of ['L1', 'L2', 'L3'] as const) {
      const commands = allowedCommandsForActor('AUTHORIZED', { permissions: held(level) });
      expect(commands).not.toContain('ENQUEUE');
    }
  });
});
