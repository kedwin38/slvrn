import { describe, it, expect } from 'vitest';
import {
  BATCH_STATES,
  BATCH_EDGES,
  assertTransition,
  allowedCommands,
  canTransition,
  isEditable,
  isTerminal,
  hasLeftTheBuilding,
  type BatchState,
  type BatchCommand,
} from './batch-state.js';
import {
  assertTxnTransition,
  isRetryEligible,
  isSettled,
  isInFlight,
  statusTone,
  TXN_STATES,
  type TxnState,
} from './txn-state.js';
import type { Permission } from './rbac.js';
import { SolvarenError } from './errors.js';

const withPermissions = (...perms: Permission[]) => ({
  level: 'L3' as const,
  permissions: new Set<Permission>(perms),
});

describe('batch lifecycle state machine (§5.1)', () => {
  it('the happy path walks DRAFT → AUTHORIZED exactly as specified', () => {
    const path: Array<[BatchState, BatchCommand, BatchState, Permission]> = [
      ['DRAFT', 'VALIDATE', 'VALIDATED', 'batch:validate'],
      ['VALIDATED', 'SUBMIT_TO_L2', 'SUBMITTED_TO_L2', 'batch:submit_to_l2'],
      ['SUBMITTED_TO_L2', 'BEGIN_L2_REVIEW', 'L2_REVIEW', 'batch:review'],
      ['L2_REVIEW', 'APPROVE_TO_L3', 'L3_READY', 'batch:approve_to_l3'],
      ['L3_READY', 'BEGIN_AUTHORIZATION', 'AUTHORIZATION_PENDING', 'payment:authorize'],
      ['AUTHORIZATION_PENDING', 'AUTHORIZE', 'AUTHORIZED', 'payment:release'],
    ];
    for (const [from, command, to, permission] of path) {
      const edge = assertTransition(from, command, { actor: withPermissions(permission) });
      expect(edge.to).toBe(to);
    }
  });

  it('AC-01: an L1 actor cannot traverse the release edge', () => {
    expect(() =>
      assertTransition('AUTHORIZATION_PENDING', 'AUTHORIZE', {
        actor: { level: 'L1', permissions: new Set<Permission>(['batch:submit_to_l2']) },
      }),
    ).toThrow(/requires the payment:release permission/);
  });

  it('refuses commands that do not exist for the current state', () => {
    try {
      assertTransition('DRAFT', 'AUTHORIZE', { actor: withPermissions('payment:release') });
      expect.unreachable('DRAFT must not be authorizable');
    } catch (err) {
      const e = err as SolvarenError;
      expect(e.code).toBe('BATCH_TRANSITION_INVALID');
      expect(e.httpStatus).toBe(409);
      expect(e.details.allowed).toEqual(allowedCommands('DRAFT'));
    }
  });

  it('a batch cannot skip finance review on its way to authorization', () => {
    expect(canTransition('VALIDATED', 'BEGIN_AUTHORIZATION')).toBe(false);
    expect(canTransition('SUBMITTED_TO_L2', 'AUTHORIZE')).toBe(false);
    expect(canTransition('DRAFT', 'ENQUEUE')).toBe(false);
  });

  it('§4.3: no command anywhere in the machine forces a batch to SUCCESS by human action', () => {
    const humanEdgesToSuccess = BATCH_EDGES.filter((e) => e.to === 'SUCCESS' && !e.systemOnly);
    expect(humanEdgesToSuccess).toEqual([]);
  });

  it('execution edges are system-only and reject a human actor even with every permission', () => {
    const systemEdges = BATCH_EDGES.filter((e) => e.systemOnly);
    expect(systemEdges.length).toBeGreaterThan(0);
    for (const edge of systemEdges) {
      expect(() =>
        assertTransition(edge.from, edge.command, {
          actor: { level: 'L3', permissions: new Set<Permission>(['payment:release', 'batch:cancel']) },
        }),
      ).toThrow(/only be issued by the payment execution system/);
      expect(() => assertTransition(edge.from, edge.command, { system: true })).not.toThrow();
    }
  });

  it('a human edge cannot be traversed by claiming to be the system', () => {
    // `system: true` must not be a skeleton key past the approval chain.
    expect(() => assertTransition('AUTHORIZATION_PENDING', 'AUTHORIZE', { system: true })).toThrow(
      /requires an authenticated actor/,
    );
  });

  it('terminal states have no outbound edges', () => {
    for (const state of BATCH_STATES) {
      if (isTerminal(state)) expect(allowedCommands(state)).toEqual([]);
    }
  });

  it('classifies editability and money-in-flight correctly', () => {
    expect(isEditable('DRAFT')).toBe(true);
    expect(isEditable('VALIDATED')).toBe(true);
    expect(isEditable('L2_REVIEW')).toBe(false);
    expect(isEditable('AUTHORIZED')).toBe(false);

    expect(hasLeftTheBuilding('QUEUED')).toBe(true);
    expect(hasLeftTheBuilding('PROCESSING')).toBe(true);
    expect(hasLeftTheBuilding('SUCCESS')).toBe(true);
    expect(hasLeftTheBuilding('AUTHORIZED')).toBe(false);
    expect(hasLeftTheBuilding('DRAFT')).toBe(false);
  });

  it('every edge references a state that exists', () => {
    for (const edge of BATCH_EDGES) {
      expect(BATCH_STATES).toContain(edge.from);
      expect(BATCH_STATES).toContain(edge.to);
    }
  });

  it('no two edges share the same (from, command) pair', () => {
    const keys = BATCH_EDGES.map((e) => `${e.from}::${e.command}`);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it('an edit after validation forces revalidation rather than silent progress', () => {
    const edge = assertTransition('VALIDATED', 'INVALIDATE', { actor: withPermissions('batch:edit') });
    expect(edge.to).toBe('DRAFT');
  });
});

describe('transaction state machine (§6.1, §9.2)', () => {
  it('accepts the normal settlement path with provider evidence', () => {
    expect(assertTxnTransition({ from: 'PENDING', to: 'SUBMITTED', source: 'SYSTEM' }).to).toBe('SUBMITTED');
    expect(
      assertTxnTransition({ from: 'SUBMITTED', to: 'AWAITING_CALLBACK', source: 'SYNC_ACK' }).to,
    ).toBe('AWAITING_CALLBACK');
    expect(
      assertTxnTransition({
        from: 'AWAITING_CALLBACK',
        to: 'SUCCESS',
        source: 'CALLBACK',
        providerReceipt: 'SG632NMUAB',
      }).to,
    ).toBe('SUCCESS');
  });

  it('§23: a SUCCESS cannot be forged without provider evidence', () => {
    // No receipt.
    expect(() =>
      assertTxnTransition({ from: 'PROCESSING', to: 'SUCCESS', source: 'CALLBACK', providerReceipt: '' }),
    ).toThrow(/receipt number/);
    // Internal actor claiming success.
    expect(() =>
      assertTxnTransition({
        from: 'PROCESSING',
        to: 'SUCCESS',
        source: 'SYSTEM',
        providerReceipt: 'SG632NMUAB',
      }),
    ).toThrow(/provider callback or status query/);
  });

  it('TRK-002: a FAILED transition requires a failure code, so no failure is ever blank', () => {
    expect(() => assertTxnTransition({ from: 'PROCESSING', to: 'FAILED', source: 'CALLBACK' })).toThrow(
      /provider failure code/,
    );
    expect(
      assertTxnTransition({ from: 'PROCESSING', to: 'FAILED', source: 'CALLBACK', failureCode: '1' }).to,
    ).toBe('FAILED');
  });

  it('§23: a settled transaction cannot be rewritten by a later message', () => {
    for (const settled of ['SUCCESS', 'FAILED', 'CANCELLED'] as TxnState[]) {
      try {
        assertTxnTransition({
          from: settled,
          to: 'PROCESSING',
          source: 'CALLBACK',
        });
        expect.unreachable(`${settled} must be terminal`);
      } catch (err) {
        expect((err as SolvarenError).code).toBe('TXN_ALREADY_SETTLED');
      }
    }
  });

  it('§23 duplicate callbacks: re-delivering the same outcome is an idempotent no-op', () => {
    const result = assertTxnTransition({
      from: 'SUCCESS',
      to: 'SUCCESS',
      source: 'CALLBACK',
      providerReceipt: 'SG632NMUAB',
    });
    expect(result.to).toBe('SUCCESS');
    expect(result.opensReconciliation).toBe(false);
  });

  it('a timeout opens reconciliation rather than settling', () => {
    const result = assertTxnTransition({ from: 'SUBMITTED', to: 'TIMEOUT', source: 'QUEUE_TIMEOUT' });
    expect(result.opensReconciliation).toBe(true);
  });

  it('reconciliation can settle a timed-out transaction in either direction', () => {
    expect(
      assertTxnTransition({
        from: 'RECONCILING',
        to: 'SUCCESS',
        source: 'STATUS_QUERY',
        providerReceipt: 'SG632NMUAB',
      }).to,
    ).toBe('SUCCESS');
    expect(
      assertTxnTransition({ from: 'RECONCILING', to: 'FAILED', source: 'STATUS_QUERY', failureCode: '1' }).to,
    ).toBe('FAILED');
  });

  it('rejects transitions that are not in the graph', () => {
    expect(() => assertTxnTransition({ from: 'PENDING', to: 'PROCESSING', source: 'SYSTEM' })).toThrow(
      /cannot move from PENDING to PROCESSING/,
    );
  });

  it('classifies every state for the explorer chips', () => {
    for (const s of TXN_STATES) {
      expect(['success', 'danger', 'warning', 'info', 'neutral']).toContain(statusTone(s));
      expect(typeof isSettled(s)).toBe('boolean');
      expect(typeof isInFlight(s)).toBe('boolean');
      // A state is never both settled and in flight.
      expect(isSettled(s) && isInFlight(s)).toBe(false);
    }
  });
});

describe('retry eligibility (§9.3 — no blind retries)', () => {
  it('never retries an ambiguous or unsettled transaction', () => {
    for (const s of ['PENDING', 'SUBMITTED', 'AWAITING_CALLBACK', 'PROCESSING', 'TIMEOUT', 'RECONCILING'] as TxnState[]) {
      expect(isRetryEligible(s, '1')).toBe(false);
    }
  });

  it('never retries a permanent failure that would fail identically', () => {
    for (const code of ['2001', '2040', '8006', '21', '2028', 'SFC_IC0003', '2', '3', '4', '8']) {
      expect(isRetryEligible('FAILED', code)).toBe(false);
    }
  });

  it('permits retry for transient funding and provider failures', () => {
    expect(isRetryEligible('FAILED', '1')).toBe(true); // insufficient utility balance — top up and retry
    expect(isRetryEligible('FAILED', '17')).toBe(true); // M-PESA internal failure
    expect(isRetryEligible('FAILED', '26')).toBe(true); // system too busy
  });

  it('refuses retry when no failure code was recorded', () => {
    expect(isRetryEligible('FAILED', null)).toBe(false);
    expect(isRetryEligible('FAILED', '')).toBe(false);
  });
});
