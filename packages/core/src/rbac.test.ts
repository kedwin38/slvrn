import { describe, it, expect } from 'vitest';
import {
  PERMISSIONS,
  AUTHORITY_LEVELS,
  FORBIDDEN_TO_ALL,
  hasPermission,
  requirePermission,
  requireSameOrganization,
  canExportFailedTransactions,
  capabilitiesFor,
  atLeast,
  type Actor,
  type AuthorityLevel,
  type Permission,
} from './rbac.js';
import { SolvarenError } from './errors.js';

const actor = (level: AuthorityLevel, overrides: Partial<Actor> = {}): Actor => ({
  userId: `user-${level}`,
  organizationId: 'org-1',
  level,
  status: 'ACTIVE',
  ...overrides,
});

describe('RBAC permission matrix (spec §4.4)', () => {
  it('AC-01/AC-02/AC-03: only L3 may authorize or release payments', () => {
    for (const level of AUTHORITY_LEVELS) {
      const allowed = level === 'L3';
      expect(hasPermission(actor(level), 'payment:authorize')).toBe(allowed);
      expect(hasPermission(actor(level), 'payment:release')).toBe(allowed);
    }
  });

  it('AC-19: the balance and recent-transactions panels are L3-only', () => {
    for (const level of AUTHORITY_LEVELS) {
      const allowed = level === 'L3';
      expect(hasPermission(actor(level), 'dashboard:balance_panel')).toBe(allowed);
      expect(hasPermission(actor(level), 'dashboard:recent_transactions_panel')).toBe(allowed);
    }
  });

  it('only L3 may administer Daraja, users, policies, security and backups', () => {
    const adminPerms: Permission[] = [
      'admin:daraja',
      'admin:users',
      'admin:policies',
      'admin:security',
      'admin:backups',
    ];
    for (const p of adminPerms) {
      expect(hasPermission(actor('L1'), p)).toBe(false);
      expect(hasPermission(actor('L2'), p)).toBe(false);
      expect(hasPermission(actor('L3'), p)).toBe(true);
    }
  });

  it('L1 can submit to L2 but neither approve nor release', () => {
    expect(hasPermission(actor('L1'), 'batch:submit_to_l2')).toBe(true);
    expect(hasPermission(actor('L1'), 'batch:approve_to_l3')).toBe(false);
    expect(hasPermission(actor('L1'), 'payment:release')).toBe(false);
  });

  it('L2 approves to L3 but cannot release, and L3 cannot perform the L2 approval step', () => {
    expect(hasPermission(actor('L2'), 'batch:approve_to_l3')).toBe(true);
    expect(hasPermission(actor('L2'), 'payment:release')).toBe(false);
    // L3 performing its own L2 approval would collapse the two-person rule into one.
    expect(hasPermission(actor('L3'), 'batch:approve_to_l3')).toBe(false);
  });

  it('every level can see transaction statuses and failure reasons (§6, AC-16/17)', () => {
    for (const level of AUTHORITY_LEVELS) {
      expect(hasPermission(actor(level), 'transactions:read')).toBe(true);
    }
  });

  it('on-demand status refresh is L2/L3 only (TRK-007)', () => {
    expect(hasPermission(actor('L1'), 'transactions:refresh_status')).toBe(false);
    expect(hasPermission(actor('L2'), 'transactions:refresh_status')).toBe(true);
    expect(hasPermission(actor('L3'), 'transactions:refresh_status')).toBe(true);
  });

  it('denies every permission to a non-active account regardless of level', () => {
    for (const level of AUTHORITY_LEVELS) {
      for (const status of ['DISABLED', 'LOCKED'] as const) {
        const a = actor(level, { status });
        for (const p of PERMISSIONS) expect(hasPermission(a, p)).toBe(false);
      }
    }
  });

  it('capabilities payload covers every declared permission exactly', () => {
    const caps = capabilitiesFor(actor('L3'));
    expect(Object.keys(caps).sort()).toEqual([...PERMISSIONS].sort());
  });

  it('the forbidden capability list is disjoint from every grantable permission', () => {
    // A capability that is forbidden to all must never become a grantable Permission.
    for (const forbidden of FORBIDDEN_TO_ALL) {
      expect(PERMISSIONS as readonly string[]).not.toContain(forbidden);
    }
  });

  it('permission names are unique', () => {
    expect(new Set(PERMISSIONS).size).toBe(PERMISSIONS.length);
  });
});

describe('requirePermission enforcement', () => {
  it('throws a 403 SolvarenError when the level lacks the permission', () => {
    try {
      requirePermission(actor('L1'), 'payment:release');
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(SolvarenError);
      const e = err as SolvarenError;
      expect(e.code).toBe('PERMISSION_DENIED');
      expect(e.httpStatus).toBe(403);
      expect(e.details.permission).toBe('payment:release');
    }
  });

  it('throws when the account is not active, before checking the permission', () => {
    try {
      requirePermission(actor('L3', { status: 'DISABLED' }), 'payment:release');
      expect.unreachable('should have thrown');
    } catch (err) {
      expect((err as SolvarenError).code).toBe('ACTOR_NOT_ACTIVE');
    }
  });

  it('passes silently when the permission is held', () => {
    expect(() => requirePermission(actor('L3'), 'payment:release')).not.toThrow();
  });
});

describe('tenant isolation', () => {
  it('refuses access to an object owned by another organization', () => {
    try {
      requireSameOrganization(actor('L3'), 'org-2');
      expect.unreachable('should have thrown');
    } catch (err) {
      const e = err as SolvarenError;
      expect(e.code).toBe('CROSS_ORGANIZATION_DENIED');
      // The message must not confirm that the other organization's object exists.
      expect(e.message).toContain('not found');
      expect(e.message).not.toContain('org-2');
    }
  });

  it('allows access within the same organization', () => {
    expect(() => requireSameOrganization(actor('L2'), 'org-1')).not.toThrow();
  });
});

describe('failed-transaction export policy (§28)', () => {
  it('honours the org toggle for L1 and always allows L2/L3', () => {
    const off = { allowL1FailedExport: false };
    const on = { allowL1FailedExport: true };
    expect(canExportFailedTransactions(actor('L1'), off)).toBe(false);
    expect(canExportFailedTransactions(actor('L1'), on)).toBe(true);
    for (const level of ['L2', 'L3'] as const) {
      expect(canExportFailedTransactions(actor(level), off)).toBe(true);
      expect(canExportFailedTransactions(actor(level), on)).toBe(true);
    }
  });

  it('refuses a disabled L1 account even when the policy permits the level', () => {
    expect(canExportFailedTransactions(actor('L1', { status: 'DISABLED' }), { allowL1FailedExport: true })).toBe(false);
  });
});

describe('authority ranking', () => {
  it('orders levels correctly', () => {
    expect(atLeast('L3', 'L2')).toBe(true);
    expect(atLeast('L2', 'L2')).toBe(true);
    expect(atLeast('L1', 'L2')).toBe(false);
  });
});
