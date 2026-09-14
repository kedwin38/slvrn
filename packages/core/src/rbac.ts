/**
 * Role-based access control and the authority matrix of SOLVAREN.
 *
 * This module is the single source of truth for "may this actor issue this command".
 * It is pure and synchronous so that it can be unit-tested exhaustively and called from
 * request middleware, queue consumers and export jobs alike. The UI may *also* hide
 * controls, but hiding a button is not an access control — every privileged API handler
 * calls `requirePermission` before it touches state (spec §4, HARD CONTROL).
 */

import { authorizationError } from './errors.js';

export const AUTHORITY_LEVELS = ['L1', 'L2', 'L3'] as const;
export type AuthorityLevel = (typeof AUTHORITY_LEVELS)[number];

export const LEVEL_RANK: Record<AuthorityLevel, number> = { L1: 1, L2: 2, L3: 3 };

export const LEVEL_TITLES: Record<AuthorityLevel, string> = {
  L1: 'Payment Operations',
  L2: 'Finance Control & Review',
  L3: 'Chief / Executive Payment Authority',
};

/**
 * Every privileged command in the platform. Adding a route without adding a permission
 * here is caught by the route-coverage test in `rbac.test.ts`.
 */
export const PERMISSIONS = [
  // Recipients & organisation data
  'recipients:read',
  'recipients:write',
  'departments:read',
  'departments:write',
  // Batch lifecycle
  'batch:create',
  'batch:edit',
  'batch:validate',
  'batch:read',
  'batch:submit_to_l2',
  'batch:review',
  'batch:approve_to_l3',
  'batch:reject',
  'batch:hold',
  'batch:cancel',
  // Payment authorization & release (L3 only)
  'payment:authorize',
  'payment:release',
  // Transactions & status tracking (§6)
  'transactions:read',
  'transactions:export_failed',
  'transactions:export_all',
  'transactions:refresh_status',
  'transactions:retry',
  // Reconciliation
  'reconciliation:read',
  'reconciliation:resolve',
  // Executive dashboard (L3 ONLY — §21)
  'dashboard:balance_panel',
  'dashboard:recent_transactions_panel',
  // Analytics & AI
  'analytics:basic',
  'analytics:advanced',
  'analytics:executive',
  'ai:batch_analysis',
  'ai:financial_analysis',
  'ai:executive_intelligence',
  // Reports
  'reports:operational',
  'reports:management',
  'reports:executive',
  // Administration
  'admin:users',
  'admin:policies',
  'admin:security',
  'admin:daraja',
  'admin:backups',
  // Audit
  'audit:read_own_scope',
  'audit:read_org',
  'audit:read_full',
] as const;

export type Permission = (typeof PERMISSIONS)[number];

/**
 * The permission matrix of spec §4.4. Default deny: a permission absent from a level's
 * set is refused, so new permissions are unreachable until deliberately granted.
 */
const MATRIX: Record<AuthorityLevel, ReadonlySet<Permission>> = {
  L1: new Set<Permission>([
    'recipients:read',
    'recipients:write',
    'departments:read',
    'batch:create',
    'batch:edit',
    'batch:validate',
    'batch:read',
    'batch:submit_to_l2',
    'transactions:read',
    'transactions:export_failed', // subject to the org export policy — see `canExportFailedTransactions`
    'analytics:basic',
    'ai:batch_analysis',
    'reports:operational',
    'audit:read_own_scope',
  ]),
  L2: new Set<Permission>([
    'recipients:read',
    'recipients:write',
    'departments:read',
    'departments:write',
    'batch:create',
    'batch:edit',
    'batch:validate',
    'batch:read',
    'batch:review',
    'batch:approve_to_l3',
    'batch:reject',
    'batch:hold',
    'transactions:read',
    'transactions:export_failed',
    'transactions:export_all',
    'transactions:refresh_status',
    'transactions:retry',
    'reconciliation:read',
    'reconciliation:resolve',
    'analytics:basic',
    'analytics:advanced',
    'ai:batch_analysis',
    'ai:financial_analysis',
    'reports:operational',
    'reports:management',
    'audit:read_own_scope',
    'audit:read_org',
  ]),
  L3: new Set<Permission>([
    'recipients:read',
    'recipients:write',
    'departments:read',
    'departments:write',
    'batch:create',
    'batch:edit',
    'batch:validate',
    'batch:read',
    'batch:review',
    'batch:reject',
    'batch:hold',
    'batch:cancel',
    'payment:authorize',
    'payment:release',
    'transactions:read',
    'transactions:export_failed',
    'transactions:export_all',
    'transactions:refresh_status',
    'transactions:retry',
    'reconciliation:read',
    'reconciliation:resolve',
    'dashboard:balance_panel',
    'dashboard:recent_transactions_panel',
    'analytics:basic',
    'analytics:advanced',
    'analytics:executive',
    'ai:batch_analysis',
    'ai:financial_analysis',
    'ai:executive_intelligence',
    'reports:operational',
    'reports:management',
    'reports:executive',
    'admin:users',
    'admin:policies',
    'admin:security',
    'admin:daraja',
    'admin:backups',
    'audit:read_own_scope',
    'audit:read_org',
    'audit:read_full',
  ]),
};

/**
 * Permissions that NO level holds, ever. These exist so that an attempt to grant them —
 * by a future code change, a seeded row, or a compromised admin — fails a test rather than
 * quietly becoming reachable. Spec §4.3: "Even L3 cannot…".
 */
export const FORBIDDEN_TO_ALL = [
  'audit:delete',
  'transactions:alter_history',
  'transactions:force_status',
  'daraja:view_plaintext_secret',
  'batch:self_approve',
] as const;
export type ForbiddenCapability = (typeof FORBIDDEN_TO_ALL)[number];

export interface Actor {
  userId: string;
  organizationId: string;
  level: AuthorityLevel;
  status: 'ACTIVE' | 'DISABLED' | 'LOCKED';
}

/** Pure predicate — no throwing, safe for UI capability payloads. */
export function hasPermission(
  actor: Pick<Actor, 'level' | 'status'>,
  permission: Permission,
): boolean {
  if (actor.status !== 'ACTIVE') return false;
  return MATRIX[actor.level].has(permission);
}

/** Enforcement helper used by every privileged handler. Throws 403 on denial. */
export function requirePermission(actor: Actor, permission: Permission): void {
  if (actor.status !== 'ACTIVE') {
    throw authorizationError('ACTOR_NOT_ACTIVE', 'This account is not active', {
      status: actor.status,
    });
  }
  if (!MATRIX[actor.level].has(permission)) {
    throw authorizationError(
      'PERMISSION_DENIED',
      `Authority level ${actor.level} may not perform this action`,
      {
        permission,
        level: actor.level,
      },
    );
  }
}

/** Organization scoping. Every query is tenant-scoped; this catches cross-tenant object ids. */
export function requireSameOrganization(actor: Actor, objectOrganizationId: string): void {
  if (actor.organizationId !== objectOrganizationId) {
    // Deliberately reported as NOT_FOUND-shaped detail to avoid confirming existence
    // of another tenant's object, while still auditing as an authorization denial.
    throw authorizationError('CROSS_ORGANIZATION_DENIED', 'Object not found in this organization');
  }
}

/**
 * Failed-transaction export policy (spec §28: "Default export policy per role").
 * L1 access is org-configurable and defaults to enabled, because the whole point of §6 is
 * that operators can act on their own failures without waiting for finance.
 */
export function canExportFailedTransactions(
  actor: Pick<Actor, 'level' | 'status'>,
  policy: { allowL1FailedExport: boolean },
): boolean {
  if (!hasPermission(actor, 'transactions:export_failed')) return false;
  if (actor.level === 'L1') return policy.allowL1FailedExport;
  return true;
}

/** The capability payload sent to the browser, so the UI can render honestly. */
export function capabilitiesFor(
  actor: Pick<Actor, 'level' | 'status'>,
): Record<Permission, boolean> {
  const out = {} as Record<Permission, boolean>;
  for (const p of PERMISSIONS) out[p] = hasPermission(actor, p);
  return out;
}

export function atLeast(level: AuthorityLevel, minimum: AuthorityLevel): boolean {
  return LEVEL_RANK[level] >= LEVEL_RANK[minimum];
}
