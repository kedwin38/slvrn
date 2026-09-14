/**
 * Derive an actor's real permission set from the authority matrix.
 *
 * Shared by the services and routes that feed `assertTransition`, because the alternative —
 * each caller constructing the set it expects to need — makes the state machine's authority
 * guard vacuous: passing in the permission the edge requires guarantees the check succeeds.
 * A guard that cannot fail is not a guard.
 */

import { PERMISSIONS, hasPermission, type Permission, type AuthorityLevel } from '@solvaren/core';

export function permissionsOfActor(actor: {
  level: AuthorityLevel;
  status: 'ACTIVE' | 'DISABLED' | 'LOCKED';
}): Set<Permission> {
  const held = new Set<Permission>();
  for (const permission of PERMISSIONS) {
    if (hasPermission(actor, permission)) held.add(permission);
  }
  return held;
}
