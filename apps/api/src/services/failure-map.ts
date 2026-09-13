/**
 * Failure-reason overrides (TRK-009).
 *
 * Resolution order is: organisation override -> platform default row -> the compiled
 * dictionary in @solvaren/core. The compiled fallback is what makes the guarantee hold
 * even if this query fails: a transaction still gets an explanation.
 */

import type { FailureOverrides, FailureClass } from '@solvaren/core';
import type { Sql } from '../db/client.js';

interface FailureMapRow {
  provider_code: string;
  reason: string;
  failure_class: FailureClass;
  operator_action: string;
  transient: boolean;
  organization_id: string | null;
}

export async function loadFailureOverrides(
  sql: Sql,
  organizationId: string,
): Promise<FailureOverrides> {
  try {
    const rows = await sql<FailureMapRow[]>`
      SELECT provider_code, reason, failure_class, operator_action, transient, organization_id
        FROM failure_reason_map
       WHERE organization_id = ${organizationId} OR organization_id IS NULL
       ORDER BY organization_id NULLS FIRST
    `;

    const overrides: Record<string, FailureOverrides[string]> = {};
    // Ordered NULLS FIRST, so an organisation-scoped row overwrites the platform default.
    for (const row of rows) {
      overrides[row.provider_code] = {
        reason: row.reason,
        class: row.failure_class,
        operatorAction: row.operator_action,
        transient: row.transient,
      };
    }
    return overrides;
  } catch (err) {
    // A dictionary lookup failure must never stop a failure being explained; the compiled
    // dictionary takes over.
    console.warn(
      JSON.stringify({
        level: 'warn',
        message: 'Failure reason overrides unavailable; using the compiled dictionary',
        error: err instanceof Error ? err.message : String(err),
      }),
    );
    return {};
  }
}
