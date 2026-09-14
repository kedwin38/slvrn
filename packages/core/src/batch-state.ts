/**
 * Payment batch lifecycle state machine (spec §5.1).
 *
 *   DRAFT → VALIDATED → SUBMITTED_TO_L2 → L2_REVIEW → L3_READY
 *   → AUTHORIZATION_PENDING → AUTHORIZED → QUEUED → SUBMITTED
 *   → PROCESSING → SUCCESS / FAILED / TIMEOUT / HELD / CANCELLED
 *
 * The machine is closed: `assertTransition` is the only way a batch changes state, it is
 * called inside the same database transaction that writes the new row, and every edge
 * names the permission and authority level required to traverse it. "A batch cannot move
 * backward by direct mutation."
 */

import { stateError, authorizationError } from './errors.js';
import type { AuthorityLevel, Permission } from './rbac.js';

export const BATCH_STATES = [
  'DRAFT',
  'VALIDATED',
  'SUBMITTED_TO_L2',
  'L2_REVIEW',
  'L3_READY',
  'AUTHORIZATION_PENDING',
  'AUTHORIZED',
  'QUEUED',
  'SUBMITTED',
  'PROCESSING',
  'SUCCESS',
  'PARTIAL_SUCCESS',
  'FAILED',
  'TIMEOUT',
  'HELD',
  'CANCELLED',
] as const;

export type BatchState = (typeof BATCH_STATES)[number];

/** States in which the instruction set may still be edited by L1. */
export const EDITABLE_STATES: readonly BatchState[] = ['DRAFT', 'VALIDATED'];

/** Terminal states — no outbound edges at all. */
export const TERMINAL_STATES: readonly BatchState[] = [
  'SUCCESS',
  'PARTIAL_SUCCESS',
  'FAILED',
  'CANCELLED',
];

/**
 * Commands are the *only* vocabulary for state change. There is deliberately no
 * `FORCE_STATE` command: spec §4.3 requires that not even L3 can force a batch to SUCCESS.
 */
export const BATCH_COMMANDS = [
  'VALIDATE',
  'INVALIDATE',
  'SUBMIT_TO_L2',
  'BEGIN_L2_REVIEW',
  'APPROVE_TO_L3',
  'REJECT',
  'RETURN_TO_L1',
  'HOLD',
  'RELEASE_HOLD',
  'BEGIN_AUTHORIZATION',
  'ABANDON_AUTHORIZATION',
  'AUTHORIZE',
  'ENQUEUE',
  'MARK_SUBMITTED',
  'MARK_PROCESSING',
  'SETTLE_SUCCESS',
  'SETTLE_PARTIAL',
  'SETTLE_FAILED',
  'SETTLE_TIMEOUT',
  'CANCEL',
] as const;

export type BatchCommand = (typeof BATCH_COMMANDS)[number];

export interface BatchEdge {
  readonly from: BatchState;
  readonly command: BatchCommand;
  readonly to: BatchState;
  /** Permission the actor must hold. `null` means the transition is system-driven only. */
  readonly permission: Permission | null;
  /** Minimum authority level; `null` for system transitions. */
  readonly minimumLevel: AuthorityLevel | null;
  /** True when only a queue consumer / scheduled worker may traverse the edge. */
  readonly systemOnly: boolean;
  /** Human-readable purpose, surfaced in the batch state timeline UI. */
  readonly describes: string;
}

const E = (
  from: BatchState,
  command: BatchCommand,
  to: BatchState,
  permission: Permission | null,
  minimumLevel: AuthorityLevel | null,
  describes: string,
  systemOnly = false,
): BatchEdge => ({ from, command, to, permission, minimumLevel, systemOnly, describes });

export const BATCH_EDGES: readonly BatchEdge[] = [
  // ---- Level 1 preparation ------------------------------------------------
  E('DRAFT', 'VALIDATE', 'VALIDATED', 'batch:validate', 'L1', 'All instructions passed validation'),
  E(
    'VALIDATED',
    'INVALIDATE',
    'DRAFT',
    'batch:edit',
    'L1',
    'Batch edited after validation; revalidation required',
  ),
  E(
    'VALIDATED',
    'SUBMIT_TO_L2',
    'SUBMITTED_TO_L2',
    'batch:submit_to_l2',
    'L1',
    'Submitted to Finance Control; approval version frozen',
  ),
  E('DRAFT', 'CANCEL', 'CANCELLED', 'batch:cancel', 'L1', 'Draft abandoned'),
  E(
    'VALIDATED',
    'CANCEL',
    'CANCELLED',
    'batch:cancel',
    'L1',
    'Validated batch abandoned before submission',
  ),

  // ---- Level 2 financial review -------------------------------------------
  E(
    'SUBMITTED_TO_L2',
    'BEGIN_L2_REVIEW',
    'L2_REVIEW',
    'batch:review',
    'L2',
    'Finance review opened',
  ),
  E(
    'L2_REVIEW',
    'APPROVE_TO_L3',
    'L3_READY',
    'batch:approve_to_l3',
    'L2',
    'Approved and forwarded for executive authorization',
  ),
  E(
    'L2_REVIEW',
    'REJECT',
    'DRAFT',
    'batch:reject',
    'L2',
    'Rejected and returned to Payment Operations',
  ),
  E('L2_REVIEW', 'RETURN_TO_L1', 'DRAFT', 'batch:reject', 'L2', 'Returned for correction'),
  /*
   * Approving straight from SUBMITTED_TO_L2, without a separate "open review" step.
   *
   * The approve route has always accepted this — it asserts BEGIN_L2_REVIEW and then
   * approves — but the edge table did not say so, so anything reading the table to decide
   * what a reviewer may do concluded that a freshly submitted batch could only be rejected
   * or held. That is the state every batch actually sits in when it reaches Finance
   * Control, and BEGIN_L2_REVIEW has no endpoint of its own to get out of it, so the
   * console offered no way to approve anything at all.
   *
   * Nothing is loosened by naming the edge: separation of duties, the risk acknowledgement
   * and the approval record are enforced in the route, not here.
   */
  E(
    'SUBMITTED_TO_L2',
    'APPROVE_TO_L3',
    'L3_READY',
    'batch:approve_to_l3',
    'L2',
    'Approved and forwarded for executive authorization',
  ),
  E('SUBMITTED_TO_L2', 'REJECT', 'DRAFT', 'batch:reject', 'L2', 'Rejected before review'),
  E('L2_REVIEW', 'HOLD', 'HELD', 'batch:hold', 'L2', 'Placed on hold pending clarification'),
  E('SUBMITTED_TO_L2', 'HOLD', 'HELD', 'batch:hold', 'L2', 'Placed on hold pending clarification'),

  // ---- Level 3 authorization ----------------------------------------------
  E('L3_READY', 'HOLD', 'HELD', 'batch:hold', 'L3', 'Executive hold'),
  E('L3_READY', 'REJECT', 'DRAFT', 'batch:reject', 'L3', 'Rejected by executive authority'),
  E('L3_READY', 'CANCEL', 'CANCELLED', 'batch:cancel', 'L3', 'Cancelled before release'),
  E(
    'L3_READY',
    'BEGIN_AUTHORIZATION',
    'AUTHORIZATION_PENDING',
    'payment:authorize',
    'L3',
    'Authorization ceremony opened; manifest challenge issued',
  ),
  E(
    'AUTHORIZATION_PENDING',
    'ABANDON_AUTHORIZATION',
    'L3_READY',
    'payment:authorize',
    'L3',
    'Authorization ceremony abandoned or challenge expired',
  ),
  E(
    'AUTHORIZATION_PENDING',
    'AUTHORIZE',
    'AUTHORIZED',
    'payment:release',
    'L3',
    'Manifest signed; payment release authorized',
  ),
  E(
    'AUTHORIZATION_PENDING',
    'CANCEL',
    'CANCELLED',
    'batch:cancel',
    'L3',
    'Cancelled during authorization',
  ),

  // ---- Hold handling -------------------------------------------------------
  E(
    'HELD',
    'RELEASE_HOLD',
    'SUBMITTED_TO_L2',
    'batch:hold',
    'L2',
    'Hold lifted; returned to review queue',
  ),
  E('HELD', 'CANCEL', 'CANCELLED', 'batch:cancel', 'L3', 'Held batch cancelled'),

  // ---- Execution (system-driven only) -------------------------------------
  E(
    'AUTHORIZED',
    'ENQUEUE',
    'QUEUED',
    null,
    null,
    'Dispatched to the payment execution queue',
    true,
  ),
  E('QUEUED', 'MARK_SUBMITTED', 'SUBMITTED', null, null, 'Instructions submitted to Daraja', true),
  E(
    'SUBMITTED',
    'MARK_PROCESSING',
    'PROCESSING',
    null,
    null,
    'Provider acknowledged; awaiting results',
    true,
  ),
  E(
    'QUEUED',
    'MARK_PROCESSING',
    'PROCESSING',
    null,
    null,
    'Provider acknowledged; awaiting results',
    true,
  ),
  E('PROCESSING', 'SETTLE_SUCCESS', 'SUCCESS', null, null, 'All instructions succeeded', true),
  E(
    'PROCESSING',
    'SETTLE_PARTIAL',
    'PARTIAL_SUCCESS',
    null,
    null,
    'Batch settled with one or more failures',
    true,
  ),
  E('PROCESSING', 'SETTLE_FAILED', 'FAILED', null, null, 'All instructions failed', true),
  E(
    'PROCESSING',
    'SETTLE_TIMEOUT',
    'TIMEOUT',
    null,
    null,
    'Provider outcome unresolved; reconciliation engaged',
    true,
  ),
  E(
    'SUBMITTED',
    'SETTLE_TIMEOUT',
    'TIMEOUT',
    null,
    null,
    'No provider acknowledgement; reconciliation engaged',
    true,
  ),
  E(
    'TIMEOUT',
    'SETTLE_SUCCESS',
    'SUCCESS',
    null,
    null,
    'Reconciliation resolved every instruction as successful',
    true,
  ),
  E(
    'TIMEOUT',
    'SETTLE_PARTIAL',
    'PARTIAL_SUCCESS',
    null,
    null,
    'Reconciliation resolved the batch with failures',
    true,
  ),
  E(
    'TIMEOUT',
    'SETTLE_FAILED',
    'FAILED',
    null,
    null,
    'Reconciliation resolved every instruction as failed',
    true,
  ),
];

const EDGE_INDEX = new Map<string, BatchEdge>();
for (const edge of BATCH_EDGES) EDGE_INDEX.set(`${edge.from}::${edge.command}`, edge);

export interface TransitionActor {
  level: AuthorityLevel;
  permissions: ReadonlySet<Permission>;
}

export interface TransitionOptions {
  /** Set when a queue consumer or scheduled worker is driving the transition. */
  system?: boolean;
  actor?: TransitionActor;
}

/**
 * Validate and resolve a transition. Throws rather than returning a boolean so that a
 * caller cannot accidentally ignore the result and write the row anyway.
 */
export function assertTransition(
  from: BatchState,
  command: BatchCommand,
  options: TransitionOptions = {},
): BatchEdge {
  const edge = EDGE_INDEX.get(`${from}::${command}`);
  if (!edge) {
    throw stateError(
      'BATCH_TRANSITION_INVALID',
      `Command ${command} is not valid for a batch in state ${from}`,
      { from, command, allowed: allowedCommands(from) },
    );
  }

  if (edge.systemOnly) {
    if (!options.system) {
      throw authorizationError(
        'BATCH_TRANSITION_SYSTEM_ONLY',
        `Command ${command} may only be issued by the payment execution system`,
        { command },
      );
    }
    return edge;
  }

  // A human-driven edge always requires a human actor; `system: true` must not be a skeleton
  // key that lets a worker bypass the approval chain.
  if (!options.actor) {
    throw authorizationError(
      'BATCH_TRANSITION_ACTOR_REQUIRED',
      `Command ${command} requires an authenticated actor`,
      { command },
    );
  }
  if (edge.permission && !options.actor.permissions.has(edge.permission)) {
    throw authorizationError(
      'BATCH_TRANSITION_PERMISSION_DENIED',
      `Command ${command} requires the ${edge.permission} permission`,
      { command, permission: edge.permission },
    );
  }
  return edge;
}

export function canTransition(from: BatchState, command: BatchCommand): boolean {
  return EDGE_INDEX.has(`${from}::${command}`);
}

export function allowedCommands(from: BatchState): BatchCommand[] {
  return BATCH_EDGES.filter((e) => e.from === from).map((e) => e.command);
}

/**
 * The commands this particular actor may issue against a batch in this state.
 *
 * `allowedCommands` answers a question about the state machine alone, which is the wrong
 * question for a console: it would offer an L1 the Approve button and let them discover the
 * refusal by pressing it. This intersects the state's edges with the actor's own
 * permissions, using exactly the rule `assertTransition` enforces, so the screen and the
 * server cannot disagree.
 *
 * System-only edges are never included: no human issues those, at any level.
 */
export function allowedCommandsForActor(
  from: BatchState,
  actor: { permissions: ReadonlySet<Permission> },
): BatchCommand[] {
  return BATCH_EDGES.filter(
    (e) =>
      e.from === from && !e.systemOnly && (!e.permission || actor.permissions.has(e.permission)),
  ).map((e) => e.command);
}

export function isEditable(state: BatchState): boolean {
  return EDITABLE_STATES.includes(state);
}

export function isTerminal(state: BatchState): boolean {
  return TERMINAL_STATES.includes(state);
}

/**
 * States at or beyond which money may already have moved. Used to refuse destructive
 * operations (delete, hard edit) regardless of the caller's authority.
 */
export function hasLeftTheBuilding(state: BatchState): boolean {
  return (
    state === 'QUEUED' ||
    state === 'SUBMITTED' ||
    state === 'PROCESSING' ||
    state === 'SUCCESS' ||
    state === 'PARTIAL_SUCCESS' ||
    state === 'FAILED' ||
    state === 'TIMEOUT'
  );
}
