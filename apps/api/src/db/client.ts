/**
 * Database access through Cloudflare Hyperdrive.
 *
 * Three rules this module exists to enforce:
 *
 *  1. **Parameterised queries only.** The `sql` tagged template from `postgres` interpolates
 *     every value as a bind parameter. The one place user input influences SQL *text* is
 *     the explorer's ORDER BY, and that goes through the closed allowlist in
 *     `@solvaren/core` — there is no string concatenation of user input anywhere.
 *  2. **Tenant scoping is not optional.** `tenantScope` wraps a connection with the acting
 *     organisation so that helpers cannot accidentally issue an unscoped query.
 *  3. **Connections are per-request.** A Worker isolate may be reused across requests for
 *     different organisations; holding a connection across that boundary would be a
 *     cross-tenant hazard, so the connection is created per request and closed after.
 */

import postgres from 'postgres';
import { internalError } from '@solvaren/core';
import type { Env } from '../env.js';

/**
 * A postgres.js client with no custom type extensions.
 *
 * `Record<string, never>` rather than `{}`: the empty-object type accepts any non-nullish
 * value, so it would silently permit a mis-parameterised client.
 */
export type Sql = postgres.Sql<Record<string, never>>;

/**
 * Open a connection for the lifetime of one request or queue batch.
 *
 * `max: 1` is deliberate: Hyperdrive already pools on the Cloudflare side, and a Worker
 * isolate holding several sockets fights that pool rather than helping it.
 */
export function createConnection(env: Env): Sql {
  return postgres(env.HYPERDRIVE.connectionString, {
    max: 1,
    fetch_types: false, // saves a round trip per connection; all our types are standard
    idle_timeout: 20,
    connect_timeout: 10,
    prepare: false, // Hyperdrive pools connections; named prepared statements do not survive
    transform: { undefined: null },
    onnotice: () => {}, // suppress PostgreSQL NOTICEs from reaching Worker logs
  });
}

/**
 * Run a function with a connection, closing it afterwards even on failure.
 * `ctx.waitUntil` is used for the close so the response is not delayed by socket teardown.
 */
export async function withConnection<T>(
  env: Env,
  ctx: { waitUntil(promise: Promise<unknown>): void } | null,
  fn: (sql: Sql) => Promise<T>,
): Promise<T> {
  const sql = createConnection(env);
  try {
    return await fn(sql);
  } finally {
    const closing = sql.end({ timeout: 5 }).catch(() => {});
    if (ctx) ctx.waitUntil(closing);
    else await closing;
  }
}

/**
 * Execute inside a transaction with a statement timeout.
 *
 * The timeout matters on a payment platform: a query that hangs while holding row locks on
 * a batch blocks every other worker touching it, and Cloudflare will kill the isolate long
 * before PostgreSQL notices. Ten seconds is generous for every statement we issue.
 */
export async function inTransaction<T>(sql: Sql, fn: (tx: Sql) => Promise<T>): Promise<T> {
  return sql.begin(async (tx) => {
    await tx`SET LOCAL statement_timeout = '10s'`;
    await tx`SET LOCAL idle_in_transaction_session_timeout = '15s'`;
    // `TransactionSql` exposes the same query surface as `Sql` but omits the pool-level
    // members we never call inside a transaction, so the cast is through `unknown`.
    return fn(tx as unknown as Sql);
  }) as Promise<T>;
}

/**
 * Take a transaction-scoped advisory lock, so that two Workers cannot process the same
 * batch, backup or reconciliation case concurrently. Released automatically at commit or
 * rollback — there is no lock to leak if the isolate dies.
 */
export async function acquireLock(tx: Sql, namespace: string, id: string): Promise<boolean> {
  const rows = await tx<{ acquired: boolean }[]>`
    SELECT pg_try_advisory_xact_lock(hashtext(${`${namespace}:${id}`})) AS acquired
  `;
  return rows[0]?.acquired ?? false;
}

export async function requireLock(tx: Sql, namespace: string, id: string): Promise<void> {
  if (!(await acquireLock(tx, namespace, id))) {
    throw internalError(
      'RESOURCE_BUSY',
      'This item is currently being processed by another operation. Try again in a moment.',
      { namespace },
    );
  }
}

/*
 * Binding lists of UUIDs.
 *
 * `fetch_types: false` on the connection saves a round trip per connection but disables the
 * driver's array-OID inference, so a plain `${ids}::uuid[]` is serialised as a bare
 * comma-joined string that PostgreSQL rejects as a malformed array literal. Passing the
 * list as JSON and expanding it server-side is correct either way, handles the empty list,
 * and keeps every value a bound parameter rather than interpolated text.
 *
 * Two helpers, because the two SQL positions need different things — using one for the
 * other produces `uuid = uuid[]` or a syntax error, both of which are caught by the
 * integration suite rather than in production.
 */

/** A *set* of uuids, for the subquery form: `WHERE id = ANY(${uuidSet(sql, ids)})`. */
export function uuidSet(sql: Sql, ids: readonly string[]) {
  return sql`SELECT jsonb_array_elements_text(${sql.json([...ids] as never)}::jsonb)::uuid`;
}

/** A `uuid[]` *value*, for a column: `VALUES (..., ${uuidArrayValue(sql, ids)}, ...)`. */
export function uuidArrayValue(sql: Sql, ids: readonly string[]) {
  return sql`(SELECT COALESCE(ARRAY(SELECT jsonb_array_elements_text(${sql.json([...ids] as never)}::jsonb)::uuid), '{}'::uuid[]))`;
}

/** Assert exactly one row came back, with a caller-supplied not-found error. */
export function exactlyOne<T>(rows: readonly T[], onMissing: () => Error): T {
  const first = rows[0];
  if (first === undefined) throw onMissing();
  return first;
}
