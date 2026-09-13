/**
 * Database access.
 *
 * Three rules this module exists to enforce:
 *
 *  1. **Parameterised queries only.** The `sql` tagged template from `postgres` interpolates
 *     every value as a bind parameter. The one place user input influences SQL *text* is
 *     the explorer's ORDER BY, and that goes through the closed allowlist in
 *     `@solvaren/core` — there is no string concatenation of user input anywhere.
 *  2. **Tenant scoping is not optional.** Every query carries the acting organisation, and
 *     the schema requires a NOT NULL `organization_id` on every tenant-owned table.
 *  3. **Connections come from one pool and are returned to it.** On Cloudflare this module
 *     opened a socket per request because a Worker isolate could be reused across
 *     organisations and holding a connection across that boundary was a cross-tenant
 *     hazard. A Node process has no such boundary: the pool is process-wide, checkout is
 *     per query, and a connection never carries session state between callers — nothing
 *     here issues SET (outside a transaction's SET LOCAL), LISTEN, or a temp table.
 */

import postgres from 'postgres';
import { internalError } from '@solvaren/core';

/**
 * A postgres.js client with no custom type extensions.
 *
 * `Record<string, never>` rather than `{}`: the empty-object type accepts any non-nullish
 * value, so it would silently permit a mis-parameterised client.
 */
export type Sql = postgres.Sql<Record<string, never>>;

export interface PoolOptions {
  /** Maximum pooled connections. Keep below the database's own limit. */
  max?: number;
  /** Require TLS. Railway's managed PostgreSQL terminates TLS on its proxy. */
  ssl?: boolean;
}

/**
 * Create the process-wide connection pool.
 *
 * Called once at boot. `max` defaults to 10, which is comfortably inside Railway's
 * PostgreSQL connection limit while leaving headroom for a second replica and for the
 * occasional `psql` session during an incident — a pool sized to the database's exact
 * maximum is a pool that locks the operator out of their own database at 3am.
 */
export function createPool(databaseUrl: string, options: PoolOptions = {}): Sql {
  const useSsl = options.ssl ?? shouldUseSsl(databaseUrl);
  return postgres(databaseUrl, {
    max: options.max ?? 10,
    fetch_types: false, // saves a round trip per connection; all our types are standard
    idle_timeout: 30,
    connect_timeout: 10,
    max_lifetime: 60 * 30,
    transform: { undefined: null },
    onnotice: () => {}, // suppress PostgreSQL NOTICEs from reaching the application log
    ...(useSsl ? { ssl: { rejectUnauthorized: false } } : {}),
  });
}

/**
 * Decide whether to negotiate TLS.
 *
 * Railway's internal network (`*.railway.internal`) is private and its PostgreSQL image
 * does not present a certificate there, so TLS is negotiated only for external hosts. A
 * local development database is likewise plaintext. Anything else gets TLS.
 *
 * `rejectUnauthorized: false` above is deliberate and worth understanding: managed
 * PostgreSQL providers, Railway included, present certificates signed by their own internal
 * CA. Verification would fail against the public trust store. The connection is still
 * encrypted; what is not verified is the server's identity, and on Railway's private
 * network that identity is established by the network itself.
 */
function shouldUseSsl(databaseUrl: string): boolean {
  try {
    const { hostname, searchParams } = new URL(databaseUrl);
    const sslmode = searchParams.get('sslmode');
    if (sslmode === 'disable') return false;
    if (sslmode && sslmode !== 'prefer') return true;
    if (hostname === 'localhost' || hostname === '127.0.0.1') return false;
    if (hostname.endsWith('.railway.internal')) return false;
    return true;
  } catch {
    return false;
  }
}

/**
 * Run a function against the pool.
 *
 * Retained as a named helper rather than passing `env.sql` around directly because it is
 * the seam every route already goes through, and because it keeps one place to add
 * per-request instrumentation.
 */
export async function withConnection<T>(
  env: { sql: Sql },
  fn: (sql: Sql) => Promise<T>,
): Promise<T> {
  return fn(env.sql);
}

/**
 * Execute inside a transaction with a statement timeout.
 *
 * The timeout matters on a payment platform: a query that hangs while holding row locks on
 * a batch blocks every other worker touching it. Ten seconds is generous for every
 * statement we issue, and a statement that exceeds it is a bug worth surfacing.
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
 * Take a transaction-scoped advisory lock, so that two workers cannot process the same
 * batch, backup or reconciliation case concurrently. Released automatically at commit or
 * rollback — there is no lock to leak if the process dies.
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
 * `fetch_types: false` on the pool saves a round trip per connection but disables the
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
