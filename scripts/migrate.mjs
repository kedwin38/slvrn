/**
 * Apply database migrations.
 *
 * Run as Railway's release command, so every deploy reaches a migrated database before the
 * new image serves traffic.
 *
 * Four properties matter for a migrator that runs automatically against a payment ledger:
 *
 *  1. **Each migration runs at most once**, recorded in `schema_migrations`.
 *  2. **Each runs inside a transaction.** A migration that fails half-applied would leave
 *     the schema in a state no version of the code expects.
 *  3. **Only one deploy migrates at a time.** Two replicas released simultaneously would
 *     otherwise race; a session advisory lock serialises them and the loser simply finds
 *     nothing left to do.
 *  4. **A changed migration is an error, not a silent skip.** Files are checksummed. If a
 *     migration that already ran has been edited, this stops — because the database no
 *     longer matches the file that claims to describe it, and continuing would hide that.
 *
 * Usage:
 *   node scripts/migrate.mjs                 # apply pending migrations
 *   node scripts/migrate.mjs --dry-run       # list what would be applied
 *   node scripts/migrate.mjs --status        # show applied and pending
 */

import postgres from 'postgres';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const MIGRATIONS_DIR = join(REPO_ROOT, 'db', 'migrations');

/** Distinct from the scheduler's keys so a migration never blocks a sweep or vice versa. */
const MIGRATION_LOCK_KEY = 947_200_001;

const args = new Set(process.argv.slice(2));
const dryRun = args.has('--dry-run');
const statusOnly = args.has('--status');

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  console.error(
    'DATABASE_URL is not set. Railway provides it when a PostgreSQL service is attached.',
  );
  process.exit(1);
}

/** Mirrors the TLS decision in apps/api/src/db/client.ts; see the comment there. */
function sslOption(url) {
  try {
    const { hostname, searchParams } = new URL(url);
    const sslmode = searchParams.get('sslmode');
    if (sslmode === 'disable') return {};
    if (sslmode && sslmode !== 'prefer') return { ssl: { rejectUnauthorized: false } };
    if (hostname === 'localhost' || hostname === '127.0.0.1') return {};
    if (hostname.endsWith('.railway.internal')) return {};
    return { ssl: { rejectUnauthorized: false } };
  } catch {
    return {};
  }
}

const sql = postgres(databaseUrl, { max: 1, onnotice: () => {}, ...sslOption(databaseUrl) });

function checksum(contents) {
  return createHash('sha256').update(contents).digest('hex').slice(0, 16);
}

function discover() {
  return readdirSync(MIGRATIONS_DIR)
    .filter((name) => name.endsWith('.sql'))
    .sort()
    .map((name) => {
      const contents = readFileSync(join(MIGRATIONS_DIR, name), 'utf8');
      return { name, contents, checksum: checksum(contents) };
    });
}

let locked = false;

try {
  await sql`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      name        TEXT PRIMARY KEY,
      checksum    TEXT NOT NULL,
      applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `;

  const migrations = discover();
  const appliedRows = await sql`SELECT name, checksum, applied_at FROM schema_migrations`;
  const applied = new Map(appliedRows.map((row) => [row.name, row]));

  // A migration that already ran but whose file has changed means the database and the
  // repository disagree about the schema. Refuse rather than guess which is right.
  const drifted = migrations.filter(
    (m) => applied.has(m.name) && applied.get(m.name).checksum !== m.checksum,
  );
  if (drifted.length > 0) {
    console.error('');
    console.error('  Migration drift detected. These files changed after they were applied:');
    for (const m of drifted) {
      console.error(
        `    ${m.name}  (recorded ${applied.get(m.name).checksum}, file ${m.checksum})`,
      );
    }
    console.error('');
    console.error('  The database no longer matches the migration that describes it.');
    console.error('  Write a NEW migration instead of editing an applied one.');
    process.exit(1);
  }

  const pending = migrations.filter((m) => !applied.has(m.name));

  if (statusOnly) {
    console.log('');
    console.log('  Applied:');
    for (const row of appliedRows.sort((a, b) => a.name.localeCompare(b.name))) {
      console.log(`    ${row.name.padEnd(40)} ${row.applied_at.toISOString()}`);
    }
    console.log('');
    console.log(pending.length ? '  Pending:' : '  Pending: none');
    for (const m of pending) console.log(`    ${m.name}`);
    console.log('');
    process.exit(0);
  }

  if (pending.length === 0) {
    console.log('  Database is up to date; no migrations to apply.');
    process.exit(0);
  }

  if (dryRun) {
    console.log(`  ${pending.length} migration(s) would be applied:`);
    for (const m of pending) console.log(`    ${m.name}`);
    process.exit(0);
  }

  // Serialise concurrent deploys. The loser waits, then finds nothing pending.
  const lock = await sql`SELECT pg_advisory_lock(${MIGRATION_LOCK_KEY})`;
  locked = true;
  void lock;

  // Re-read after taking the lock: another deploy may have applied everything while we
  // waited, and applying a migration twice is exactly what the lock exists to prevent.
  const afterLock = await sql`SELECT name FROM schema_migrations`;
  const nowApplied = new Set(afterLock.map((row) => row.name));
  const todo = pending.filter((m) => !nowApplied.has(m.name));

  if (todo.length === 0) {
    console.log('  Another deploy applied the pending migrations while we waited.');
    process.exit(0);
  }

  console.log(`  Applying ${todo.length} migration(s)…`);
  for (const migration of todo) {
    const started = Date.now();
    await sql.begin(async (tx) => {
      await tx.unsafe(migration.contents);
      await tx`
        INSERT INTO schema_migrations (name, checksum)
        VALUES (${migration.name}, ${migration.checksum})
      `;
    });
    console.log(`    ${migration.name.padEnd(40)} ${Date.now() - started}ms`);
  }
  console.log('  Migrations complete.');
} catch (error) {
  console.error('');
  console.error(`  Migration failed: ${error instanceof Error ? error.message : String(error)}`);
  console.error('  The failing migration was rolled back; the database is unchanged by it.');
  process.exitCode = 1;
} finally {
  if (locked) {
    await sql`SELECT pg_advisory_unlock(${MIGRATION_LOCK_KEY})`.catch(() => {});
  }
  await sql.end({ timeout: 10 });
}
