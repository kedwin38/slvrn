/**
 * Scheduled work.
 *
 * Replaces the Worker's cron triggers. Three jobs, on fixed intervals:
 *
 *   every 5 minutes — reconciliation and status sweeps (TRK-008)
 *   hourly          — backup schedules, including missed-window detection (spec 13.4)
 *   daily at 02:00  — housekeeping: expire stale ceremonies and sessions
 *
 * **Every run takes a PostgreSQL advisory lock first.** This is the part that matters.
 * Cloudflare guaranteed a cron fired once per schedule regardless of how many isolates
 * existed; a Node process on Railway has no such guarantee, and the moment the service
 * scales to two replicas, every timer fires in every replica. For the reconciliation sweep
 * that would mean two concurrent Transaction Status sweeps per organisation — duplicated
 * provider calls against a rate-limited API, which is exactly what the rate limiter exists
 * to prevent.
 *
 * `pg_try_advisory_lock` is the cheapest correct answer: whichever replica gets the lock
 * runs the job, the others return immediately, and a replica that dies mid-job releases
 * the lock when its connection drops.
 *
 * The daily job additionally records the date it last ran, so that a restart at 02:05 does
 * not skip the day and a restart loop does not run it repeatedly.
 */

import { correlationId } from '@solvaren/core';
import type { Sql } from './db/client.js';
import type { Env } from './env.js';
import { runReconciliationSweep, runBackupSchedules, runHousekeeping } from './index.js';

const FIVE_MINUTES_MS = 5 * 60 * 1000;
const ONE_HOUR_MS = 60 * 60 * 1000;
/** Checked often; the job itself only runs once the UTC day has turned past 02:00. */
const DAILY_CHECK_MS = 10 * 60 * 1000;

/**
 * Advisory lock keys.
 *
 * Arbitrary but fixed constants. They must not collide with the keys used by
 * `acquireLock`, which hashes a namespaced string via `hashtext` — these are chosen in a
 * range that a text hash is vanishingly unlikely to produce, and each is distinct so two
 * different jobs never block one another.
 */
const LOCK_KEYS = {
  reconciliation: 947_100_001,
  backups: 947_100_002,
  housekeeping: 947_100_003,
} as const;

export interface SchedulerHandle {
  stop(): Promise<void>;
}

/**
 * Start the three timers.
 *
 * Each job is run once at startup too, after a short stagger. A deploy that happens to land
 * between two five-minute ticks should not leave in-flight payments unreconciled for the
 * remainder of the interval; the advisory lock makes the extra run harmless.
 */
export function startScheduler(env: Env): SchedulerHandle {
  const timers: NodeJS.Timeout[] = [];
  let running = true;
  let active: Promise<unknown> = Promise.resolve();

  const schedule = (
    name: keyof typeof LOCK_KEYS,
    intervalMs: number,
    job: (env: Env, correlation: string) => Promise<void>,
    shouldRun?: (sql: Sql) => Promise<boolean>,
  ) => {
    const tick = () => {
      if (!running) return;
      active = active
        .then(() => runLocked(env, name, job, shouldRun))
        .catch((error) => {
          console.error(
            JSON.stringify({
              level: 'error',
              message: 'Scheduled job failed',
              job: name,
              error: error instanceof Error ? error.message : String(error),
            }),
          );
        });
    };
    timers.push(setInterval(tick, intervalMs));
    // Stagger the startup runs so three jobs do not contend for the pool at once.
    timers.push(setTimeout(tick, 5000 + timers.length * 2000));
  };

  schedule('reconciliation', FIVE_MINUTES_MS, runReconciliationSweep);
  schedule('backups', ONE_HOUR_MS, runBackupSchedules);
  schedule('housekeeping', DAILY_CHECK_MS, runHousekeeping, dailyWindowHasNotRunToday);

  console.log(
    JSON.stringify({
      level: 'info',
      message: 'Scheduler started',
      jobs: Object.keys(LOCK_KEYS),
    }),
  );

  return {
    async stop() {
      running = false;
      for (const timer of timers) clearTimeout(timer);
      for (const timer of timers) clearInterval(timer);
      // Let whatever is mid-flight finish rather than tearing down its transaction.
      await active.catch(() => {});
      console.log(JSON.stringify({ level: 'info', message: 'Scheduler stopped' }));
    },
  };
}

/**
 * Run a job while holding its advisory lock.
 *
 * The lock is session-scoped rather than transaction-scoped, because the job runs many
 * transactions. It is taken and released on one reserved connection, and released in a
 * `finally` so a thrown job does not hold it until the process exits.
 */
async function runLocked(
  env: Env,
  name: keyof typeof LOCK_KEYS,
  job: (env: Env, correlation: string) => Promise<void>,
  shouldRun?: (sql: Sql) => Promise<boolean>,
): Promise<void> {
  const key = LOCK_KEYS[name];
  const reserved = await env.sql.reserve();

  try {
    const locked = await reserved<{ acquired: boolean }[]>`
      SELECT pg_try_advisory_lock(${key}) AS acquired
    `;
    if (!locked[0]?.acquired) {
      // Another replica is running it. Not an error, and not worth logging at info on
      // every tick of every replica.
      return;
    }

    try {
      if (shouldRun && !(await shouldRun(reserved))) return;

      const correlation = correlationId();
      const started = Date.now();
      await job(env, correlation);
      console.log(
        JSON.stringify({
          level: 'info',
          message: 'Scheduled job complete',
          job: name,
          durationMs: Date.now() - started,
          correlationId: correlation,
        }),
      );
    } finally {
      await reserved`SELECT pg_advisory_unlock(${key})`;
    }
  } finally {
    reserved.release();
  }
}

/**
 * Gate the daily job to once per UTC day, after 02:00.
 *
 * Without this the ten-minute check would run housekeeping 144 times a day. The marker is
 * a row rather than process state so it survives a restart and is shared across replicas —
 * the advisory lock stops two replicas running it *simultaneously*, but only a persisted
 * marker stops a replica that restarted at 02:05 running it *again*.
 */
async function dailyWindowHasNotRunToday(sql: Sql): Promise<boolean> {
  const now = new Date();
  if (now.getUTCHours() < 2) return false;

  const today = now.toISOString().slice(0, 10);
  const rows = await sql<{ claimed: boolean }[]>`
    INSERT INTO scheduled_job_runs (job_name, ran_on)
    VALUES ('housekeeping', ${today}::date)
    ON CONFLICT (job_name, ran_on) DO NOTHING
    RETURNING TRUE AS claimed
  `;
  return rows.length > 0;
}
