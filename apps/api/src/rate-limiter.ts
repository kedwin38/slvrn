/**
 * Per-organisation submission rate limiter (spec 10: "Rate limiting aligned to the active
 * Daraja contract and operational safety thresholds").
 *
 * A token bucket held in a PostgreSQL row and mutated under `SELECT ... FOR UPDATE`.
 *
 * The requirement is a single authoritative counter per organisation. On Cloudflare that
 * was a Durable Object, because it was the only primitive there offering strong consistency
 * for one key. A locked row gives the same guarantee and gives it across however many
 * replicas Railway is running — which matters more than it might appear: an in-process
 * counter would look correct in testing and then silently double the effective rate the
 * first time the service scaled to two instances. Against Daraja that means `500.003.03`
 * for the whole burst and a payroll stalled mid-run.
 *
 * The refill is computed from elapsed time rather than accumulated by a timer, so there is
 * no background job to run and a bucket that has not been touched for an hour is simply
 * full when next read.
 */

import type { Sql } from './db/client.js';
import type { RateLimiter } from './env.js';

export interface RateLimitRequest {
  /** Number of permits requested. One per payment submission. */
  permits?: number;
  /** Sustained rate in requests per second. */
  ratePerSecond?: number;
  /** Burst capacity. */
  burst?: number;
}

export interface RateLimitResponse {
  allowed: boolean;
  /** Permits remaining in the bucket after this decision. */
  remaining: number;
  /** Milliseconds until the next permit becomes available, when refused. */
  retryAfterMs: number;
}

/** Conservative defaults. Daraja does not publish a universal TPS; the contract governs. */
const DEFAULT_RATE_PER_SECOND = 5;
const DEFAULT_BURST = 20;

export class PostgresRateLimiter implements RateLimiter {
  constructor(private readonly pool: Sql) {}

  async acquire(
    organizationId: string,
    options: RateLimitRequest = {},
  ): Promise<RateLimitResponse> {
    const permits = Math.max(1, Math.min(options.permits ?? 1, 100));
    const ratePerSecond = Math.max(0.1, options.ratePerSecond ?? DEFAULT_RATE_PER_SECOND);
    const burst = Math.max(1, options.burst ?? DEFAULT_BURST);

    // The whole decision is one transaction: read the bucket under a row lock, refill it
    // for elapsed time, and either spend the permits or refuse. Two workers submitting
    // simultaneously serialise here rather than both seeing the same stale count.
    return this.pool.begin(async (tx) => {
      await tx`SET LOCAL statement_timeout = '5s'`;

      // Create the bucket full on first use, then lock whatever is there. `ON CONFLICT DO
      // NOTHING` plus a following SELECT is deliberate: an UPSERT that wrote `tokens`
      // would reset a live bucket to full on every call, which is a rate limiter that
      // never limits.
      await tx`
        INSERT INTO rate_limit_buckets (organization_id, tokens, last_refill_at)
        VALUES (${organizationId}, ${burst}, now())
        ON CONFLICT (organization_id) DO NOTHING
      `;

      const rows = await tx<{ tokens: number; elapsed_seconds: number }[]>`
        SELECT tokens,
               EXTRACT(EPOCH FROM (now() - last_refill_at))::double precision AS elapsed_seconds
          FROM rate_limit_buckets
         WHERE organization_id = ${organizationId}
           FOR UPDATE
      `;

      const current = rows[0];
      if (!current) {
        // The row was created above and is locked; its absence would mean someone deleted
        // the organisation mid-call. Refuse rather than invent a permit.
        return { allowed: false, remaining: 0, retryAfterMs: 1000 };
      }

      const refilled = Math.min(
        burst,
        current.tokens + Math.max(0, current.elapsed_seconds) * ratePerSecond,
      );

      if (refilled < permits) {
        const shortfall = permits - refilled;
        // Persist the refill even on refusal, so the elapsed time is not counted twice on
        // the next call.
        await tx`
          UPDATE rate_limit_buckets
             SET tokens = ${refilled}, last_refill_at = now(), updated_at = now()
           WHERE organization_id = ${organizationId}
        `;
        return {
          allowed: false,
          remaining: Math.floor(refilled),
          retryAfterMs: Math.ceil((shortfall / ratePerSecond) * 1000),
        };
      }

      const remaining = refilled - permits;
      await tx`
        UPDATE rate_limit_buckets
           SET tokens = ${remaining}, last_refill_at = now(), updated_at = now()
         WHERE organization_id = ${organizationId}
      `;

      return { allowed: true, remaining: Math.floor(remaining), retryAfterMs: 0 };
    });
  }
}

/**
 * Client helper used by the payment executor.
 *
 * Kept as a free function with the same name and shape as the Cloudflare version so the
 * call site reads identically — the executor should not need to know what backs the limiter.
 */
export async function acquirePermit(
  limiter: RateLimiter,
  organizationId: string,
  options: RateLimitRequest = {},
): Promise<RateLimitResponse> {
  return limiter.acquire(organizationId, options);
}
