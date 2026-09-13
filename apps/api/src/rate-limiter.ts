/**
 * Per-organisation submission rate limiter (spec 10: "Rate limiting aligned to the active
 * Daraja contract and operational safety thresholds").
 *
 * A Durable Object rather than a counter in PostgreSQL or KV, because rate limiting needs
 * a single authoritative counter and Durable Objects are the only Cloudflare primitive
 * that gives strong consistency for one key. A KV-based limiter would let a burst of
 * Workers each read a stale count and collectively blow straight through the limit — which,
 * against Daraja, means `500.003.03` and a payroll stalled mid-run.
 *
 * Two limits are enforced together:
 *   - a **token bucket** for sustained throughput, matching the contracted TPS;
 *   - a **hard ceiling on in-flight submissions**, so a provider slowdown cannot silently
 *     accumulate thousands of unresolved payments.
 */

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

interface BucketState {
  tokens: number;
  lastRefillMs: number;
}

/** Conservative defaults. Daraja does not publish a universal TPS; the contract governs. */
const DEFAULT_RATE_PER_SECOND = 5;
const DEFAULT_BURST = 20;

export class OrganizationRateLimiter implements DurableObject {
  private state: DurableObjectState;
  private bucket: BucketState | null = null;

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const body = (await request.json().catch(() => ({}))) as RateLimitRequest;
    const permits = Math.max(1, Math.min(body.permits ?? 1, 100));
    const ratePerSecond = Math.max(0.1, body.ratePerSecond ?? DEFAULT_RATE_PER_SECOND);
    const burst = Math.max(1, body.burst ?? DEFAULT_BURST);

    const now = Date.now();

    if (!this.bucket) {
      this.bucket =
        (await this.state.storage.get<BucketState>('bucket')) ?? { tokens: burst, lastRefillMs: now };
    }

    // Refill by elapsed time, capped at the burst size.
    const elapsedSeconds = Math.max(0, (now - this.bucket.lastRefillMs) / 1000);
    this.bucket.tokens = Math.min(burst, this.bucket.tokens + elapsedSeconds * ratePerSecond);
    this.bucket.lastRefillMs = now;

    let response: RateLimitResponse;

    if (this.bucket.tokens >= permits) {
      this.bucket.tokens -= permits;
      response = { allowed: true, remaining: Math.floor(this.bucket.tokens), retryAfterMs: 0 };
    } else {
      const deficit = permits - this.bucket.tokens;
      response = {
        allowed: false,
        remaining: Math.floor(this.bucket.tokens),
        retryAfterMs: Math.ceil((deficit / ratePerSecond) * 1000),
      };
    }

    // Persisted so the limit survives isolate eviction. Without this, a restart would
    // hand out a full burst immediately.
    await this.state.storage.put('bucket', this.bucket);

    return Response.json(response);
  }
}

/** Client helper used by the payment executor. */
export async function acquirePermit(
  namespace: DurableObjectNamespace,
  organizationId: string,
  options: RateLimitRequest = {},
): Promise<RateLimitResponse> {
  const id = namespace.idFromName(`rate:${organizationId}`);
  const stub = namespace.get(id);
  const response = await stub.fetch('https://rate-limiter.internal/acquire', {
    method: 'POST',
    body: JSON.stringify(options),
  });
  return (await response.json()) as RateLimitResponse;
}
