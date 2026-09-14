-- ============================================================================
-- 0008 — Job queue and rate limiting in PostgreSQL
--
-- Replaces two Cloudflare primitives: Queues and the Durable Object rate limiter.
--
-- The queue is not a compromise forced by the move. For this system it is stronger than
-- what it replaces, for one reason: `enqueue` can now run inside the same transaction as
-- the state change that justified it.
--
-- On the previous architecture, releasing a batch wrote the idempotency claims and then
-- enqueued the payment messages. Those are two systems, and a process that died between
-- them left them disagreeing — claims with no message (a payroll that silently never
-- runs) or, on redelivery of a partial write, a message with no claim. The code defended
-- against both, at length. Here the claim and the job commit together or neither does, and
-- that entire class of defect is gone.
--
-- Delivery semantics are at-least-once, which is what the payment executor already assumes
-- and already defends against with the idempotency claim and RECONCILE_FIRST. Nothing in
-- this migration weakens that assumption.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Jobs
-- ----------------------------------------------------------------------------

CREATE TABLE job_queue (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Which consumer handles this job. Not an FK to anything; the set is defined by the
    -- application's QueueName union and checked here so a typo cannot silently create a
    -- queue nobody consumes.
    queue               TEXT NOT NULL
        CHECK (queue IN ('payments', 'callbacks', 'reconciliation', 'backups')),

    -- The message. JSONB rather than TEXT so a stuck job can be inspected with SQL during
    -- an incident without a JSON parser in the loop.
    body                JSONB NOT NULL,

    -- Tenant scoping. Every job belongs to exactly one organisation, which makes
    -- "show me everything queued for this customer" a single indexed query.
    organization_id     UUID NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,

    -- Correlation id, lifted out of the body so it can be indexed and joined against the
    -- audit log when tracing one payment end to end.
    correlation_id      TEXT NOT NULL,

    status              TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'IN_FLIGHT', 'SUCCEEDED', 'DEAD_LETTERED')),

    -- Visibility. A job is claimable when `run_after` has passed. Retries set it forward.
    run_after           TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Claim bookkeeping. `claimed_until` is the visibility timeout: if a worker dies
    -- holding a job, the job becomes claimable again once this passes. There is no
    -- external broker to notice the death, so the deadline is the recovery mechanism.
    claimed_at          TIMESTAMPTZ,
    claimed_until       TIMESTAMPTZ,
    claimed_by          TEXT,

    attempts            INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts        INTEGER NOT NULL CHECK (max_attempts >= 1),

    last_error          TEXT,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at        TIMESTAMPTZ,
    dead_lettered_at    TIMESTAMPTZ,

    -- A terminal job must record when it became terminal, so "how long has this been
    -- stuck" is answerable without guessing.
    CONSTRAINT job_succeeded_requires_timestamp
        CHECK (status <> 'SUCCEEDED' OR completed_at IS NOT NULL),
    CONSTRAINT job_dead_lettered_requires_timestamp
        CHECK (status <> 'DEAD_LETTERED' OR dead_lettered_at IS NOT NULL),
    -- A dead-lettered job must say why. Same principle as a FAILED transaction: an
    -- operator looking at this row needs the reason, not just the fact.
    CONSTRAINT job_dead_lettered_requires_reason
        CHECK (status <> 'DEAD_LETTERED' OR (last_error IS NOT NULL AND last_error <> '')),
    -- An in-flight job must carry its lease.
    CONSTRAINT job_in_flight_requires_lease
        CHECK (status <> 'IN_FLIGHT' OR (claimed_until IS NOT NULL AND claimed_by IS NOT NULL))
);

COMMENT ON TABLE job_queue IS
    'Asynchronous work. Enqueued transactionally with the state change that justified it, so a job and its ledger row can never disagree.';

-- The claim query's index. Partial, because claimable jobs are a small minority of the
-- table and this keeps the index small enough to stay in cache under load.
CREATE INDEX job_queue_claimable_idx
    ON job_queue (queue, run_after, id)
    WHERE status = 'PENDING';

-- Recovering jobs whose worker died.
CREATE INDEX job_queue_expired_leases_idx
    ON job_queue (claimed_until)
    WHERE status = 'IN_FLIGHT';

-- Operator queries: what is stuck, and for whom.
CREATE INDEX job_queue_organization_idx ON job_queue (organization_id, created_at DESC);
CREATE INDEX job_queue_correlation_idx ON job_queue (correlation_id);
CREATE INDEX job_queue_dead_letter_idx
    ON job_queue (queue, dead_lettered_at DESC)
    WHERE status = 'DEAD_LETTERED';

-- ----------------------------------------------------------------------------
-- Payment jobs are singular
-- ----------------------------------------------------------------------------
--
-- The one guarantee worth enforcing in the schema rather than the application: a given
-- payment instruction may have at most one live job. Two concurrent releases of the same
-- batch, a retried API call, or a bug in the release path cannot produce two queued
-- submissions for one instruction.
--
-- This is defence in depth, not the primary control — the idempotency claim in
-- `idempotency_claims` is that, and it survives even a job delivered twice. But a
-- duplicate job is a thing that should never exist, and the cheapest place to say so is
-- here.
CREATE UNIQUE INDEX job_queue_one_live_payment_per_instruction
    ON job_queue ((body ->> 'instructionId'))
    WHERE queue = 'payments' AND status IN ('PENDING', 'IN_FLIGHT');

-- ----------------------------------------------------------------------------
-- A job's history is not rewritable
-- ----------------------------------------------------------------------------
--
-- Jobs are operational rather than financial records, so they are not append-only the way
-- audit events are — a job legitimately transitions PENDING → IN_FLIGHT → SUCCEEDED. What
-- must not happen is a *terminal* job coming back to life, which would re-submit a payment
-- that already settled.

CREATE OR REPLACE FUNCTION guard_job_update() RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status IN ('SUCCEEDED', 'DEAD_LETTERED') AND NEW.status <> OLD.status THEN
        RAISE EXCEPTION
            'SOLVAREN immutability: job % is already %, and a terminal job cannot be reopened. Enqueue a new job instead.',
            OLD.id, OLD.status
            USING ERRCODE = 'check_violation';
    END IF;

    -- The queue a job belongs to, its payload and its tenant are fixed at creation.
    -- Rewriting the body of a queued payment is precisely the attack the fingerprint check
    -- in the executor defends against; this closes the door at the database as well.
    IF NEW.queue <> OLD.queue OR NEW.body <> OLD.body OR NEW.organization_id <> OLD.organization_id THEN
        RAISE EXCEPTION
            'SOLVAREN immutability: the queue, payload and organisation of job % cannot be altered.',
            OLD.id
            USING ERRCODE = 'check_violation';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER job_queue_guard_update
    BEFORE UPDATE ON job_queue
    FOR EACH ROW EXECUTE FUNCTION guard_job_update();

-- ----------------------------------------------------------------------------
-- Rate limiting
-- ----------------------------------------------------------------------------
--
-- Replaces the Durable Object token bucket. A Durable Object was used because it gives a
-- single authoritative counter for one key; a row with `SELECT ... FOR UPDATE` gives the
-- same thing, and gives it across however many replicas Railway is running.
--
-- The bucket is stored rather than held in memory precisely so that scaling to a second
-- instance does not silently double the effective rate against Daraja — which would mean
-- 500.003.03 and a payroll stalled mid-run.

CREATE TABLE rate_limit_buckets (
    organization_id     UUID PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    tokens              DOUBLE PRECISION NOT NULL CHECK (tokens >= 0),
    last_refill_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE rate_limit_buckets IS
    'Per-organisation token bucket for Daraja submissions. A row rather than in-process state, so the limit holds across replicas.';

-- ----------------------------------------------------------------------------
-- Scheduled job bookkeeping
-- ----------------------------------------------------------------------------
--
-- Cloudflare guaranteed a cron fired once per schedule. A Node process has no such
-- guarantee: every replica runs every timer, and a replica that restarts runs its startup
-- tick again. An advisory lock stops two replicas running a job *simultaneously*; this
-- table stops a restarted replica running a once-a-day job a second time.

CREATE TABLE scheduled_job_runs (
    job_name    TEXT NOT NULL,
    ran_on      DATE NOT NULL,
    ran_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (job_name, ran_on)
);

COMMENT ON TABLE scheduled_job_runs IS
    'One row per daily job per day. The INSERT ... ON CONFLICT DO NOTHING is the claim: whichever replica inserts the row runs the job.';
