-- ============================================================================
-- SOLVAREN Payment Solutions — 0003 Audit, immutability and integrations
--
-- This migration is where §14 ("The audit layer is a security boundary, not a convenience
-- log") and §4.3 ("Even L3 cannot modify immutable audit history") stop being prose and
-- become database behaviour.
--
-- The guarantee is deliberately precise: an ordinary application connection — which is the
-- only connection the Workers hold — cannot UPDATE or DELETE a historical financial or
-- audit row, whatever SQL it sends. A database superuser can still disable these triggers,
-- but doing so is itself a privileged act outside the application's reach, and the audit
-- hash chain (packages/core/src/audit.ts) makes any resulting gap detectable.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Append-only audit log with a per-organisation hash chain
-- ---------------------------------------------------------------------------
CREATE TABLE audit_events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    -- Monotonic per organisation. The unique constraint makes a gap or a reordering
    -- impossible to introduce silently.
    sequence            BIGINT      NOT NULL,
    event_reference     TEXT        NOT NULL,

    actor_id            TEXT        NOT NULL,   -- user UUID, or 'system:reconciliation-worker'
    actor_level         TEXT,
    event_class         TEXT        NOT NULL CHECK (event_class IN (
                            'IDENTITY', 'AUTHORITY', 'PAYMENT', 'INTEGRATION',
                            'DATA_EXPORT', 'SECURITY', 'BACKUP', 'ADMINISTRATION')),
    action              TEXT        NOT NULL,
    object_type         TEXT        NOT NULL,
    object_id           TEXT,
    outcome             TEXT        NOT NULL CHECK (outcome IN ('SUCCESS', 'DENIED', 'FAILURE')),

    previous_state      JSONB,
    new_state           JSONB,
    security_context    JSONB       NOT NULL DEFAULT '{}'::jsonb,
    detail              JSONB       NOT NULL DEFAULT '{}'::jsonb,
    correlation_id      TEXT        NOT NULL,

    occurred_at         TIMESTAMPTZ NOT NULL,
    recorded_at         TIMESTAMPTZ NOT NULL DEFAULT now(),

    previous_hash       CHAR(64)    NOT NULL,
    event_hash          CHAR(64)    NOT NULL,

    CONSTRAINT audit_sequence_unique  UNIQUE (organization_id, sequence),
    CONSTRAINT audit_reference_unique UNIQUE (event_reference),
    CONSTRAINT audit_hash_unique      UNIQUE (event_hash),
    CONSTRAINT audit_sequence_positive CHECK (sequence > 0)
);

CREATE INDEX audit_org_time_idx    ON audit_events (organization_id, occurred_at DESC);
CREATE INDEX audit_org_class_idx   ON audit_events (organization_id, event_class, occurred_at DESC);
CREATE INDEX audit_actor_idx       ON audit_events (organization_id, actor_id, occurred_at DESC);
CREATE INDEX audit_object_idx      ON audit_events (organization_id, object_type, object_id);
CREATE INDEX audit_correlation_idx ON audit_events (correlation_id);
-- Denied attempts are the security team's primary view; keep them cheap to scan.
CREATE INDEX audit_denied_idx      ON audit_events (organization_id, occurred_at DESC) WHERE outcome = 'DENIED';

COMMENT ON TABLE audit_events IS
    'Append-only, hash-chained evidence. UPDATE and DELETE are blocked by trigger for every non-superuser role; each row commits to its predecessor so a removal breaks verification at a known point.';

-- ---------------------------------------------------------------------------
-- Immutability enforcement
-- ---------------------------------------------------------------------------

-- Absolute: no UPDATE, no DELETE, no exceptions, regardless of who is asking.
CREATE OR REPLACE FUNCTION forbid_mutation() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION
        'SOLVAREN immutability: % on % is not permitted. Historical financial and audit records are append-only (spec §4.3, §14).',
        TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'restrict_violation';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

-- Approvals are decisions, not drafts: a decision that can be edited is not a decision.
CREATE TRIGGER approvals_no_update BEFORE UPDATE ON approvals
    FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER approvals_no_delete BEFORE DELETE ON approvals
    FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

-- Raw provider evidence. `processed_at` / `processing_outcome` are set once by the
-- callback processor, so UPDATE is narrowly allowed; DELETE never is.
CREATE TRIGGER provider_callbacks_no_delete BEFORE DELETE ON provider_callbacks
    FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

/*
 * Transactions are mutable only *forwards* along the state machine, and only in the
 * columns that represent provider outcome. Everything that identifies the payment —
 * which instruction, which batch, how much, under which correlation id — is frozen at
 * insert. This is the storage-layer expression of "no alteration of historical
 * transactions (even by L3)".
 */
CREATE OR REPLACE FUNCTION guard_transaction_update() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.id <> OLD.id
       OR NEW.organization_id <> OLD.organization_id
       OR NEW.instruction_id <> OLD.instruction_id
       OR NEW.batch_id <> OLD.batch_id
       OR NEW.amount_cents <> OLD.amount_cents
       OR NEW.originator_conversation_id <> OLD.originator_conversation_id
       OR NEW.request_fingerprint <> OLD.request_fingerprint
       OR NEW.created_at <> OLD.created_at
    THEN
        RAISE EXCEPTION
            'SOLVAREN immutability: the identity of transaction % cannot be altered after creation.', OLD.id
            USING ERRCODE = 'restrict_violation';
    END IF;

    -- A settled outcome is final. Later evidence that disagrees opens a reconciliation
    -- discrepancy case; it never rewrites what the ledger says happened.
    IF OLD.status IN ('SUCCESS', 'FAILED', 'CANCELLED') AND NEW.status <> OLD.status THEN
        RAISE EXCEPTION
            'SOLVAREN immutability: transaction % is already settled as %; it cannot be changed to %.',
            OLD.id, OLD.status, NEW.status
            USING ERRCODE = 'restrict_violation';
    END IF;

    -- Provider evidence, once recorded, is evidence.
    IF OLD.mpesa_receipt_number IS NOT NULL AND NEW.mpesa_receipt_number IS DISTINCT FROM OLD.mpesa_receipt_number THEN
        RAISE EXCEPTION
            'SOLVAREN immutability: the M-PESA receipt on transaction % cannot be changed or removed.', OLD.id
            USING ERRCODE = 'restrict_violation';
    END IF;
    IF OLD.failure_code IS NOT NULL AND NEW.failure_code IS DISTINCT FROM OLD.failure_code
       AND OLD.status IN ('SUCCESS', 'FAILED', 'CANCELLED') THEN
        RAISE EXCEPTION
            'SOLVAREN immutability: the failure code on settled transaction % cannot be changed.', OLD.id
            USING ERRCODE = 'restrict_violation';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER transactions_guard_update BEFORE UPDATE ON transactions
    FOR EACH ROW EXECUTE FUNCTION guard_transaction_update();
CREATE TRIGGER transactions_no_delete BEFORE DELETE ON transactions
    FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

/*
 * A payment instruction becomes part of the financial record the moment its batch leaves
 * the editable states. After that it may change status but not substance: not the amount,
 * not the recipient, not the number the money is going to.
 */
CREATE OR REPLACE FUNCTION guard_instruction_update() RETURNS TRIGGER AS $$
DECLARE
    batch_state TEXT;
BEGIN
    SELECT state INTO batch_state FROM payment_batches WHERE id = OLD.batch_id;

    IF batch_state IS NOT NULL AND batch_state NOT IN ('DRAFT', 'VALIDATED') THEN
        IF NEW.amount_cents <> OLD.amount_cents
           OR NEW.recipient_id <> OLD.recipient_id
           OR NEW.msisdn_snapshot <> OLD.msisdn_snapshot
           OR NEW.batch_id <> OLD.batch_id
        THEN
            RAISE EXCEPTION
                'SOLVAREN immutability: instruction % belongs to a batch in state % and its amount or recipient can no longer be changed.',
                OLD.id, batch_state
                USING ERRCODE = 'restrict_violation';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER instructions_guard_update BEFORE UPDATE ON payment_instructions
    FOR EACH ROW EXECUTE FUNCTION guard_instruction_update();

-- Instructions may only be removed while the batch is still editable.
CREATE OR REPLACE FUNCTION guard_instruction_delete() RETURNS TRIGGER AS $$
DECLARE
    batch_state TEXT;
BEGIN
    SELECT state INTO batch_state FROM payment_batches WHERE id = OLD.batch_id;
    IF batch_state IS NOT NULL AND batch_state NOT IN ('DRAFT', 'VALIDATED') THEN
        RAISE EXCEPTION
            'SOLVAREN immutability: instruction % cannot be deleted; its batch is in state %.', OLD.id, batch_state
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER instructions_guard_delete BEFORE DELETE ON payment_instructions
    FOR EACH ROW EXECUTE FUNCTION guard_instruction_delete();

/*
 * Batches: the version counter only ever increases, released timestamps are write-once,
 * and a batch that has reached a terminal state stays there.
 */
CREATE OR REPLACE FUNCTION guard_batch_update() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.version < OLD.version THEN
        RAISE EXCEPTION
            'SOLVAREN immutability: the version of batch % cannot be decreased (% -> %).',
            OLD.id, OLD.version, NEW.version
            USING ERRCODE = 'restrict_violation';
    END IF;
    IF OLD.state IN ('SUCCESS', 'PARTIAL_SUCCESS', 'FAILED', 'CANCELLED') AND NEW.state <> OLD.state THEN
        RAISE EXCEPTION
            'SOLVAREN immutability: batch % is in terminal state % and cannot be moved to %.',
            OLD.id, OLD.state, NEW.state
            USING ERRCODE = 'restrict_violation';
    END IF;
    IF OLD.authorized_at IS NOT NULL AND NEW.authorized_at IS DISTINCT FROM OLD.authorized_at THEN
        RAISE EXCEPTION
            'SOLVAREN immutability: the authorization timestamp on batch % is write-once.', OLD.id
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER batches_guard_update BEFORE UPDATE ON payment_batches
    FOR EACH ROW EXECUTE FUNCTION guard_batch_update();

-- An authorization challenge is single-use. Un-consuming one would permit replay.
CREATE OR REPLACE FUNCTION guard_challenge_update() RETURNS TRIGGER AS $$
BEGIN
    IF OLD.consumed_at IS NOT NULL AND NEW.consumed_at IS DISTINCT FROM OLD.consumed_at THEN
        RAISE EXCEPTION
            'SOLVAREN immutability: authorization challenge % has already been consumed and cannot be reused.', OLD.id
            USING ERRCODE = 'restrict_violation';
    END IF;
    IF NEW.manifest_hash <> OLD.manifest_hash OR NEW.challenge_hash <> OLD.challenge_hash OR NEW.nonce <> OLD.nonce THEN
        RAISE EXCEPTION
            'SOLVAREN immutability: the cryptographic binding of challenge % cannot be altered.', OLD.id
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER challenges_guard_update BEFORE UPDATE ON authorization_challenges
    FOR EACH ROW EXECUTE FUNCTION guard_challenge_update();
CREATE TRIGGER challenges_no_delete BEFORE DELETE ON authorization_challenges
    FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

-- ---------------------------------------------------------------------------
-- Audit chain maintenance
-- ---------------------------------------------------------------------------

/*
 * Assign the sequence number and verify the chain link inside the insert itself.
 *
 * The advisory lock serialises appenders within an organisation. Without it, two Workers
 * inserting concurrently would both read the same tail and produce two rows claiming the
 * same predecessor — a fork in the chain that looks identical to tampering.
 */
CREATE OR REPLACE FUNCTION seal_audit_event() RETURNS TRIGGER AS $$
DECLARE
    tail_sequence BIGINT;
    tail_hash     CHAR(64);
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('solvaren_audit_' || NEW.organization_id::text));

    SELECT sequence, event_hash INTO tail_sequence, tail_hash
      FROM audit_events
     WHERE organization_id = NEW.organization_id
     ORDER BY sequence DESC
     LIMIT 1;

    IF tail_sequence IS NULL THEN
        tail_sequence := 0;
        tail_hash := repeat('0', 64);   -- GENESIS_HASH
    END IF;

    NEW.sequence := tail_sequence + 1;

    IF NEW.previous_hash <> tail_hash THEN
        RAISE EXCEPTION
            'SOLVAREN audit chain: event % claims predecessor % but the current tail is %.',
            NEW.event_reference, left(NEW.previous_hash, 12), left(tail_hash, 12)
            USING ERRCODE = 'restrict_violation';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_events_seal BEFORE INSERT ON audit_events
    FOR EACH ROW EXECUTE FUNCTION seal_audit_event();

-- Convenience view for the Security Center chain-verification screen.
CREATE OR REPLACE VIEW audit_chain_tails AS
SELECT DISTINCT ON (organization_id)
       organization_id, sequence, event_hash, occurred_at
  FROM audit_events
 ORDER BY organization_id, sequence DESC;

-- ---------------------------------------------------------------------------
-- Daraja integration configuration (§9.1 — L3 only, secrets by reference)
-- ---------------------------------------------------------------------------
CREATE TABLE daraja_configurations (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id             UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    environment                 TEXT        NOT NULL CHECK (environment IN ('sandbox', 'production')),
    short_code                  TEXT        NOT NULL,
    initiator_name              TEXT        NOT NULL,
    command_id                  TEXT        NOT NULL DEFAULT 'BusinessPayment'
                                CHECK (command_id IN ('BusinessPayment', 'SalaryPayment', 'PromotionPayment')),

    /*
     * Secrets live in the Cloudflare Secrets Store. These columns hold *references* only —
     * the binding name and a version tag. §8.4: "Application tables store metadata and
     * references, not plaintext credentials."
     *
     * The last four characters of the consumer key are kept purely so the configuration
     * screen can show `••••••••3f9a` and an administrator can tell two keys apart during a
     * rotation. Four characters of a public identifier is not a credential.
     */
    consumer_key_secret_ref     TEXT        NOT NULL,
    consumer_secret_secret_ref  TEXT        NOT NULL,
    security_credential_ref     TEXT        NOT NULL,
    consumer_key_last_four      TEXT,
    credential_version          INTEGER     NOT NULL DEFAULT 1,
    credential_rotated_at       TIMESTAMPTZ,
    credential_rotated_by       UUID REFERENCES users(id),

    result_url                  TEXT        NOT NULL,
    queue_timeout_url           TEXT        NOT NULL,
    -- Shared secret reference used to authenticate callbacks (§9.4).
    callback_secret_ref         TEXT        NOT NULL,

    status                      TEXT        NOT NULL DEFAULT 'DISABLED'
                                CHECK (status IN ('DISABLED', 'TESTING', 'ENABLED', 'ERROR')),
    last_test_at                TIMESTAMPTZ,
    last_test_ok                BOOLEAN,
    last_test_message           TEXT,
    -- Production processing is refused until a connection test has passed (§9.1).
    enabled_at                  TIMESTAMPTZ,
    enabled_by_user_id          UUID REFERENCES users(id),

    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT daraja_one_per_env UNIQUE (organization_id, environment),
    CONSTRAINT daraja_shortcode_format CHECK (short_code ~ '^[0-9]{5,9}$'),
    CONSTRAINT daraja_urls_https CHECK (result_url LIKE 'https://%' AND queue_timeout_url LIKE 'https://%'),
    CONSTRAINT daraja_enabled_requires_passing_test CHECK (
        status <> 'ENABLED' OR (last_test_ok IS TRUE AND enabled_at IS NOT NULL))
);

CREATE INDEX daraja_active_idx ON daraja_configurations (organization_id) WHERE status = 'ENABLED';

COMMENT ON CONSTRAINT daraja_enabled_requires_passing_test ON daraja_configurations IS
    'Spec §9.1: "Test connection before enabling production processing." An integration cannot be switched on without a passing test on record.';

COMMENT ON COLUMN daraja_configurations.consumer_key_last_four IS
    'Display aid for the masked credential UI only. Never the secret itself; the secret lives in the Cloudflare Secrets Store and is referenced by binding name.';

-- ---------------------------------------------------------------------------
-- Failure reason dictionary (TRK-009 — mappable without a deploy)
-- ---------------------------------------------------------------------------
CREATE TABLE failure_reason_map (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- NULL organization_id = the platform default dictionary shipped with the release.
    organization_id     UUID REFERENCES organizations(id) ON DELETE CASCADE,
    provider_code       TEXT        NOT NULL,
    reason              TEXT        NOT NULL,
    failure_class       TEXT        NOT NULL CHECK (failure_class IN (
                            'FUNDING', 'RECIPIENT', 'LIMIT', 'CREDENTIAL', 'PERMISSION',
                            'PROVIDER', 'REQUEST', 'AMBIGUOUS', 'UNKNOWN')),
    operator_action     TEXT        NOT NULL,
    transient           BOOLEAN     NOT NULL DEFAULT FALSE,
    dictionary_version  TEXT        NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by_user_id  UUID REFERENCES users(id),

    CONSTRAINT failure_map_reason_not_blank CHECK (btrim(reason) <> '' AND lower(btrim(reason)) <> 'error')
);

-- One mapping per code per scope; the NULLS NOT DISTINCT form treats the platform default
-- row as a single logical scope.
CREATE UNIQUE INDEX failure_map_scope_unique ON failure_reason_map (organization_id, provider_code)
    NULLS NOT DISTINCT;

COMMENT ON CONSTRAINT failure_map_reason_not_blank ON failure_reason_map IS
    'TRK-002 at the storage layer: a failure explanation may never be blank and may never be the bare word "Error".';

CREATE TRIGGER daraja_configurations_updated_at BEFORE UPDATE ON daraja_configurations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
