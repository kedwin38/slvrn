-- ============================================================================
-- SOLVAREN Payment Solutions — 0002 Payment domain
--
-- Recipients, departments, batches, instructions, approvals, the authorization
-- ceremony, transactions, idempotency and reconciliation.
--
-- This is the system of record. Its constraints are the last line of defence when
-- application logic is bypassed: a direct `psql` session must not be able to produce a
-- transaction that claims SUCCESS without a provider receipt, or a batch whose totals
-- disagree with its instructions.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Departments and recipients
-- ---------------------------------------------------------------------------
CREATE TABLE departments (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                TEXT        NOT NULL,
    code                TEXT,
    status              TEXT        NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'INACTIVE')),
    monthly_budget_cents BIGINT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT departments_name_unique UNIQUE (organization_id, name)
);

CREATE INDEX departments_org_idx ON departments (organization_id) WHERE status = 'ACTIVE';

CREATE TABLE recipients (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    full_name           TEXT        NOT NULL,
    -- Canonical 12-digit Kenyan MSISDN. The constraint is the same rule the CSV parser
    -- applies, restated here so that no code path can insert an unpayable number.
    msisdn              TEXT        NOT NULL,
    department_id       UUID REFERENCES departments(id) ON DELETE SET NULL,
    external_reference  TEXT,
    status              TEXT        NOT NULL DEFAULT 'ACTIVE'
                        CHECK (status IN ('ACTIVE', 'INACTIVE', 'BLOCKED')),
    metadata            JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by_user_id  UUID REFERENCES users(id),
    -- Drives the RECENTLY_MODIFIED_RECIPIENT risk signal: the account-swap attack changes
    -- this column, and the risk engine reads it.
    payment_details_modified_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    payment_details_modified_by UUID REFERENCES users(id),

    CONSTRAINT recipients_msisdn_format CHECK (msisdn ~ '^254(7|1)[0-9]{8}$'),
    CONSTRAINT recipients_msisdn_unique UNIQUE (organization_id, msisdn)
);

CREATE INDEX recipients_org_status_idx ON recipients (organization_id, status);
CREATE INDEX recipients_department_idx ON recipients (organization_id, department_id);
CREATE INDEX recipients_name_search_idx ON recipients USING gin (to_tsvector('simple', full_name));

COMMENT ON CONSTRAINT recipients_msisdn_unique ON recipients IS
    'One recipient per phone number per organisation. Two master records for the same number is how the same person gets paid twice through two batches.';

-- ---------------------------------------------------------------------------
-- Payment batches
-- ---------------------------------------------------------------------------
CREATE TABLE payment_batches (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id         UUID        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    batch_reference         TEXT        NOT NULL,
    purpose                 TEXT        NOT NULL,
    department_id           UUID REFERENCES departments(id) ON DELETE SET NULL,
    payment_period          TEXT,

    state                   TEXT        NOT NULL DEFAULT 'DRAFT' CHECK (state IN (
                                'DRAFT', 'VALIDATED', 'SUBMITTED_TO_L2', 'L2_REVIEW', 'L3_READY',
                                'AUTHORIZATION_PENDING', 'AUTHORIZED', 'QUEUED', 'SUBMITTED',
                                'PROCESSING', 'SUCCESS', 'PARTIAL_SUCCESS', 'FAILED', 'TIMEOUT',
                                'HELD', 'CANCELLED')),

    -- Monotonic content version. Every material edit increments it, which invalidates any
    -- approval and any authorization challenge bound to the old value (§7.5, §19).
    version                 INTEGER     NOT NULL DEFAULT 1,
    -- Denormalised roll-ups, maintained by trigger so they can never drift from the
    -- instruction rows they summarise.
    instruction_count       INTEGER     NOT NULL DEFAULT 0,
    total_amount_cents      BIGINT      NOT NULL DEFAULT 0,

    created_by_user_id      UUID        NOT NULL REFERENCES users(id),
    submitted_by_user_id    UUID REFERENCES users(id),
    approved_by_user_id     UUID REFERENCES users(id),
    authorized_by_user_id   UUID REFERENCES users(id),

    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_material_edit_at   TIMESTAMPTZ,
    submitted_at            TIMESTAMPTZ,
    approved_at             TIMESTAMPTZ,
    authorized_at           TIMESTAMPTZ,
    released_at             TIMESTAMPTZ,
    settled_at              TIMESTAMPTZ,

    risk_score              INTEGER,
    risk_band               TEXT CHECK (risk_band IN ('LOW', 'ELEVATED', 'HIGH', 'CRITICAL')),

    CONSTRAINT batches_reference_unique UNIQUE (organization_id, batch_reference),
    CONSTRAINT batches_totals_non_negative CHECK (instruction_count >= 0 AND total_amount_cents >= 0),
    -- §19: creator ≠ approver and creator ≠ authorizer, restated at the storage layer so
    -- that an application bug cannot persist a self-approved batch.
    CONSTRAINT batches_no_self_approval CHECK (
        approved_by_user_id IS NULL OR approved_by_user_id <> created_by_user_id),
    CONSTRAINT batches_no_self_authorization CHECK (
        authorized_by_user_id IS NULL OR authorized_by_user_id <> created_by_user_id),
    CONSTRAINT batches_approver_not_authorizer CHECK (
        authorized_by_user_id IS NULL OR approved_by_user_id IS NULL
        OR authorized_by_user_id <> approved_by_user_id)
);

CREATE INDEX batches_org_state_idx    ON payment_batches (organization_id, state, created_at DESC);
CREATE INDEX batches_org_created_idx  ON payment_batches (organization_id, created_at DESC);
CREATE INDEX batches_pending_review_idx ON payment_batches (organization_id, state)
    WHERE state IN ('SUBMITTED_TO_L2', 'L2_REVIEW', 'L3_READY', 'AUTHORIZATION_PENDING');

COMMENT ON CONSTRAINT batches_no_self_approval ON payment_batches IS
    'Separation of duties at the storage layer. The application blocks this first (§19); the constraint means a bug or a direct SQL session cannot.';

-- ---------------------------------------------------------------------------
-- Payment instructions
-- ---------------------------------------------------------------------------
CREATE TABLE payment_instructions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    batch_id            UUID        NOT NULL REFERENCES payment_batches(id) ON DELETE CASCADE,
    recipient_id        UUID        NOT NULL REFERENCES recipients(id) ON DELETE RESTRICT,
    -- Snapshot of the recipient at authorization time. If the master record is edited
    -- afterwards, the ledger still shows who was actually paid and on what number.
    recipient_name_snapshot TEXT    NOT NULL,
    msisdn_snapshot     TEXT        NOT NULL,
    department_id       UUID REFERENCES departments(id) ON DELETE SET NULL,

    amount_cents        BIGINT      NOT NULL,
    currency            TEXT        NOT NULL DEFAULT 'KES' CHECK (currency = 'KES'),
    remarks             TEXT        NOT NULL DEFAULT 'Business payment',
    occasion            TEXT,
    source_line_number  INTEGER,

    status              TEXT        NOT NULL DEFAULT 'PENDING' CHECK (status IN (
                            'PENDING', 'SUBMITTED', 'AWAITING_CALLBACK', 'PROCESSING',
                            'RECONCILING', 'SUCCESS', 'FAILED', 'TIMEOUT', 'CANCELLED')),

    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- M-PESA B2C accepts whole shillings between KES 10 and KES 250,000. Storing anything
    -- outside that range guarantees a provider rejection later, so it is refused now.
    CONSTRAINT instructions_amount_range CHECK (amount_cents BETWEEN 1000 AND 25000000),
    CONSTRAINT instructions_amount_whole_shillings CHECK (amount_cents % 100 = 0),
    CONSTRAINT instructions_msisdn_format CHECK (msisdn_snapshot ~ '^254(7|1)[0-9]{8}$'),
    CONSTRAINT instructions_remarks_length CHECK (char_length(remarks) BETWEEN 2 AND 100),
    CONSTRAINT instructions_occasion_length CHECK (occasion IS NULL OR char_length(occasion) BETWEEN 1 AND 100)
);

CREATE INDEX instructions_batch_idx      ON payment_instructions (batch_id, status);
CREATE INDEX instructions_org_status_idx ON payment_instructions (organization_id, status);
CREATE INDEX instructions_recipient_idx  ON payment_instructions (organization_id, recipient_id, created_at DESC);

COMMENT ON CONSTRAINT instructions_amount_whole_shillings ON payment_instructions IS
    'M-PESA B2C pays whole shillings. Rounding at the provider boundary would be a silent financial mutation, so fractional amounts are rejected at ingest and again here.';

-- Keep batch roll-ups exact. A denormalised total that drifts from its rows is worse than
-- no total at all, because it is the number a Level 3 authorizer reads before releasing.
CREATE OR REPLACE FUNCTION refresh_batch_totals() RETURNS TRIGGER AS $$
DECLARE
    target UUID := COALESCE(NEW.batch_id, OLD.batch_id);
BEGIN
    UPDATE payment_batches b
       SET instruction_count = sub.count,
           total_amount_cents = sub.total,
           updated_at = now()
      FROM (
          SELECT COUNT(*) AS count, COALESCE(SUM(amount_cents), 0) AS total
            FROM payment_instructions
           WHERE batch_id = target
      ) sub
     WHERE b.id = target;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER instructions_refresh_totals
    AFTER INSERT OR UPDATE OF amount_cents OR DELETE ON payment_instructions
    FOR EACH ROW EXECUTE FUNCTION refresh_batch_totals();

-- ---------------------------------------------------------------------------
-- Approvals (§15 — immutable workflow decisions)
-- ---------------------------------------------------------------------------
CREATE TABLE approvals (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    approval_reference  TEXT        NOT NULL,
    batch_id            UUID        NOT NULL REFERENCES payment_batches(id) ON DELETE CASCADE,
    -- The batch version this decision applies to. An edit bumps the version and this row
    -- becomes historical rather than being updated (§19: "Changes after Level 2 approval
    -- invalidate the affected approval version").
    batch_version       INTEGER     NOT NULL,
    actor_user_id       UUID        NOT NULL REFERENCES users(id),
    actor_level         TEXT        NOT NULL CHECK (actor_level IN ('L1', 'L2', 'L3')),
    action              TEXT        NOT NULL CHECK (action IN (
                            'SUBMIT', 'APPROVE', 'REJECT', 'RETURN', 'HOLD', 'RELEASE_HOLD',
                            'AUTHORIZE', 'CANCEL')),
    reason              TEXT,
    risk_acknowledged   BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT approvals_reference_unique UNIQUE (organization_id, approval_reference)
);

CREATE INDEX approvals_batch_idx ON approvals (batch_id, created_at DESC);
CREATE INDEX approvals_actor_idx ON approvals (organization_id, actor_user_id, created_at DESC);

-- Everyone who has materially edited a batch, for the SoD "modifier ≠ approver" rule.
CREATE TABLE batch_editors (
    batch_id            UUID        NOT NULL REFERENCES payment_batches(id) ON DELETE CASCADE,
    user_id             UUID        NOT NULL REFERENCES users(id),
    first_edited_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_edited_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    edit_count          INTEGER     NOT NULL DEFAULT 1,
    PRIMARY KEY (batch_id, user_id)
);

-- ---------------------------------------------------------------------------
-- Authorization ceremony (§7.5)
-- ---------------------------------------------------------------------------
CREATE TABLE authorization_challenges (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id         UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    batch_id                UUID        NOT NULL REFERENCES payment_batches(id) ON DELETE CASCADE,
    approval_id             UUID        NOT NULL REFERENCES approvals(id),
    authorizer_user_id      UUID        NOT NULL REFERENCES users(id),

    manifest_hash           TEXT        NOT NULL,
    challenge_hash          TEXT        NOT NULL,
    -- The exact bytes that were hashed, retained so an auditor can reproduce the digest
    -- years later without reconstructing application code.
    manifest_canonical_form TEXT        NOT NULL,
    nonce                   TEXT        NOT NULL,
    batch_version           INTEGER     NOT NULL,
    recipient_count         INTEGER     NOT NULL,
    total_amount_cents      BIGINT      NOT NULL,

    webauthn_challenge      TEXT        NOT NULL,
    issued_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at              TIMESTAMPTZ NOT NULL,
    consumed_at             TIMESTAMPTZ,
    -- Evidence of the completed ceremony.
    webauthn_credential_id  UUID REFERENCES webauthn_credentials(id),
    signature_verified_at   TIMESTAMPTZ,
    pin_verified_at         TIMESTAMPTZ,
    abandoned_at            TIMESTAMPTZ,

    CONSTRAINT challenge_nonce_unique UNIQUE (nonce),
    CONSTRAINT challenge_hash_unique  UNIQUE (challenge_hash),
    CONSTRAINT challenge_expiry_after_issue CHECK (expires_at > issued_at)
);

-- At most one live ceremony per batch: two concurrent authorizations of the same payroll
-- is exactly the race that produces a double disbursement.
CREATE UNIQUE INDEX challenge_one_open_per_batch
    ON authorization_challenges (batch_id)
    WHERE consumed_at IS NULL AND abandoned_at IS NULL;

CREATE INDEX challenge_expiry_idx ON authorization_challenges (expires_at)
    WHERE consumed_at IS NULL AND abandoned_at IS NULL;

COMMENT ON INDEX challenge_one_open_per_batch IS
    'Partial unique index: one open authorization ceremony per batch. Enforced by the database because two Workers can process two release requests simultaneously.';

-- ---------------------------------------------------------------------------
-- Idempotency ledger (§9.3)
-- ---------------------------------------------------------------------------
CREATE TABLE idempotency_claims (
    fingerprint                 TEXT        PRIMARY KEY,
    organization_id             UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    instruction_id              UUID        NOT NULL REFERENCES payment_instructions(id) ON DELETE CASCADE,
    state                       TEXT        NOT NULL DEFAULT 'CLAIMED'
                                CHECK (state IN ('CLAIMED', 'SUBMITTED', 'SETTLED', 'ABANDONED')),
    originator_conversation_id  TEXT,
    claimed_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- One live claim per instruction. The PRIMARY KEY on the content fingerprint stops the
    -- same authorized payment being claimed twice; this stops two different fingerprints
    -- (e.g. after an edit) racing for the same instruction.
    CONSTRAINT idempotency_one_per_instruction UNIQUE (instruction_id)
);

COMMENT ON TABLE idempotency_claims IS
    'Claimed before the provider call, never released. A worker retry finds the existing claim and reconciles instead of resubmitting — the primary control against double disbursement (Daraja''s own duplicate check is only the backstop).';

-- ---------------------------------------------------------------------------
-- Transactions — the provider execution ledger
-- ---------------------------------------------------------------------------
CREATE TABLE transactions (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id             UUID        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    instruction_id              UUID        NOT NULL REFERENCES payment_instructions(id) ON DELETE RESTRICT,
    batch_id                    UUID        NOT NULL REFERENCES payment_batches(id) ON DELETE RESTRICT,

    status                      TEXT        NOT NULL DEFAULT 'PENDING' CHECK (status IN (
                                    'PENDING', 'SUBMITTED', 'AWAITING_CALLBACK', 'PROCESSING',
                                    'RECONCILING', 'SUCCESS', 'FAILED', 'TIMEOUT', 'CANCELLED')),

    -- Provider correlation identifiers (§6.4 requires all three in the export).
    originator_conversation_id  TEXT        NOT NULL,
    conversation_id             TEXT,
    mpesa_receipt_number        TEXT,

    request_fingerprint         TEXT        NOT NULL,
    amount_cents                BIGINT      NOT NULL,

    -- Failure capture (§6.2). A FAILED row without a code is impossible by constraint,
    -- which is what makes "never blank, never just Error" a guarantee rather than an aim.
    failure_code                TEXT,
    failure_reason              TEXT,
    failure_class               TEXT,
    provider_result_description TEXT,

    status_source               TEXT CHECK (status_source IN
                                    ('SYNC_ACK', 'CALLBACK', 'QUEUE_TIMEOUT', 'STATUS_QUERY', 'SYSTEM')),
    last_status_check_at        TIMESTAMPTZ,
    status_check_count          INTEGER     NOT NULL DEFAULT 0,

    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    submitted_at                TIMESTAMPTZ,
    completed_at                TIMESTAMPTZ,
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT transactions_originator_unique UNIQUE (originator_conversation_id),
    -- A SUCCESS without a receipt would be an unverifiable claim that money moved.
    CONSTRAINT transactions_success_requires_receipt CHECK (
        status <> 'SUCCESS' OR (mpesa_receipt_number IS NOT NULL AND mpesa_receipt_number <> '')),
    -- TRK-002 at the storage layer: a failure always carries a code and a reason.
    CONSTRAINT transactions_failure_requires_reason CHECK (
        status <> 'FAILED' OR (failure_code IS NOT NULL AND failure_code <> ''
                               AND failure_reason IS NOT NULL AND failure_reason <> '')),
    CONSTRAINT transactions_amount_positive CHECK (amount_cents > 0)
);

-- Explorer indexes (§6.3, NFR-OPS-002). Every sort column in packages/core/src/explorer.ts
-- has a matching index so a 400,000-row ledger paginates without a sequential scan.
CREATE INDEX transactions_org_created_idx   ON transactions (organization_id, created_at DESC, id DESC);
CREATE INDEX transactions_org_status_idx    ON transactions (organization_id, status, created_at DESC);
CREATE INDEX transactions_batch_idx         ON transactions (batch_id, status);
CREATE INDEX transactions_instruction_idx   ON transactions (instruction_id);
CREATE INDEX transactions_receipt_idx       ON transactions (organization_id, mpesa_receipt_number)
    WHERE mpesa_receipt_number IS NOT NULL;
CREATE INDEX transactions_conversation_idx  ON transactions (conversation_id) WHERE conversation_id IS NOT NULL;
CREATE INDEX transactions_failure_code_idx  ON transactions (organization_id, failure_code)
    WHERE failure_code IS NOT NULL;
-- The reconciliation sweep's working set: everything still in flight, oldest first.
CREATE INDEX transactions_in_flight_idx     ON transactions (organization_id, last_status_check_at NULLS FIRST)
    WHERE status IN ('SUBMITTED', 'AWAITING_CALLBACK', 'PROCESSING', 'TIMEOUT', 'RECONCILING');
-- The failed-export working set (§6.4).
CREATE INDEX transactions_failed_export_idx ON transactions (organization_id, created_at DESC)
    WHERE status IN ('FAILED', 'TIMEOUT');

COMMENT ON CONSTRAINT transactions_success_requires_receipt ON transactions IS
    'Spec §23: "Attempt to forge a SUCCESS status through an API or database mutation path; confirm the application cannot perform it." This constraint extends that guarantee to direct SQL.';

-- Raw provider payloads, retained as audit evidence (§9.4).
CREATE TABLE provider_callbacks (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id             UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    transaction_id              UUID REFERENCES transactions(id) ON DELETE SET NULL,
    callback_type               TEXT        NOT NULL CHECK (callback_type IN
                                    ('B2C_RESULT', 'B2C_TIMEOUT', 'TRANSACTION_STATUS', 'ACCOUNT_BALANCE')),
    originator_conversation_id  TEXT,
    conversation_id             TEXT,
    result_code                 TEXT,
    -- Digest of the raw body. Re-delivery of an identical payload is detected here and
    -- recorded as a duplicate rather than reprocessed (§23 duplicate callback test).
    payload_digest              TEXT        NOT NULL,
    raw_payload                 JSONB       NOT NULL,
    source_ip                   INET,
    received_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    processed_at                TIMESTAMPTZ,
    processing_outcome          TEXT CHECK (processing_outcome IN
                                    ('APPLIED', 'DUPLICATE', 'UNMATCHED', 'REJECTED', 'IGNORED_SETTLED')),
    processing_note             TEXT,

    CONSTRAINT provider_callbacks_digest_unique UNIQUE (payload_digest)
);

CREATE INDEX provider_callbacks_txn_idx      ON provider_callbacks (transaction_id, received_at DESC);
CREATE INDEX provider_callbacks_unmatched_idx ON provider_callbacks (organization_id, received_at DESC)
    WHERE processing_outcome = 'UNMATCHED';

-- ---------------------------------------------------------------------------
-- Reconciliation (§9.3, TRK-008)
-- ---------------------------------------------------------------------------
CREATE TABLE reconciliation_cases (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    transaction_id      UUID        NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
    case_reference      TEXT        NOT NULL,
    state               TEXT        NOT NULL DEFAULT 'OPEN'
                        CHECK (state IN ('OPEN', 'QUERYING', 'RESOLVED_SUCCESS', 'RESOLVED_FAILED',
                                         'RESOLVED_MANUAL', 'ESCALATED')),
    opened_reason       TEXT        NOT NULL,
    -- Raised when a status query contradicts a settled ledger row. The ledger is never
    -- rewritten; a human decides what happened.
    discrepancy         BOOLEAN     NOT NULL DEFAULT FALSE,
    evidence            JSONB       NOT NULL DEFAULT '[]'::jsonb,
    query_attempts      INTEGER     NOT NULL DEFAULT 0,
    next_query_at       TIMESTAMPTZ,
    opened_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at         TIMESTAMPTZ,
    resolved_by_user_id UUID REFERENCES users(id),
    resolution_note     TEXT,

    CONSTRAINT reconciliation_reference_unique UNIQUE (organization_id, case_reference),
    CONSTRAINT reconciliation_one_open_per_txn EXCLUDE (transaction_id WITH =)
        WHERE (state IN ('OPEN', 'QUERYING'))
);

CREATE INDEX reconciliation_open_idx ON reconciliation_cases (organization_id, state, next_query_at NULLS FIRST)
    WHERE state IN ('OPEN', 'QUERYING');

-- ---------------------------------------------------------------------------
-- Risk findings (§11)
-- ---------------------------------------------------------------------------
CREATE TABLE risk_findings (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id         UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    batch_id                UUID REFERENCES payment_batches(id) ON DELETE CASCADE,
    batch_version           INTEGER,
    signal_type             TEXT        NOT NULL,
    severity                TEXT        NOT NULL CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    summary                 TEXT        NOT NULL,
    evidence                JSONB       NOT NULL DEFAULT '{}'::jsonb,
    instruction_ids         UUID[]      NOT NULL DEFAULT '{}',
    -- Advisory findings from the AI layer are marked so they can never be mistaken for a
    -- deterministic policy result (§11 AI CONTROL).
    source                  TEXT        NOT NULL DEFAULT 'DETERMINISTIC'
                            CHECK (source IN ('DETERMINISTIC', 'AI_ADVISORY')),
    disposition             TEXT        NOT NULL DEFAULT 'OPEN'
                            CHECK (disposition IN ('OPEN', 'ACKNOWLEDGED', 'CLEARED', 'ESCALATED')),
    dispositioned_by_user_id UUID REFERENCES users(id),
    dispositioned_at        TIMESTAMPTZ,
    disposition_note        TEXT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX risk_findings_batch_idx ON risk_findings (batch_id, severity, disposition);
CREATE INDEX risk_findings_open_idx  ON risk_findings (organization_id, disposition) WHERE disposition = 'OPEN';

-- ---------------------------------------------------------------------------
-- Balance snapshots (§21 — L3 executive panel)
-- ---------------------------------------------------------------------------
CREATE TABLE account_balance_snapshots (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    account_type        TEXT        NOT NULL,
    currency            TEXT        NOT NULL DEFAULT 'KES',
    available_cents     BIGINT      NOT NULL,
    uncleared_cents     BIGINT      NOT NULL DEFAULT 0,
    reserved_cents      BIGINT      NOT NULL DEFAULT 0,
    -- "as of" timestamp shown beside the figure. A balance without one invites an
    -- authorizer to treat a stale number as live.
    as_of               TIMESTAMPTZ NOT NULL,
    requested_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    requested_by_user_id UUID REFERENCES users(id),
    source              TEXT        NOT NULL DEFAULT 'CALLBACK'
                        CHECK (source IN ('CALLBACK', 'SCHEDULED', 'ON_DEMAND'))
);

CREATE INDEX balance_snapshots_org_idx ON account_balance_snapshots (organization_id, as_of DESC);

CREATE TRIGGER departments_updated_at BEFORE UPDATE ON departments
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER recipients_updated_at BEFORE UPDATE ON recipients
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER instructions_updated_at BEFORE UPDATE ON payment_instructions
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER transactions_updated_at BEFORE UPDATE ON transactions
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
