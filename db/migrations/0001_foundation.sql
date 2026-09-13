-- ============================================================================
-- SOLVAREN Payment Solutions — 0001 Foundation
--
-- Tenancy, identity, authenticators, devices and organisation policy.
--
-- Conventions used throughout every migration:
--   * Every tenant-owned table carries organization_id and is indexed on it first.
--     Cross-tenant leakage is the highest-impact bug class in a multi-tenant payment
--     platform, so the column is NOT NULL everywhere and application queries are required
--     to filter on it (enforced by the query-builder helpers in apps/api/src/db).
--   * Money is BIGINT cents. No NUMERIC, no floats: cents are exact and fit comfortably in
--     a signed 64-bit integer for any realistic payroll.
--   * Timestamps are TIMESTAMPTZ, stored in UTC. Kenya is UTC+3 with no DST, but a
--     multinational customer's reporting must not depend on that.
--   * Enumerations are TEXT with CHECK constraints rather than native ENUM types, because
--     adding a value to a native enum takes a lock and cannot be done inside a transaction
--     in older PostgreSQL versions.
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_uuid(), digest()
CREATE EXTENSION IF NOT EXISTS "citext";     -- case-insensitive email

-- ---------------------------------------------------------------------------
-- Organisations
-- ---------------------------------------------------------------------------
CREATE TABLE organizations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                TEXT        NOT NULL,
    slug                TEXT        NOT NULL UNIQUE,
    status              TEXT        NOT NULL DEFAULT 'ACTIVE'
                        CHECK (status IN ('ACTIVE', 'SUSPENDED', 'CLOSED')),
    timezone            TEXT        NOT NULL DEFAULT 'Africa/Nairobi',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT organizations_slug_format CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$')
);

COMMENT ON TABLE organizations IS
    'Tenant boundary. Every other tenant-owned row references this table and no query may span two organisations.';

-- ---------------------------------------------------------------------------
-- Organisation policy (§20, packages/core/src/policy.ts)
-- ---------------------------------------------------------------------------
CREATE TABLE policies (
    organization_id                 UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    max_instruction_amount_cents    BIGINT  NOT NULL DEFAULT 25000000,   -- KES 250,000 (M-PESA ceiling)
    max_batch_total_cents           BIGINT  NOT NULL DEFAULT 5000000000, -- KES 50,000,000
    max_batch_instructions          INTEGER NOT NULL DEFAULT 5000,
    high_value_threshold_cents      BIGINT  NOT NULL DEFAULT 500000000,  -- KES 5,000,000
    cooling_off_seconds             INTEGER NOT NULL DEFAULT 300,
    blocking_risk_band              TEXT    NOT NULL DEFAULT 'CRITICAL'
                                    CHECK (blocking_risk_band IN ('NEVER', 'HIGH', 'CRITICAL')),
    allow_l1_failed_export          BOOLEAN NOT NULL DEFAULT TRUE,
    max_export_rows                 INTEGER NOT NULL DEFAULT 50000,
    daily_disbursement_ceiling_cents BIGINT NOT NULL DEFAULT 0,          -- 0 disables the circuit breaker
    -- Risk model tuning (packages/core/src/risk.ts)
    risk_amount_deviation_multiple  NUMERIC(5,2) NOT NULL DEFAULT 2.50,
    risk_new_recipient_window_hours INTEGER NOT NULL DEFAULT 72,
    risk_batch_deviation_fraction   NUMERIC(5,4) NOT NULL DEFAULT 0.2500,
    risk_late_edit_window_minutes   INTEGER NOT NULL DEFAULT 10,
    risk_acknowledgement_threshold  INTEGER NOT NULL DEFAULT 40,
    updated_at                      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by_user_id              UUID,

    CONSTRAINT policies_limits_sane CHECK (
        max_instruction_amount_cents > 0
        AND max_instruction_amount_cents <= 25000000
        AND max_batch_total_cents >= max_instruction_amount_cents
        AND max_batch_instructions > 0
    )
);

COMMENT ON CONSTRAINT policies_limits_sane ON policies IS
    'The per-instruction ceiling can never exceed the M-PESA B2C maximum of KES 250,000; a policy that promised more would fail at the provider with result code 3.';

-- ---------------------------------------------------------------------------
-- Users
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id         UUID        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    email                   CITEXT      NOT NULL,
    full_name               TEXT        NOT NULL,
    authority_level         TEXT        NOT NULL CHECK (authority_level IN ('L1', 'L2', 'L3')),
    status                  TEXT        NOT NULL DEFAULT 'ACTIVE'
                            CHECK (status IN ('ACTIVE', 'DISABLED', 'LOCKED', 'PENDING_ENROLMENT')),

    -- Argon2id. The encoded string carries its own salt and parameters; there is no
    -- separate salt column and no reversible representation anywhere in the schema.
    password_hash           TEXT        NOT NULL,
    password_updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- SOLVAREN Authorization PIN (SPAC, §7.4). Also Argon2id, also non-reversible, and
    -- deliberately a *different* credential from the login password.
    authorization_pin_hash  TEXT,
    authorization_pin_updated_at TIMESTAMPTZ,

    failed_login_count      INTEGER     NOT NULL DEFAULT 0,
    locked_until            TIMESTAMPTZ,
    last_login_at           TIMESTAMPTZ,

    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by_user_id      UUID REFERENCES users(id),
    disabled_at             TIMESTAMPTZ,

    CONSTRAINT users_email_unique_per_org UNIQUE (organization_id, email),
    -- §7.3: WebAuthn is mandatory for L2/L3, and an L2/L3 account without an authorization
    -- PIN cannot complete a release ceremony, so it must not be marked ACTIVE.
    CONSTRAINT users_privileged_requires_pin CHECK (
        authority_level = 'L1' OR status <> 'ACTIVE' OR authorization_pin_hash IS NOT NULL
    )
);

CREATE INDEX users_org_level_idx   ON users (organization_id, authority_level) WHERE status = 'ACTIVE';
CREATE INDEX users_org_status_idx  ON users (organization_id, status);

COMMENT ON COLUMN users.authorization_pin_hash IS
    'SPAC credential hash. Separate from password_hash by design: being logged in is never sufficient authority to release money (§7).';

-- ---------------------------------------------------------------------------
-- WebAuthn credentials (§7.3 — mandatory for L2/L3)
-- ---------------------------------------------------------------------------
CREATE TABLE webauthn_credentials (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id             UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id       TEXT        NOT NULL,          -- base64url
    public_key          BYTEA       NOT NULL,          -- COSE public key
    signature_counter   BIGINT      NOT NULL DEFAULT 0,
    transports          TEXT[]      NOT NULL DEFAULT '{}',
    aaguid              TEXT,
    attestation_format  TEXT,
    -- A platform authenticator (passkey) and a roaming security key are operationally
    -- different things; L3 accounts are encouraged to hold at least one roaming key.
    device_type         TEXT        NOT NULL DEFAULT 'UNKNOWN'
                        CHECK (device_type IN ('PLATFORM', 'CROSS_PLATFORM', 'UNKNOWN')),
    backed_up           BOOLEAN     NOT NULL DEFAULT FALSE,
    friendly_name       TEXT,
    status              TEXT        NOT NULL DEFAULT 'ACTIVE'
                        CHECK (status IN ('ACTIVE', 'REVOKED')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at        TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,

    CONSTRAINT webauthn_credential_id_unique UNIQUE (credential_id)
);

CREATE INDEX webauthn_user_idx ON webauthn_credentials (user_id) WHERE status = 'ACTIVE';

COMMENT ON COLUMN webauthn_credentials.signature_counter IS
    'Authenticator signature counter. A value that fails to increase indicates a cloned authenticator and raises a security event rather than silently succeeding.';

-- ---------------------------------------------------------------------------
-- Trusted devices (§8.1)
-- ---------------------------------------------------------------------------
CREATE TABLE trusted_devices (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id         UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id                 UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_fingerprint      TEXT        NOT NULL,
    webauthn_credential_id  UUID REFERENCES webauthn_credentials(id) ON DELETE SET NULL,
    trust_status            TEXT        NOT NULL DEFAULT 'REVIEW'
                            CHECK (trust_status IN ('TRUSTED', 'REVIEW', 'BLOCKED', 'REVOKED')),
    label                   TEXT,
    first_seen_ip           INET,
    last_seen_ip            INET,
    user_agent              TEXT,
    registered_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_activity_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at              TIMESTAMPTZ,

    CONSTRAINT trusted_devices_unique UNIQUE (user_id, device_fingerprint)
);

CREATE INDEX trusted_devices_user_idx ON trusted_devices (user_id, trust_status);

-- ---------------------------------------------------------------------------
-- Sessions (§8.2)
-- ---------------------------------------------------------------------------
CREATE TABLE sessions (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id         UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id                 UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Only a hash of the session token is stored. A database reader must not be able to
    -- resume a live session.
    token_hash              TEXT        NOT NULL UNIQUE,
    trusted_device_id       UUID REFERENCES trusted_devices(id) ON DELETE SET NULL,
    -- Timestamp of the most recent *full* authentication, used to decide whether a
    -- privileged action needs fresh step-up (§8.2).
    authenticated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    webauthn_verified_at    TIMESTAMPTZ,
    issued_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at              TIMESTAMPTZ NOT NULL,
    last_seen_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at              TIMESTAMPTZ,
    revocation_reason       TEXT,
    ip                      INET,
    user_agent              TEXT,

    CONSTRAINT sessions_expiry_after_issue CHECK (expires_at > issued_at)
);

CREATE INDEX sessions_user_active_idx ON sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX sessions_expiry_idx      ON sessions (expires_at) WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- Recovery credentials (§8.3 — no SMS anywhere in this schema)
-- ---------------------------------------------------------------------------
CREATE TABLE recovery_codes (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id             UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash           TEXT        NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    consumed_at         TIMESTAMPTZ,
    consumed_ip         INET
);

CREATE INDEX recovery_codes_user_idx ON recovery_codes (user_id) WHERE consumed_at IS NULL;

COMMENT ON TABLE recovery_codes IS
    'Single-use recovery credentials. There is deliberately no phone_number column anywhere in this schema: §7.1 forbids SMS for authentication, OTP, MFA, approval or recovery.';

-- ---------------------------------------------------------------------------
-- Conflict-of-interest registry (§19)
-- ---------------------------------------------------------------------------
CREATE TABLE conflict_registrations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id             UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope_type          TEXT        NOT NULL CHECK (scope_type IN ('RECIPIENT', 'DEPARTMENT', 'ORGANIZATION')),
    scope_id            UUID,
    reason              TEXT        NOT NULL,
    declared_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    declared_by_user_id UUID        NOT NULL REFERENCES users(id),
    withdrawn_at        TIMESTAMPTZ,

    CONSTRAINT conflict_scope_id_present CHECK (
        (scope_type = 'ORGANIZATION' AND scope_id IS NULL) OR
        (scope_type <> 'ORGANIZATION' AND scope_id IS NOT NULL)
    )
);

CREATE INDEX conflict_user_idx ON conflict_registrations (organization_id, user_id) WHERE withdrawn_at IS NULL;

-- ---------------------------------------------------------------------------
-- updated_at maintenance
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER organizations_updated_at BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
