-- ============================================================================
-- SOLVAREN Payment Solutions — 0004 Backups, exports, scheduling and AI audit
-- Implements §13 (backup system), §6.4/§12 (export records) and §10 (scheduling).
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Backup configuration (§13.2) — S3-compatible, credentials by reference
-- ---------------------------------------------------------------------------
CREATE TABLE backup_configurations (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id         UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider_label          TEXT        NOT NULL DEFAULT 'Cloudflare R2',
    endpoint                TEXT,
    region                  TEXT,
    bucket                  TEXT        NOT NULL,
    path_prefix             TEXT        NOT NULL DEFAULT 'solvaren/backups',

    -- §13.7: "Backup credentials stored as secrets, never in plaintext application tables."
    access_key_secret_ref   TEXT        NOT NULL,
    secret_key_secret_ref   TEXT        NOT NULL,
    access_key_last_four    TEXT,

    encryption_mode         TEXT        NOT NULL DEFAULT 'SSE_S3'
                            CHECK (encryption_mode IN ('SSE_S3', 'SSE_KMS', 'APPLICATION')),
    status                  TEXT        NOT NULL DEFAULT 'DISABLED'
                            CHECK (status IN ('CONNECTED', 'ERROR', 'DISABLED')),
    last_test_at            TIMESTAMPTZ,
    last_test_ok            BOOLEAN,
    last_test_message       TEXT,

    schedule_enabled        BOOLEAN     NOT NULL DEFAULT FALSE,
    schedule_cron           TEXT,
    schedule_timezone       TEXT        NOT NULL DEFAULT 'Africa/Nairobi',
    -- Set by the scheduler on each firing so a *missed* run is visible as a gap rather
    -- than silently disappearing (§13.4).
    last_scheduled_run_at   TIMESTAMPTZ,
    next_scheduled_run_at   TIMESTAMPTZ,

    retention_max_count     INTEGER     NOT NULL DEFAULT 30,
    -- After this many consecutive credential failures the scheduler stops trying (§22).
    consecutive_failures    INTEGER     NOT NULL DEFAULT 0,
    suspended_at            TIMESTAMPTZ,
    suspension_reason       TEXT,

    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by_user_id      UUID REFERENCES users(id),

    CONSTRAINT backup_one_per_org UNIQUE (organization_id),
    CONSTRAINT backup_retention_sane CHECK (retention_max_count BETWEEN 1 AND 3650),
    -- §13.2: "Connection test required before enabling schedule."
    CONSTRAINT backup_schedule_requires_test CHECK (
        schedule_enabled = FALSE OR (last_test_ok IS TRUE AND schedule_cron IS NOT NULL))
);

COMMENT ON CONSTRAINT backup_schedule_requires_test ON backup_configurations IS
    'A schedule cannot be enabled against a target that has never successfully connected — otherwise the first anyone learns of a broken backup is when they need to restore.';

-- ---------------------------------------------------------------------------
-- Backup attempts (§13.6) — every attempt has a durable outcome (NFR-BAK-001)
-- ---------------------------------------------------------------------------
CREATE TABLE backup_attempts (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id         UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    attempt_reference       TEXT        NOT NULL,         -- e.g. BAK-2026-000184
    trigger_type            TEXT        NOT NULL CHECK (trigger_type IN ('MANUAL', 'SCHEDULED')),
    status                  TEXT        NOT NULL DEFAULT 'STARTED'
                            CHECK (status IN ('STARTED', 'SUCCESS', 'FAILED', 'PARTIAL', 'MISSED')),

    started_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at                TIMESTAMPTZ,

    target_description      TEXT        NOT NULL,          -- provider + bucket + prefix, secrets masked
    object_key              TEXT,
    size_bytes              BIGINT,
    checksum                TEXT,
    checksum_algorithm      TEXT,

    -- §13.7: sanitized error only. A raw provider error can contain a presigned URL.
    error_code              TEXT,
    error_message           TEXT,

    actor_user_id           UUID REFERENCES users(id),     -- NULL for scheduled runs
    retention_deleted_count INTEGER     NOT NULL DEFAULT 0,
    retention_retained_count INTEGER    NOT NULL DEFAULT 0,
    retention_complete      BOOLEAN     NOT NULL DEFAULT FALSE,
    job_id                  TEXT,
    correlation_id          TEXT        NOT NULL,

    CONSTRAINT backup_attempt_reference_unique UNIQUE (organization_id, attempt_reference),
    -- §13.7: "A failed backup must never be presented as successful."
    CONSTRAINT backup_success_requires_object CHECK (
        status <> 'SUCCESS' OR (object_key IS NOT NULL AND size_bytes IS NOT NULL AND size_bytes > 0)),
    CONSTRAINT backup_failure_requires_reason CHECK (
        status <> 'FAILED' OR (error_message IS NOT NULL AND btrim(error_message) <> '')),
    CONSTRAINT backup_terminal_has_end CHECK (
        status = 'STARTED' OR ended_at IS NOT NULL)
);

CREATE INDEX backup_attempts_org_idx     ON backup_attempts (organization_id, started_at DESC);
CREATE INDEX backup_attempts_success_idx ON backup_attempts (organization_id, started_at DESC)
    WHERE status = 'SUCCESS';
CREATE INDEX backup_attempts_running_idx ON backup_attempts (organization_id) WHERE status = 'STARTED';

-- A backup attempt, once terminal, is a record of what happened.
CREATE OR REPLACE FUNCTION guard_backup_attempt_update() RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status IN ('SUCCESS', 'FAILED', 'PARTIAL', 'MISSED')
       AND NEW.status <> OLD.status
       -- Retention bookkeeping is written after the fact against a SUCCESS row, so that
       -- one transition is permitted.
       AND NOT (OLD.status = 'SUCCESS' AND NEW.status = 'SUCCESS')
    THEN
        RAISE EXCEPTION
            'SOLVAREN immutability: backup attempt % is already recorded as % and cannot be re-reported as %.',
            OLD.attempt_reference, OLD.status, NEW.status
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER backup_attempts_guard_update BEFORE UPDATE ON backup_attempts
    FOR EACH ROW EXECUTE FUNCTION guard_backup_attempt_update();
CREATE TRIGGER backup_attempts_no_delete BEFORE DELETE ON backup_attempts
    FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

-- ---------------------------------------------------------------------------
-- Export records (§6.4, TRK-006 — every export is audited)
-- ---------------------------------------------------------------------------
CREATE TABLE export_records (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id         UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    export_reference        TEXT        NOT NULL,
    export_type             TEXT        NOT NULL CHECK (export_type IN (
                                'FAILED_TRANSACTIONS', 'ALL_TRANSACTIONS', 'BATCH_REPORT',
                                'RECONCILIATION', 'AUDIT', 'MANAGEMENT', 'EXECUTIVE')),
    requested_by_user_id    UUID        NOT NULL REFERENCES users(id),
    requested_by_level      TEXT        NOT NULL CHECK (requested_by_level IN ('L1', 'L2', 'L3')),
    -- The exact filter, so "who exported what" is answerable a year later.
    filter_description      TEXT        NOT NULL,
    filter_json             JSONB       NOT NULL DEFAULT '{}'::jsonb,
    row_count               INTEGER,
    byte_size               BIGINT,
    status                  TEXT        NOT NULL DEFAULT 'GENERATING'
                            CHECK (status IN ('GENERATING', 'COMPLETED', 'FAILED')),
    -- §22: "Export generation failure → durable failed export record; never a silent partial file."
    error_message           TEXT,
    requested_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at            TIMESTAMPTZ,
    correlation_id          TEXT        NOT NULL,

    CONSTRAINT export_reference_unique UNIQUE (organization_id, export_reference),
    CONSTRAINT export_completed_has_count CHECK (status <> 'COMPLETED' OR row_count IS NOT NULL),
    CONSTRAINT export_failed_has_reason CHECK (status <> 'FAILED' OR error_message IS NOT NULL)
);

CREATE INDEX export_records_org_idx  ON export_records (organization_id, requested_at DESC);
CREATE INDEX export_records_user_idx ON export_records (organization_id, requested_by_user_id, requested_at DESC);

CREATE TRIGGER export_records_no_delete BEFORE DELETE ON export_records
    FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

-- ---------------------------------------------------------------------------
-- Batch scheduling and recurring templates (§10)
-- ---------------------------------------------------------------------------
CREATE TABLE batch_templates (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id         UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                    TEXT        NOT NULL,
    purpose                 TEXT        NOT NULL,
    department_id           UUID REFERENCES departments(id) ON DELETE SET NULL,
    recipient_ids           UUID[]      NOT NULL DEFAULT '{}',
    default_amounts         JSONB       NOT NULL DEFAULT '{}'::jsonb,
    schedule_cron           TEXT,
    schedule_enabled        BOOLEAN     NOT NULL DEFAULT FALSE,
    cutoff_time             TIME,
    created_by_user_id      UUID        NOT NULL REFERENCES users(id),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_run_at             TIMESTAMPTZ,
    next_run_at             TIMESTAMPTZ,

    CONSTRAINT batch_template_name_unique UNIQUE (organization_id, name)
);

COMMENT ON TABLE batch_templates IS
    'A template creates a DRAFT batch on schedule. It deliberately cannot create anything further along the lifecycle: a recurring payroll still passes through L1 validation, L2 approval and L3 authorization every cycle.';

-- Holiday calendar and cut-off control (§10).
CREATE TABLE payment_calendar (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    calendar_date       DATE        NOT NULL,
    kind                TEXT        NOT NULL CHECK (kind IN ('HOLIDAY', 'BLACKOUT', 'CUTOFF_OVERRIDE')),
    description         TEXT        NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT calendar_unique UNIQUE (organization_id, calendar_date, kind)
);

-- ---------------------------------------------------------------------------
-- AI interaction log (§11 — advisory boundary, provably)
-- ---------------------------------------------------------------------------
CREATE TABLE ai_interactions (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id         UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id                 UUID        NOT NULL REFERENCES users(id),
    capability              TEXT        NOT NULL CHECK (capability IN (
                                'BATCH_ANALYSIS', 'FAILURE_EXPLANATION', 'EXPENDITURE_ANALYSIS',
                                'PAYROLL_COMPARISON', 'MANAGEMENT_SUMMARY', 'EXECUTIVE_BRIEFING',
                                'NATURAL_LANGUAGE_QUERY')),
    -- What the user asked, and a digest of the context actually sent to the model, so a
    -- data-residency review can establish exactly what left the environment.
    prompt_summary          TEXT        NOT NULL,
    context_digest          TEXT        NOT NULL,
    context_row_count       INTEGER     NOT NULL DEFAULT 0,
    model                   TEXT        NOT NULL,
    response_summary        TEXT,
    -- Always FALSE. The column exists so that the invariant is queryable evidence rather
    -- than an assurance: §11 "The AI layer must not directly issue a payment release command."
    caused_state_change     BOOLEAN     NOT NULL DEFAULT FALSE,
    latency_ms              INTEGER,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT ai_never_mutates_state CHECK (caused_state_change = FALSE)
);

CREATE INDEX ai_interactions_org_idx ON ai_interactions (organization_id, created_at DESC);

COMMENT ON CONSTRAINT ai_never_mutates_state ON ai_interactions IS
    'Spec §11 AI CONTROL, expressed as a database constraint: no AI interaction may ever be recorded as having changed platform state. If a future code path tried, the insert would fail.';

-- ---------------------------------------------------------------------------
-- Rate limiting / security events
-- ---------------------------------------------------------------------------
CREATE TABLE security_events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID REFERENCES organizations(id) ON DELETE CASCADE,
    user_id             UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type          TEXT        NOT NULL,
    severity            TEXT        NOT NULL CHECK (severity IN ('INFO', 'WARNING', 'CRITICAL')),
    description         TEXT        NOT NULL,
    ip                  INET,
    user_agent          TEXT,
    detail              JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    acknowledged_at     TIMESTAMPTZ,
    acknowledged_by     UUID REFERENCES users(id)
);

CREATE INDEX security_events_org_idx ON security_events (organization_id, created_at DESC);
CREATE INDEX security_events_open_idx ON security_events (organization_id, severity, created_at DESC)
    WHERE acknowledged_at IS NULL;

CREATE TRIGGER backup_configurations_updated_at BEFORE UPDATE ON backup_configurations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER batch_templates_updated_at BEFORE UPDATE ON batch_templates
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
