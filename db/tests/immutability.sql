-- ============================================================================
-- SOLVAREN database security assertions.
--
-- Each block performs an attack from spec §23 against the schema directly — no application
-- code in the way — and fails loudly if the database permits it. Run by `pnpm db:test`
-- and by CI against a disposable PostgreSQL instance.
-- ============================================================================

\set ON_ERROR_STOP on
\timing off

/*
 * Assert that a statement is refused.
 *
 * The row-count check matters more than it looks: an UPDATE or DELETE whose WHERE clause
 * matches nothing "succeeds" without ever firing a row trigger, so it would silently pass
 * an immutability assertion while proving nothing at all. Such a test is reported as
 * INCONCLUSIVE and fails the run, because a security assertion that cannot fail is worse
 * than no assertion.
 */
CREATE OR REPLACE FUNCTION assert_refused(stmt TEXT, expectation TEXT) RETURNS VOID AS $$
DECLARE affected BIGINT;
BEGIN
    BEGIN
        EXECUTE stmt;
        GET DIAGNOSTICS affected = ROW_COUNT;
    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE 'PASS  %  (refused: %)', expectation, left(SQLERRM, 90);
        RETURN;
    END;

    IF affected = 0 AND stmt ~* '^\s*(UPDATE|DELETE)' THEN
        RAISE EXCEPTION
            'INCONCLUSIVE  % — the statement matched no rows, so no trigger fired. Fix the fixture.',
            expectation;
    END IF;
    RAISE EXCEPTION 'FAIL  % — the database ALLOWED this statement (% row(s) affected)', expectation, affected;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION assert_allowed(stmt TEXT, expectation TEXT) RETURNS VOID AS $$
DECLARE affected BIGINT;
BEGIN
    EXECUTE stmt;
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected = 0 AND stmt ~* '^\s*(UPDATE|DELETE)' THEN
        RAISE EXCEPTION 'INCONCLUSIVE  % — the statement matched no rows. Fix the fixture.', expectation;
    END IF;
    RAISE NOTICE 'PASS  %', expectation;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- Fixture
-- ---------------------------------------------------------------------------
BEGIN;

INSERT INTO organizations (id, name, slug)
VALUES ('00000000-0000-0000-0000-0000000000a1', 'Acme Holdings', 'acme');

INSERT INTO policies (organization_id) VALUES ('00000000-0000-0000-0000-0000000000a1');

INSERT INTO users (id, organization_id, email, full_name, authority_level, password_hash, authorization_pin_hash)
VALUES
 ('00000000-0000-0000-0000-0000000000b1', '00000000-0000-0000-0000-0000000000a1', 'ops@acme.test',     'Ops Officer',     'L1', '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$hash', NULL),
 ('00000000-0000-0000-0000-0000000000b2', '00000000-0000-0000-0000-0000000000a1', 'finance@acme.test', 'Finance Officer', 'L2', '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$hash', '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$pin'),
 ('00000000-0000-0000-0000-0000000000b3', '00000000-0000-0000-0000-0000000000a1', 'ceo@acme.test',     'Chief Executive', 'L3', '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$hash', '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$pin');

INSERT INTO departments (id, organization_id, name)
VALUES ('00000000-0000-0000-0000-0000000000c1', '00000000-0000-0000-0000-0000000000a1', 'Engineering');

INSERT INTO recipients (id, organization_id, full_name, msisdn, department_id)
VALUES ('00000000-0000-0000-0000-0000000000d1', '00000000-0000-0000-0000-0000000000a1', 'Jane Doe', '254712345678', '00000000-0000-0000-0000-0000000000c1');

INSERT INTO payment_batches (id, organization_id, batch_reference, purpose, created_by_user_id, state)
VALUES ('00000000-0000-0000-0000-0000000000e1', '00000000-0000-0000-0000-0000000000a1', 'SLV-2026-00981', 'September payroll', '00000000-0000-0000-0000-0000000000b1', 'DRAFT');

INSERT INTO payment_instructions (id, organization_id, batch_id, recipient_id, recipient_name_snapshot, msisdn_snapshot, amount_cents)
VALUES ('00000000-0000-0000-0000-0000000000f1', '00000000-0000-0000-0000-0000000000a1', '00000000-0000-0000-0000-0000000000e1', '00000000-0000-0000-0000-0000000000d1', 'Jane Doe', '254712345678', 4500000);

COMMIT;

-- ---------------------------------------------------------------------------
-- §5.1 / §15 — batch totals are maintained by the database, not trusted from the caller
-- ---------------------------------------------------------------------------
DO $$
DECLARE total BIGINT; cnt INTEGER;
BEGIN
    SELECT total_amount_cents, instruction_count INTO total, cnt
      FROM payment_batches WHERE id = '00000000-0000-0000-0000-0000000000e1';
    IF total <> 4500000 OR cnt <> 1 THEN
        RAISE EXCEPTION 'FAIL  batch roll-up drifted: total=% count=%', total, cnt;
    END IF;
    RAISE NOTICE 'PASS  batch roll-ups are maintained by trigger from the instruction rows';
END $$;

-- ---------------------------------------------------------------------------
-- Amount and MSISDN constraints (M-PESA B2C limits)
-- ---------------------------------------------------------------------------
SELECT assert_refused($$
    INSERT INTO payment_instructions (organization_id, batch_id, recipient_id, recipient_name_snapshot, msisdn_snapshot, amount_cents)
    VALUES ('00000000-0000-0000-0000-0000000000a1','00000000-0000-0000-0000-0000000000e1','00000000-0000-0000-0000-0000000000d1','Jane Doe','254712345678', 4500050)
$$, 'a fractional-shilling instruction is refused');

SELECT assert_refused($$
    INSERT INTO payment_instructions (organization_id, batch_id, recipient_id, recipient_name_snapshot, msisdn_snapshot, amount_cents)
    VALUES ('00000000-0000-0000-0000-0000000000a1','00000000-0000-0000-0000-0000000000e1','00000000-0000-0000-0000-0000000000d1','Jane Doe','254712345678', 30000000)
$$, 'an instruction above the KES 250,000 M-PESA ceiling is refused');

SELECT assert_refused($$
    INSERT INTO recipients (organization_id, full_name, msisdn)
    VALUES ('00000000-0000-0000-0000-0000000000a1', 'Bad Number', '+254712345678')
$$, 'a non-canonical MSISDN is refused on the recipient master record');

SELECT assert_refused($$
    INSERT INTO recipients (organization_id, full_name, msisdn)
    VALUES ('00000000-0000-0000-0000-0000000000a1', 'Duplicate', '254712345678')
$$, 'a second recipient with the same number in one organisation is refused');

-- ---------------------------------------------------------------------------
-- §19 — separation of duties enforced at the storage layer
-- ---------------------------------------------------------------------------
SELECT assert_refused($$
    UPDATE payment_batches SET approved_by_user_id = created_by_user_id
     WHERE id = '00000000-0000-0000-0000-0000000000e1'
$$, 'the creator of a batch cannot be recorded as its approver');

SELECT assert_refused($$
    UPDATE payment_batches SET authorized_by_user_id = created_by_user_id
     WHERE id = '00000000-0000-0000-0000-0000000000e1'
$$, 'the creator of a batch cannot be recorded as its authorizer');

SELECT assert_allowed($$
    UPDATE payment_batches
       SET approved_by_user_id = '00000000-0000-0000-0000-0000000000b2',
           authorized_by_user_id = '00000000-0000-0000-0000-0000000000b3'
     WHERE id = '00000000-0000-0000-0000-0000000000e1'
$$, 'an independent approver and authorizer are accepted');

SELECT assert_refused($$
    UPDATE payment_batches SET authorized_by_user_id = approved_by_user_id
     WHERE id = '00000000-0000-0000-0000-0000000000e1'
$$, 'the L2 approver cannot also be recorded as the L3 authorizer');

-- ---------------------------------------------------------------------------
-- §23 — "Attempt to forge a SUCCESS status through a database mutation path"
-- ---------------------------------------------------------------------------
SELECT assert_refused($$
    INSERT INTO transactions (organization_id, instruction_id, batch_id, status,
                              originator_conversation_id, request_fingerprint, amount_cents)
    VALUES ('00000000-0000-0000-0000-0000000000a1','00000000-0000-0000-0000-0000000000f1','00000000-0000-0000-0000-0000000000e1',
            'SUCCESS', '600992-FORGED-1', 'fp-forged', 4500000)
$$, 'a SUCCESS transaction cannot be inserted without an M-PESA receipt');

SELECT assert_refused($$
    INSERT INTO transactions (organization_id, instruction_id, batch_id, status,
                              originator_conversation_id, request_fingerprint, amount_cents, failure_code)
    VALUES ('00000000-0000-0000-0000-0000000000a1','00000000-0000-0000-0000-0000000000f1','00000000-0000-0000-0000-0000000000e1',
            'FAILED', '600992-BLANK-1', 'fp-blank', 4500000, '1')
$$, 'a FAILED transaction cannot be inserted without a human-readable reason (TRK-002)');

SELECT assert_allowed($$
    INSERT INTO transactions (id, organization_id, instruction_id, batch_id, status,
                              originator_conversation_id, request_fingerprint, amount_cents)
    VALUES ('00000000-0000-0000-0000-00000000ff01','00000000-0000-0000-0000-0000000000a1','00000000-0000-0000-0000-0000000000f1','00000000-0000-0000-0000-0000000000e1',
            'SUBMITTED', '600992-INS1-REAL', 'fp-real', 4500000)
$$, 'a legitimate SUBMITTED transaction is accepted');

SELECT assert_refused($$
    INSERT INTO transactions (organization_id, instruction_id, batch_id, status,
                              originator_conversation_id, request_fingerprint, amount_cents)
    VALUES ('00000000-0000-0000-0000-0000000000a1','00000000-0000-0000-0000-0000000000f1','00000000-0000-0000-0000-0000000000e1',
            'SUBMITTED', '600992-INS1-REAL', 'fp-dup', 4500000)
$$, 'a duplicate OriginatorConversationID is refused (double-disbursement guard)');

-- Settle it legitimately, then try to rewrite history.
SELECT assert_allowed($$
    UPDATE transactions
       SET status = 'SUCCESS', mpesa_receipt_number = 'SG632NMUAB', status_source = 'CALLBACK', completed_at = now()
     WHERE id = '00000000-0000-0000-0000-00000000ff01'
$$, 'a transaction settles to SUCCESS when a provider receipt is present');

SELECT assert_refused($$
    UPDATE transactions SET status = 'FAILED', failure_code = '1', failure_reason = 'x'
     WHERE id = '00000000-0000-0000-0000-00000000ff01'
$$, 'a settled transaction cannot be re-settled to a different outcome');

SELECT assert_refused($$
    UPDATE transactions SET amount_cents = 1 WHERE id = '00000000-0000-0000-0000-00000000ff01'
$$, 'the amount of an existing transaction cannot be altered');

SELECT assert_refused($$
    UPDATE transactions SET mpesa_receipt_number = 'FAKE123' WHERE id = '00000000-0000-0000-0000-00000000ff01'
$$, 'an M-PESA receipt cannot be overwritten once recorded');

SELECT assert_refused($$
    DELETE FROM transactions WHERE id = '00000000-0000-0000-0000-00000000ff01'
$$, 'a transaction cannot be deleted — even by the table owner');

-- ---------------------------------------------------------------------------
-- §4.3 — instructions freeze once the batch leaves the editable states
-- ---------------------------------------------------------------------------
SELECT assert_allowed($$
    UPDATE payment_batches SET state = 'SUBMITTED_TO_L2' WHERE id = '00000000-0000-0000-0000-0000000000e1'
$$, 'a batch advances to SUBMITTED_TO_L2');

SELECT assert_refused($$
    UPDATE payment_instructions SET amount_cents = 100000 WHERE id = '00000000-0000-0000-0000-0000000000f1'
$$, 'an instruction amount cannot change once the batch has been submitted');

SELECT assert_refused($$
    DELETE FROM payment_instructions WHERE id = '00000000-0000-0000-0000-0000000000f1'
$$, 'an instruction cannot be deleted once the batch has been submitted');

SELECT assert_refused($$
    UPDATE payment_batches SET version = 0 WHERE id = '00000000-0000-0000-0000-0000000000e1'
$$, 'a batch version cannot be decreased');

-- ---------------------------------------------------------------------------
-- §14 — the audit log is append-only and hash-chained
-- ---------------------------------------------------------------------------
DO $$
DECLARE genesis CHAR(64) := repeat('0', 64);
BEGIN
    INSERT INTO audit_events (organization_id, sequence, event_reference, actor_id, actor_level,
                              event_class, action, object_type, object_id, outcome, occurred_at,
                              correlation_id, previous_hash, event_hash)
    VALUES ('00000000-0000-0000-0000-0000000000a1', 1, 'EVT-1', '00000000-0000-0000-0000-0000000000b3', 'L3',
            'PAYMENT', 'payment.release', 'PaymentBatch', '00000000-0000-0000-0000-0000000000e1', 'SUCCESS', now(),
            'cor-1', genesis, repeat('a', 64));
    RAISE NOTICE 'PASS  the first audit event anchors to the genesis hash';
END $$;

SELECT assert_refused($$
    INSERT INTO audit_events (organization_id, sequence, event_reference, actor_id, event_class, action,
                              object_type, outcome, occurred_at, correlation_id, previous_hash, event_hash)
    VALUES ('00000000-0000-0000-0000-0000000000a1', 2, 'EVT-BAD', 'system', 'PAYMENT', 'payment.release',
            'PaymentBatch', 'SUCCESS', now(), 'cor-2', repeat('9', 64), repeat('b', 64))
$$, 'an audit event whose previous_hash does not match the chain tail is refused');

DO $$
BEGIN
    INSERT INTO audit_events (organization_id, sequence, event_reference, actor_id, event_class, action,
                              object_type, outcome, occurred_at, correlation_id, previous_hash, event_hash)
    VALUES ('00000000-0000-0000-0000-0000000000a1', 999, 'EVT-2', 'system', 'PAYMENT', 'payment.settle',
            'Transaction', 'SUCCESS', now(), 'cor-3', repeat('a', 64), repeat('b', 64));
    IF (SELECT sequence FROM audit_events WHERE event_reference = 'EVT-2') <> 2 THEN
        RAISE EXCEPTION 'FAIL  the audit sequence was taken from the caller instead of the chain';
    END IF;
    RAISE NOTICE 'PASS  the audit sequence is assigned by the database, not trusted from the caller';
END $$;

SELECT assert_refused($$
    UPDATE audit_events SET action = 'payment.nothing_happened' WHERE event_reference = 'EVT-1'
$$, 'an audit event cannot be modified (§4.3: not even by L3)');

SELECT assert_refused($$
    DELETE FROM audit_events WHERE event_reference = 'EVT-1'
$$, 'an audit event cannot be deleted');

-- ---------------------------------------------------------------------------
-- §7.5 — one open authorization ceremony per batch; challenges are single-use
-- ---------------------------------------------------------------------------
DO $$
DECLARE approval_id UUID;
BEGIN
    INSERT INTO approvals (id, organization_id, approval_reference, batch_id, batch_version,
                           actor_user_id, actor_level, action)
    VALUES (gen_random_uuid(), '00000000-0000-0000-0000-0000000000a1', 'APR-8821',
            '00000000-0000-0000-0000-0000000000e1', 1, '00000000-0000-0000-0000-0000000000b2', 'L2', 'APPROVE')
    RETURNING id INTO approval_id;

    INSERT INTO authorization_challenges (id, organization_id, batch_id, approval_id, authorizer_user_id,
                                          manifest_hash, challenge_hash, manifest_canonical_form, nonce,
                                          batch_version, recipient_count, total_amount_cents,
                                          webauthn_challenge, expires_at)
    VALUES ('00000000-0000-0000-0000-00000000aa01', '00000000-0000-0000-0000-0000000000a1',
            '00000000-0000-0000-0000-0000000000e1', approval_id, '00000000-0000-0000-0000-0000000000b3',
            repeat('A', 64), repeat('C', 64), 'canonical', 'nonce-1', 1, 1, 4500000, 'wa-challenge', now() + interval '5 minutes');
    RAISE NOTICE 'PASS  an authorization ceremony opens';
END $$;

-- Now that an approval row exists, prove decisions are immutable.
SELECT assert_refused($$
    UPDATE approvals SET reason = 'changed my mind' WHERE approval_reference = 'APR-8821'
$$, 'an approval decision cannot be edited after the fact');

SELECT assert_refused($$
    DELETE FROM approvals WHERE approval_reference = 'APR-8821'
$$, 'an approval decision cannot be deleted');

SELECT assert_refused($$
    INSERT INTO authorization_challenges (organization_id, batch_id, approval_id, authorizer_user_id,
                                          manifest_hash, challenge_hash, manifest_canonical_form, nonce,
                                          batch_version, recipient_count, total_amount_cents,
                                          webauthn_challenge, expires_at)
    SELECT '00000000-0000-0000-0000-0000000000a1', '00000000-0000-0000-0000-0000000000e1', approval_id,
           '00000000-0000-0000-0000-0000000000b3', repeat('B', 64), repeat('D', 64), 'canonical2', 'nonce-2',
           1, 1, 4500000, 'wa-2', now() + interval '5 minutes'
      FROM authorization_challenges WHERE id = '00000000-0000-0000-0000-00000000aa01'
$$, 'a second concurrent authorization ceremony for the same batch is refused');

SELECT assert_allowed($$
    UPDATE authorization_challenges SET consumed_at = now() WHERE id = '00000000-0000-0000-0000-00000000aa01'
$$, 'a challenge is consumed exactly once');

SELECT assert_refused($$
    UPDATE authorization_challenges SET consumed_at = NULL WHERE id = '00000000-0000-0000-0000-00000000aa01'
$$, 'a consumed challenge cannot be un-consumed (replay protection)');

SELECT assert_refused($$
    UPDATE authorization_challenges SET manifest_hash = repeat('F', 64) WHERE id = '00000000-0000-0000-0000-00000000aa01'
$$, 'the cryptographic binding of a challenge cannot be altered');

-- ---------------------------------------------------------------------------
-- §9.1 / §13.2 — integrations cannot be enabled without a passing connection test
-- ---------------------------------------------------------------------------
SELECT assert_refused($$
    INSERT INTO daraja_configurations (organization_id, environment, short_code, initiator_name,
        consumer_key_secret_ref, consumer_secret_secret_ref, security_credential_ref,
        result_url, queue_timeout_url, callback_secret_ref, status)
    VALUES ('00000000-0000-0000-0000-0000000000a1', 'production', '600992', 'testapi',
            'ref:ck', 'ref:cs', 'ref:sc', 'https://api.solvaren.test/cb', 'https://api.solvaren.test/to', 'ref:cb', 'ENABLED')
$$, 'a Daraja integration cannot be ENABLED without a passing connection test');

SELECT assert_refused($$
    INSERT INTO daraja_configurations (organization_id, environment, short_code, initiator_name,
        consumer_key_secret_ref, consumer_secret_secret_ref, security_credential_ref,
        result_url, queue_timeout_url, callback_secret_ref)
    VALUES ('00000000-0000-0000-0000-0000000000a1', 'sandbox', '600992', 'testapi',
            'ref:ck', 'ref:cs', 'ref:sc', 'http://insecure.test/cb', 'https://api.solvaren.test/to', 'ref:cb')
$$, 'a plaintext-HTTP callback URL is refused');

SELECT assert_refused($$
    INSERT INTO backup_configurations (organization_id, bucket, access_key_secret_ref, secret_key_secret_ref,
                                       schedule_enabled, schedule_cron)
    VALUES ('00000000-0000-0000-0000-0000000000a1', 'acme-backups', 'ref:ak', 'ref:sk', TRUE, '0 2 * * *')
$$, 'a backup schedule cannot be enabled against an untested target');

SELECT assert_refused($$
    INSERT INTO backup_attempts (organization_id, attempt_reference, trigger_type, status,
                                 target_description, correlation_id, ended_at)
    VALUES ('00000000-0000-0000-0000-0000000000a1', 'BAK-2026-000001', 'MANUAL', 'SUCCESS',
            'R2 acme-backups', 'cor-b1', now())
$$, 'a backup cannot be recorded as SUCCESS without an object key and size');

SELECT assert_refused($$
    INSERT INTO backup_attempts (organization_id, attempt_reference, trigger_type, status,
                                 target_description, correlation_id, ended_at)
    VALUES ('00000000-0000-0000-0000-0000000000a1', 'BAK-2026-000002', 'MANUAL', 'FAILED',
            'R2 acme-backups', 'cor-b2', now())
$$, 'a failed backup must carry an error message');

-- ---------------------------------------------------------------------------
-- §11 — the AI layer can never be recorded as having changed state
-- ---------------------------------------------------------------------------
SELECT assert_refused($$
    INSERT INTO ai_interactions (organization_id, user_id, capability, prompt_summary, context_digest, model, caused_state_change)
    VALUES ('00000000-0000-0000-0000-0000000000a1', '00000000-0000-0000-0000-0000000000b3', 'BATCH_ANALYSIS',
            'analyse batch', 'digest', 'test-model', TRUE)
$$, 'an AI interaction claiming to have changed state is refused (§11 AI CONTROL)');

-- ---------------------------------------------------------------------------
-- TRK-002 — a failure explanation may never be blank or the bare word "Error"
-- ---------------------------------------------------------------------------
SELECT assert_refused($$
    INSERT INTO failure_reason_map (organization_id, provider_code, reason, failure_class, operator_action, dictionary_version)
    VALUES ('00000000-0000-0000-0000-0000000000a1', 'X1', 'Error', 'UNKNOWN', 'do something', 'test')
$$, 'a failure mapping of just "Error" is refused');

SELECT assert_refused($$
    INSERT INTO failure_reason_map (organization_id, provider_code, reason, failure_class, operator_action, dictionary_version)
    VALUES ('00000000-0000-0000-0000-0000000000a1', 'X2', '   ', 'UNKNOWN', 'do something', 'test')
$$, 'a blank failure mapping is refused');

-- ---------------------------------------------------------------------------
-- §4.4 — policy limits cannot exceed what M-PESA will actually accept
-- ---------------------------------------------------------------------------
SELECT assert_refused($$
    UPDATE policies SET max_instruction_amount_cents = 99999999 WHERE organization_id = '00000000-0000-0000-0000-0000000000a1'
$$, 'an organisation cannot set a per-payment limit above the M-PESA maximum');

-- ---------------------------------------------------------------------------
-- §7.1 — no SMS anywhere: there is no phone/OTP column on any identity table
-- ---------------------------------------------------------------------------
DO $$
DECLARE offending TEXT;
BEGIN
    SELECT string_agg(table_name || '.' || column_name, ', ') INTO offending
      FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name IN ('users', 'sessions', 'recovery_codes', 'trusted_devices', 'webauthn_credentials')
       AND (column_name ~* '(sms|otp|phone|mobile|msisdn)');
    IF offending IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL  identity tables contain SMS/OTP columns: %', offending;
    END IF;
    RAISE NOTICE 'PASS  no SMS, OTP or phone column exists on any identity table (§7.1, AC-06)';
END $$;

-- ---------------------------------------------------------------------------
-- Job queue (§16, migration 0008)
--
-- The queue now carries payment intent, so it gets the same treatment as the ledger: a
-- terminal job cannot be reopened, and a queued payload cannot be rewritten.
-- ---------------------------------------------------------------------------

SELECT assert_allowed($$
    INSERT INTO job_queue (id, queue, body, organization_id, correlation_id, max_attempts)
    VALUES ('00000000-0000-0000-0000-00000000bc01'::uuid, 'payments',
            '{"instructionId":"ins-queue-1","organizationId":"o","correlationId":"c"}'::jsonb,
            '00000000-0000-0000-0000-0000000000a1', 'cor-queue-1', 3)
$$, 'a legitimate job is accepted');

SELECT assert_refused($$
    INSERT INTO job_queue (queue, body, organization_id, correlation_id, max_attempts, status, dead_lettered_at)
    VALUES ('payments', '{"instructionId":"ins-queue-2"}'::jsonb,
            '00000000-0000-0000-0000-0000000000a1', 'cor-queue-2', 3, 'DEAD_LETTERED', now())
$$, 'a dead-lettered job must record why it was abandoned');

SELECT assert_refused($$
    INSERT INTO job_queue (queue, body, organization_id, correlation_id, max_attempts, status)
    VALUES ('payments', '{"instructionId":"ins-queue-3"}'::jsonb,
            '00000000-0000-0000-0000-0000000000a1', 'cor-queue-3', 3, 'IN_FLIGHT')
$$, 'an in-flight job must carry the lease that makes a dead worker recoverable');

SELECT assert_refused($$
    INSERT INTO job_queue (queue, body, organization_id, correlation_id, max_attempts)
    VALUES ('not-a-real-queue', '{}'::jsonb,
            '00000000-0000-0000-0000-0000000000a1', 'cor-queue-4', 3)
$$, 'a job cannot be routed to a queue no consumer reads');

-- Two live jobs for one payment instruction would be two submissions of one payment.
SELECT assert_refused($$
    INSERT INTO job_queue (queue, body, organization_id, correlation_id, max_attempts)
    VALUES ('payments', '{"instructionId":"ins-queue-1","organizationId":"o","correlationId":"c"}'::jsonb,
            '00000000-0000-0000-0000-0000000000a1', 'cor-queue-5', 3)
$$, 'a payment instruction cannot have two live jobs at once');

-- The payload is what the executor re-verifies its fingerprint against. Rewriting it in
-- place is the tamper path the fingerprint check exists to catch; the database refuses it
-- outright.
SELECT assert_refused($$
    UPDATE job_queue SET body = '{"instructionId":"ins-swapped"}'::jsonb
     WHERE id = '00000000-0000-0000-0000-00000000bc01'::uuid
$$, 'the payload of a queued job cannot be rewritten');

SELECT assert_refused($$
    UPDATE job_queue SET queue = 'backups'
     WHERE id = '00000000-0000-0000-0000-00000000bc01'::uuid
$$, 'a queued job cannot be moved to another queue');

-- A terminal job coming back to life would re-submit a payment that already settled.
DO $$
BEGIN
    UPDATE job_queue SET status = 'SUCCEEDED', completed_at = now()
     WHERE id = '00000000-0000-0000-0000-00000000bc01'::uuid;
END $$;

SELECT assert_refused($$
    UPDATE job_queue SET status = 'PENDING'
     WHERE id = '00000000-0000-0000-0000-00000000bc01'::uuid
$$, 'a settled job cannot be reopened and paid again');

-- ---------------------------------------------------------------------------
-- Enrolment tokens: single use, and a spent one is evidence
--
-- These tokens are the only way to put the first authenticator on an L2/L3 account, and
-- that account is the only thing that can release a payment. A token that could be replayed,
-- or quietly re-pointed at a different credential after the fact, would be a way to attach
-- an attacker's key to an executive account and leave no usable trace.
-- ---------------------------------------------------------------------------
DO $$
DECLARE org_id uuid; user_id uuid;
BEGIN
    INSERT INTO organizations (name, slug) VALUES ('Enrolment Test', 'enrolment-test')
    RETURNING id INTO org_id;

    INSERT INTO users (organization_id, email, full_name, authority_level, password_hash, status)
    VALUES (org_id, 'enrol@test.invalid', 'Enrolment Test', 'L1', 'x', 'PENDING_ENROLMENT')
    RETURNING id INTO user_id;

    INSERT INTO enrolment_tokens (id, organization_id, user_id, token_hash, expires_at)
    VALUES ('00000000-0000-0000-0000-0000000e1001'::uuid, org_id, user_id,
            'hash-one', now() + interval '30 minutes');

    -- Spend it, as the API does.
    UPDATE enrolment_tokens
       SET consumed_at = now(), credential_id = 'credential-one'
     WHERE id = '00000000-0000-0000-0000-0000000e1001'::uuid;

    RAISE NOTICE 'PASS  an enrolment token can be issued and consumed once';
END $$;

SELECT assert_refused($$
    UPDATE enrolment_tokens SET consumed_at = NULL, credential_id = NULL
     WHERE id = '00000000-0000-0000-0000-0000000e1001'::uuid
$$, 'a consumed enrolment token cannot be marked unused again');

SELECT assert_refused($$
    UPDATE enrolment_tokens SET credential_id = 'some-other-credential'
     WHERE id = '00000000-0000-0000-0000-0000000e1001'::uuid
$$, 'a consumed enrolment token cannot be re-pointed at another credential');

-- Two live tokens for one user would mean a token seen over a shoulder and a token issued
-- later both work.
DO $$
DECLARE org_id uuid; user_id uuid;
BEGIN
    SELECT u.id, u.organization_id INTO user_id, org_id
      FROM users u WHERE u.email = 'enrol@test.invalid';

    INSERT INTO enrolment_tokens (organization_id, user_id, token_hash, expires_at)
    VALUES (org_id, user_id, 'hash-live-a', now() + interval '30 minutes');

    BEGIN
        INSERT INTO enrolment_tokens (organization_id, user_id, token_hash, expires_at)
        VALUES (org_id, user_id, 'hash-live-b', now() + interval '30 minutes');
        RAISE EXCEPTION 'FAIL  a user was allowed two live enrolment tokens';
    EXCEPTION WHEN unique_violation THEN
        RAISE NOTICE 'PASS  only one enrolment token may be outstanding per user';
    END;
END $$;

-- A consumed token must say which credential it produced, so the question "did this token
-- create that key?" is answerable from the row itself.
SELECT assert_refused($$
    INSERT INTO enrolment_tokens (organization_id, user_id, token_hash, expires_at, consumed_at)
    SELECT u.organization_id, u.id, 'hash-no-credential', now() + interval '30 minutes', now()
      FROM users u WHERE u.email = 'enrol@test.invalid'
$$, 'a consumed enrolment token must record the credential it produced');

-- ---------------------------------------------------------------------------
-- Tenant scoping: every tenant-owned table carries organization_id NOT NULL
-- ---------------------------------------------------------------------------
DO $$
DECLARE missing TEXT;
BEGIN
    SELECT string_agg(t.table_name, ', ') INTO missing
      FROM information_schema.tables t
     WHERE t.table_schema = 'public' AND t.table_type = 'BASE TABLE'
       -- The exclusions are global-scope tables, each for a stated reason:
       --   organizations       is the tenant itself
       --   batch_editors       is scoped transitively through its batch
       --   failure_reason_map  is a shared dictionary with per-org overrides elsewhere
       --   security_events     records events that may precede knowing the tenant
       --   scheduled_job_runs  is one row per cluster-wide daily job, not per tenant
       AND t.table_name NOT IN (
           'organizations', 'batch_editors', 'failure_reason_map', 'security_events',
           'scheduled_job_runs'
       )
       AND NOT EXISTS (
           SELECT 1 FROM information_schema.columns c
            WHERE c.table_schema = 'public' AND c.table_name = t.table_name
              AND c.column_name = 'organization_id' AND c.is_nullable = 'NO');
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL  tables missing a NOT NULL organization_id: %', missing;
    END IF;
    RAISE NOTICE 'PASS  every tenant-owned table is scoped by a NOT NULL organization_id';
END $$;

\echo ''
\echo '================================================================'
\echo ' All SOLVAREN database security assertions passed.'
\echo '================================================================'
