-- ============================================================================
-- SOLVAREN Payment Solutions — 0006 Query views
--
-- The Transactions Explorer (§6.3) joins five tables on every page. Encapsulating that
-- join in a view means the export path and the screen path read the *same* definition —
-- which is what makes "exports are generated from authoritative stored records"
-- (NFR-DATA-002) true by construction rather than by discipline.
-- ============================================================================

CREATE OR REPLACE VIEW transaction_explorer AS
SELECT
    t.id                            AS transaction_id,
    t.organization_id,
    t.status,
    t.failure_code,
    t.failure_reason,
    t.failure_class,
    t.provider_result_description,
    t.mpesa_receipt_number,
    t.conversation_id,
    t.originator_conversation_id,
    t.status_source,
    t.last_status_check_at,
    t.created_at,
    t.submitted_at,
    t.completed_at,
    t.updated_at,

    pi.id                           AS instruction_id,
    pi.amount_cents,
    pi.recipient_name_snapshot      AS recipient_name,
    pi.msisdn_snapshot              AS msisdn,
    pi.remarks,

    r.id                            AS recipient_id,
    b.id                            AS batch_id,
    b.batch_reference,
    b.purpose                       AS batch_purpose,
    b.payment_period,
    d.id                            AS department_id,
    d.name                          AS department_name
FROM transactions t
JOIN payment_instructions pi ON pi.id = t.instruction_id
JOIN payment_batches b       ON b.id = t.batch_id
JOIN recipients r            ON r.id = pi.recipient_id
LEFT JOIN departments d      ON d.id = pi.department_id;

COMMENT ON VIEW transaction_explorer IS
    'Single definition backing both the explorer screen and the CSV export, so the file a finance officer downloads is the same data they were looking at.';

-- Batch outcome roll-up for the §6.1 batch header ("182 SUCCESS / 3 FAILED / 1 TIMEOUT").
CREATE OR REPLACE VIEW batch_outcome_rollup AS
SELECT
    b.id                AS batch_id,
    b.organization_id,
    b.batch_reference,
    b.state,
    b.instruction_count,
    b.total_amount_cents,
    COUNT(t.id) FILTER (WHERE t.status = 'SUCCESS')           AS success_count,
    COUNT(t.id) FILTER (WHERE t.status = 'FAILED')            AS failed_count,
    COUNT(t.id) FILTER (WHERE t.status = 'TIMEOUT')           AS timeout_count,
    COUNT(t.id) FILTER (WHERE t.status IN ('PENDING', 'SUBMITTED', 'AWAITING_CALLBACK',
                                           'PROCESSING', 'RECONCILING'))  AS in_flight_count,
    COALESCE(SUM(pi.amount_cents) FILTER (WHERE t.status = 'SUCCESS'), 0) AS disbursed_cents,
    COALESCE(SUM(pi.amount_cents) FILTER (WHERE t.status = 'FAILED'), 0)  AS failed_cents
FROM payment_batches b
LEFT JOIN transactions t          ON t.batch_id = b.id
LEFT JOIN payment_instructions pi ON pi.id = t.instruction_id
GROUP BY b.id, b.organization_id, b.batch_reference, b.state, b.instruction_count, b.total_amount_cents;

-- Recipient payment history, feeding the AMOUNT_DEVIATION risk signal.
CREATE OR REPLACE VIEW recipient_payment_history AS
SELECT
    r.id                            AS recipient_id,
    r.organization_id,
    r.created_at                    AS recipient_created_at,
    r.payment_details_modified_at,
    COUNT(t.id) FILTER (WHERE t.status = 'SUCCESS')                   AS successful_payment_count,
    COALESCE(AVG(pi.amount_cents) FILTER (WHERE t.status = 'SUCCESS'), 0)::BIGINT AS mean_amount_cents,
    MAX(t.completed_at) FILTER (WHERE t.status = 'SUCCESS')           AS last_paid_at,
    MIN(t.completed_at) FILTER (WHERE t.status = 'SUCCESS')           AS first_paid_at
FROM recipients r
LEFT JOIN payment_instructions pi ON pi.recipient_id = r.id
LEFT JOIN transactions t          ON t.instruction_id = pi.id
GROUP BY r.id, r.organization_id, r.created_at, r.payment_details_modified_at;

-- Daily disbursement totals, for the policy circuit breaker and executive analytics.
CREATE OR REPLACE VIEW daily_disbursement_totals AS
SELECT
    t.organization_id,
    date_trunc('day', t.completed_at AT TIME ZONE 'Africa/Nairobi')::DATE AS disbursement_date,
    COUNT(*)                        AS transaction_count,
    SUM(pi.amount_cents)            AS total_cents
FROM transactions t
JOIN payment_instructions pi ON pi.id = t.instruction_id
WHERE t.status = 'SUCCESS' AND t.completed_at IS NOT NULL
GROUP BY t.organization_id, 2;

-- Departmental expenditure for L2/L3 analytics (§12).
CREATE OR REPLACE VIEW department_expenditure AS
SELECT
    b.organization_id,
    d.id                            AS department_id,
    d.name                          AS department_name,
    date_trunc('month', t.completed_at AT TIME ZONE 'Africa/Nairobi')::DATE AS period_month,
    COUNT(*) FILTER (WHERE t.status = 'SUCCESS')                        AS paid_count,
    COUNT(*) FILTER (WHERE t.status = 'FAILED')                         AS failed_count,
    COALESCE(SUM(pi.amount_cents) FILTER (WHERE t.status = 'SUCCESS'), 0) AS paid_cents
FROM transactions t
JOIN payment_instructions pi ON pi.id = t.instruction_id
JOIN payment_batches b       ON b.id = t.batch_id
LEFT JOIN departments d      ON d.id = pi.department_id
WHERE t.completed_at IS NOT NULL
GROUP BY b.organization_id, d.id, d.name, 4;
