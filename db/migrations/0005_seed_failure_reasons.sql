-- ============================================================================
-- SOLVAREN Payment Solutions — 0005 Failure reason dictionary seed
--
-- GENERATED FILE — do not edit by hand.
-- Source: packages/core/src/failure-reasons.ts (dictionary version 2026.09.13)
-- Regenerate with: pnpm db:generate-seed
--
-- These rows are the platform default scope (organization_id IS NULL). An administrator
-- may add an organisation-scoped override for any code without a deploy (TRK-009); the
-- override wins, this table is the next fallback, and the compiled dictionary in
-- @solvaren/core is the last resort if the database is unreachable.
-- ============================================================================

INSERT INTO failure_reason_map
    (organization_id, provider_code, reason, failure_class, operator_action, transient, dictionary_version)
VALUES
    (NULL, '00.002.1001', 'M-PESA is under maintenance', 'PROVIDER', 'Releases are paused automatically; retry after the maintenance window', true, '2026.09.13'),
    (NULL, '1', 'Insufficient balance in the organization''s Utility account', 'FUNDING', 'Top up the B2C shortcode, or move funds from the Working (MMF) account to Utility on the M-PESA org portal — B2C debits Utility, not Working', true, '2026.09.13'),
    (NULL, '100000001', 'M-PESA reports the system is overloaded', 'PROVIDER', 'The reconciliation sweep will re-check', true, '2026.09.13'),
    (NULL, '100000002', 'M-PESA throttling error', 'PROVIDER', 'The reconciliation sweep will re-check', true, '2026.09.13'),
    (NULL, '100000004', 'M-PESA internal server error', 'PROVIDER', 'Reconcile before any retry', true, '2026.09.13'),
    (NULL, '100000010', 'Insufficient permissions on the M-PESA account', 'PERMISSION', 'Level 3: review the API operator roles on the org portal', false, '2026.09.13'),
    (NULL, '100000011', 'M-PESA request rate limit exceeded', 'PROVIDER', 'Throughput is throttled automatically', true, '2026.09.13'),
    (NULL, '11', 'The organization B2C account is not in an active state', 'PROVIDER', 'Contact Safaricom business support to reactivate the B2C shortcode; hold further releases until resolved', false, '2026.09.13'),
    (NULL, '15', 'Duplicate request detected by M-PESA — this OriginatorConversationID was already seen', 'AMBIGUOUS', 'Do not resend. Run a status query on the original OriginatorConversationID to establish the true outcome', false, '2026.09.13'),
    (NULL, '17', 'M-PESA internal failure', 'PROVIDER', 'Reconcile before any retry; escalate to Safaricom if it repeats', true, '2026.09.13'),
    (NULL, '18', 'Initiator credential check failed (wrong password or an encryption/decryption problem)', 'CREDENTIAL', 'Level 3: regenerate the SecurityCredential against the current M-PESA public certificate and rotate the stored credential', false, '2026.09.13'),
    (NULL, '19', 'Message sequencing failure at M-PESA', 'PROVIDER', 'Reconcile the transaction; escalate if it repeats', true, '2026.09.13'),
    (NULL, '2', 'Amount is below the minimum permitted for this payment (M-PESA minimum is KES 10)', 'LIMIT', 'Correct the instruction amount and resubmit as a new instruction', false, '2026.09.13'),
    (NULL, '20', 'Unresolved initiator — the API username was not found on the M-PESA portal', 'CREDENTIAL', 'Level 3: verify the InitiatorName matches an active API operator on the shortcode', false, '2026.09.13'),
    (NULL, '2001', 'The initiator information is invalid (username, password, encryption or certificate)', 'CREDENTIAL', 'Level 3: test the Daraja connection, then rotate the initiator credential. Payments will keep failing identically until this is fixed', false, '2026.09.13'),
    (NULL, '2006', 'Declined by an account rule — the B2C account is not active', 'PROVIDER', 'Contact Safaricom business support; hold releases until the account is active', false, '2026.09.13'),
    (NULL, '2028', 'The paying shortcode is not permitted to perform B2C under its product assignment', 'PERMISSION', 'Level 3: confirm the shortcode is a Bulk Disbursement / one-account shortcode with B2C enabled', false, '2026.09.13'),
    (NULL, '2040', 'The recipient is not a registered M-PESA customer', 'RECIPIENT', 'Verify the phone number on the recipient record. B2C CommandIDs only pay registered customers', false, '2026.09.13'),
    (NULL, '21', 'The initiator is not permitted to perform this operation (missing the ORG B2C API Initiator role)', 'PERMISSION', 'Level 3: have the Business Administrator assign the "ORG B2C API Initiator" role to the API user', false, '2026.09.13'),
    (NULL, '22', 'The initiator is not permitted to pay this receiver, or the initiator is not active', 'PERMISSION', 'Level 3: check the API operator is active and permitted for the receiving party', false, '2026.09.13'),
    (NULL, '24', 'M-PESA rejected the request for missing mandatory fields', 'REQUEST', 'Raise an engineering incident — the submitted payload is incomplete', false, '2026.09.13'),
    (NULL, '25', 'M-PESA could not convert one of the request parameters', 'REQUEST', 'Raise an engineering incident — a field is the wrong type', false, '2026.09.13'),
    (NULL, '26', 'M-PESA is applying traffic blocking (system too busy)', 'PROVIDER', 'The reconciliation sweep will re-check; throughput is throttled automatically', true, '2026.09.13'),
    (NULL, '29', 'M-PESA rejected the command as invalid', 'REQUEST', 'Raise an engineering incident — the CommandID is not valid for this shortcode', false, '2026.09.13'),
    (NULL, '3', 'Amount exceeds the maximum permitted per transaction (M-PESA B2C maximum is KES 250,000)', 'LIMIT', 'Split the payment across multiple instructions within the per-transaction limit', false, '2026.09.13'),
    (NULL, '4', 'Payment would exceed the recipient''s daily M-PESA transfer limit (KES 500,000)', 'LIMIT', 'Pay the balance on a later date, or ask the recipient to confirm their limit with Safaricom', true, '2026.09.13'),
    (NULL, '400.002.02', 'Daraja rejected a field in the request as invalid', 'REQUEST', 'Raise an engineering incident with the correlation id', false, '2026.09.13'),
    (NULL, '400.002.05', 'Daraja rejected the request payload as malformed', 'REQUEST', 'Raise an engineering incident with the correlation id', false, '2026.09.13'),
    (NULL, '400.003.01', 'The Daraja access token was invalid or expired', 'CREDENTIAL', 'The token cache refreshes automatically; if it persists, Level 3 should re-test the Daraja connection', true, '2026.09.13'),
    (NULL, '400.003.02', 'Daraja rejected the request as incomplete', 'REQUEST', 'Raise an engineering incident with the correlation id', false, '2026.09.13'),
    (NULL, '401.002.01', 'The Daraja access token was rejected', 'CREDENTIAL', 'Level 3: verify the consumer key and secret, then re-test the connection', true, '2026.09.13'),
    (NULL, '404.001.03', 'The Daraja access token was rejected as invalid', 'CREDENTIAL', 'Level 3: verify the consumer key and secret, then re-test the connection', true, '2026.09.13'),
    (NULL, '404.001.04', 'Daraja rejected the authentication header or HTTP method', 'REQUEST', 'Raise an engineering incident with the correlation id', false, '2026.09.13'),
    (NULL, '500.001.1001', 'Daraja internal server error while handling the request', 'PROVIDER', 'Reconcile before any retry — the payment may still have been processed', true, '2026.09.13'),
    (NULL, '500.002.1001', 'Duplicate OriginatorConversationID — Daraja has already seen this request identifier', 'AMBIGUOUS', 'Do not resend. Query the transaction status for the original identifier to establish whether money moved', false, '2026.09.13'),
    (NULL, '500.003.02', 'Spike arrest violation — request rate exceeded the permitted burst', 'PROVIDER', 'Throughput is throttled automatically; the sweep will re-check', true, '2026.09.13'),
    (NULL, '500.003.03', 'Quota violation — the request exceeded the permitted TPS', 'PROVIDER', 'Throughput is throttled automatically; the sweep will re-check', true, '2026.09.13'),
    (NULL, '500.003.1001', 'Daraja internal server error', 'PROVIDER', 'Reconcile before any retry', true, '2026.09.13'),
    (NULL, '8', 'Payment would exceed the recipient''s maximum M-PESA wallet balance (KES 500,000)', 'LIMIT', 'Ask the recipient to withdraw funds before the payment is retried', true, '2026.09.13'),
    (NULL, '8006', 'The API security credential is locked', 'CREDENTIAL', 'Level 3: ask the Business Administrator to unlock the API user password on the M-PESA org portal, then rotate the credential', false, '2026.09.13'),
    (NULL, 'SFC_IC0003', 'The operator does not exist — the phone number is invalid or unassigned', 'RECIPIENT', 'Correct the recipient MSISDN on the master record and issue a new instruction', false, '2026.09.13'),
    (NULL, 'SLV_INTEGRATION_DISABLED', 'The Daraja integration was disabled before this instruction could be submitted', 'CREDENTIAL', 'Level 3: re-enable the integration in Settings → Daraja, then reissue the instruction', false, '2026.09.13'),
    (NULL, 'SLV_NO_CALLBACK', 'The request was accepted by M-PESA but no result callback has arrived', 'AMBIGUOUS', 'Reconciliation is querying the Transaction Status API. Do not resubmit until the outcome is known', false, '2026.09.13'),
    (NULL, 'SLV_QUEUE_TIMEOUT', 'M-PESA reported the request timed out while queued for processing', 'AMBIGUOUS', 'Reconciliation is querying the Transaction Status API. Do not resubmit until the outcome is known', false, '2026.09.13'),
    (NULL, 'SLV_SUBMIT_FAILED', 'SOLVAREN could not deliver the request to M-PESA', 'PROVIDER', 'The instruction was never accepted, so no money moved. It can be safely reissued once connectivity is restored', true, '2026.09.13'),
    (NULL, 'SLV_TIMEOUT', 'No result was received from M-PESA within the expected window', 'AMBIGUOUS', 'Reconciliation is querying the Transaction Status API. Do not resubmit until the outcome is known', false, '2026.09.13')
ON CONFLICT (organization_id, provider_code) DO UPDATE
    SET reason             = EXCLUDED.reason,
        failure_class      = EXCLUDED.failure_class,
        operator_action    = EXCLUDED.operator_action,
        transient          = EXCLUDED.transient,
        dictionary_version = EXCLUDED.dictionary_version;
