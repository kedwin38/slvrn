# Runbook: Daraja credential rotation and emergency disablement

**Applies to:** spec §27, "Daraja credential rotation and emergency disablement"
**Who:** Level 3 only. The API refuses every step below to any other level.

---

## Emergency: stop all outbound payments now

If you believe the Daraja credentials are compromised, or payments are going somewhere
they should not:

1. **Settings → Daraja → Disable.** Takes effect immediately. No further instruction will
   be submitted.
2. What this does and does not do:
   - Instructions **not yet submitted** will fail with `SLV_INTEGRATION_DISABLED` and can
     be reissued once the integration is restored. No money moves.
   - Instructions **already submitted** will still report their outcome. You cannot recall
     a payment M-PESA has accepted; reversal is manual, on the organisation portal.
3. On the M-PESA portal, have the Business Administrator **lock the API operator**. That
   stops anything using those credentials outside SOLVAREN.
4. Review the audit log: Security Center → filter by `INTEGRATION`. Every credential
   change, connection test and payment submission is there with an actor and a timestamp.

---

## Routine rotation

Safaricom portal passwords expire after 90 days. Rotate before expiry, not after — an
expired credential fails every payment with result code `2001`, and discovering that
mid-payroll is avoidable.

### 1. On the M-PESA organisation portal

Log in as a user holding **Set Restricted ORG API PASSWORD** (normally a Business Manager):

1. My Functions → Operator Management → find the API initiator username.
2. Operations → Set Password.
3. Character rules, which Safaricom enforces inconsistently and SOLVAREN validates for you:
   - Permitted special characters: `#`, `&`, `%`, `$` only.
   - **Avoid `@` and `.`** — they are handled unpredictably.
   - 8 to 30 characters.

### 2. Generate the SecurityCredential

Two options. The second is better if your organisation's policy is that SOLVAREN should
never hold the initiator password at all:

**Option A — let SOLVAREN encrypt it.** Supply the new password and the current M-PESA
public certificate in Settings → Daraja. SOLVAREN encrypts it with RSA PKCS#1 v1.5 against
that certificate, stores the ciphertext, and discards the password. The password is never
written to the database or to a log.

**Option B — encrypt it yourself.** Use the Daraja portal's password-encryption tool, then
paste the resulting credential into SOLVAREN. It recognises a pre-computed credential and
stores it as-is.

### 3. Update SOLVAREN

Settings → Daraja → update the credentials. This requires fresh authentication and a
WebAuthn signature on top of L3 authority.

Saving **automatically resets the integration to `TESTING`**. That is deliberate: the
database constraint `daraja_enabled_requires_passing_test` will not let it return to
`ENABLED` without a passing connection test, so a bad rotation cannot silently take out a
payroll run.

### 4. Test, then enable

**Test connection** proves the consumer key and secret authenticate. It does not prove the
SecurityCredential is correct — that is only exercised by an actual payment, because
Safaricom validates it inside M-PESA rather than at the gateway.

So: after enabling, **run one small real payment** (KES 10 to a number you control) before
the next payroll. A `2001` on that one payment costs nothing; a `2001` on 400 salaries
costs a day.

### 5. Confirm

- Settings → Daraja shows the new credential version and rotation timestamp.
- Security Center shows a `daraja.credentials.rotated` audit event with your user id.
- The test payment settled SUCCESS with a receipt.

---

## Updating the Safaricom callback IP ranges

Safaricom does not publish these in machine-readable form and they change. If you restrict
them in Terraform:

1. Request the current list from `apisupport@safaricom.co.ke`.
2. Update `safaricom_callback_ranges` in `production.tfvars`.
3. `terraform plan` and `terraform apply`.
4. Watch the API logs for rejected POSTs to `/integrations/daraja/` — a wrong shared
   secret is recorded as a CRITICAL security event, and returns 200 so an attacker cannot
   tell a wrong secret from a right one
   over the next hour. Blocked legitimate callbacks are lost — Safaricom does not retry —
   and would surface as a wave of TIMEOUT transactions.

If you are not confident the list is current, **leave the variable empty**. The endpoint
still requires a per-organisation shared secret and deduplicates by payload digest. An
out-of-date allowlist is worse than no allowlist, because it fails closed against real
traffic.
