# Deploying SOLVAREN

This is the order operations should be performed in, and the reasoning behind the steps
that are easy to get wrong. It assumes a Cloudflare account with Workers Paid (Queues,
Durable Objects and Hyperdrive are not on the free plan), a managed PostgreSQL 16 instance,
and a Safaricom Daraja account.

Nothing here requires SOLVAREN to hold a plaintext credential at rest. Where a secret is
involved, the step says where it lives afterwards.

---

## 0. Before you begin

**You need a Daraja production shortcode, and it takes time.** Safaricom's B2C API requires
a Bulk Disbursement Account (or a paybill/till converted to a "one account" that can both
receive and disburse). Applications go through
[m-pesaforbusiness.co.ke](https://m-pesaforbusiness.co.ke/) or
`M-PESABusiness@Safaricom.co.ke`, and approval is measured in weeks, not days. Start this
before you start the technical work.

**Decide the open questions in specification §28.** Three of them block deployment:

| Decision | Why it blocks |
|---|---|
| PostgreSQL host and region | Hyperdrive is configured against a specific connection string |
| Whether administrative surfaces sit behind Cloudflare Access | Changes the Terraform apply and the operator onboarding |
| Whether financial data may reach the AI provider | Determines whether `AI_API_KEY` is set at all |

The remainder (approval thresholds, cooling-off duration, holiday calendar) are
organisation policy and can be set through the console after go-live.

---

## 1. Database

Provision PostgreSQL 16 or later. SOLVAREN uses `pgcrypto`, `citext`, partial unique
indexes, `EXCLUDE` constraints and `NULLS NOT DISTINCT` — all standard, none requiring an
extension beyond the two named.

```bash
psql "$DATABASE_URL" -f db/migrations/0001_foundation.sql
psql "$DATABASE_URL" -f db/migrations/0002_payments.sql
psql "$DATABASE_URL" -f db/migrations/0003_audit_immutability.sql
psql "$DATABASE_URL" -f db/migrations/0004_backups_exports.sql
psql "$DATABASE_URL" -f db/migrations/0005_seed_failure_reasons.sql
psql "$DATABASE_URL" -f db/migrations/0006_views.sql
```

Then verify the guarantees actually took effect:

```bash
SOLVAREN_TEST_DB=solvaren_verify scripts/db-test.sh <host> <port> <user>
```

That runs 45 assertions against a disposable copy of the schema — that a settled
transaction cannot be re-settled, that an audit event cannot be deleted, that a batch
creator cannot be recorded as its own approver. If any fails, stop: the immutability
guarantees this platform rests on are not in place.

### Application database role

Create a role that is **not** the owner of the tables. The immutability triggers block
UPDATE and DELETE for every ordinary role, but a table owner can disable a trigger, and
the Workers should not be able to.

```sql
CREATE ROLE solvaren_app LOGIN PASSWORD '<generated>';
GRANT CONNECT ON DATABASE solvaren TO solvaren_app;
GRANT USAGE ON SCHEMA public TO solvaren_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO solvaren_app;
GRANT SELECT, DELETE ON payment_instructions TO solvaren_app;  -- editable batches only
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO solvaren_app;

-- Deliberately NOT granted: DELETE on transactions, audit_events, approvals,
-- authorization_challenges, backup_attempts or export_records. The triggers already
-- refuse, and the grant removes the second way to try.
```

Point Hyperdrive at this role, never at the owner.

---

## 2. Cloudflare resources

```bash
# Queues, with a dead-letter queue for each. The DLQ is not optional: a message that
# exhausts its retries carries a payment whose outcome is unknown, and it must land
# somewhere an operator can find it.
for q in payments callbacks reconciliation backups; do
  wrangler queues create "solvaren-$q"
  wrangler queues create "solvaren-$q-dlq"
done

# R2, for backups, encrypted secret envelopes and generated artefacts.
wrangler r2 bucket create solvaren-artifacts

# Hyperdrive, against the application role from step 1.
wrangler hyperdrive create solvaren-production \
  --connection-string "postgres://solvaren_app:<password>@<host>:5432/solvaren"
```

Take the Hyperdrive id from the output and replace `REPLACE_WITH_PRODUCTION_HYPERDRIVE_ID`
in `apps/api/wrangler.toml`.

---

## 3. Secrets

These are set with `wrangler secret put` and exist only as Worker bindings. None of them
appears in `wrangler.toml`, in the database, or in any API response — `pnpm
check:invariants` fails the build if one does.

```bash
cd apps/api

# 32+ bytes of entropy. Rotating this invalidates every live session, which is the
# intended behaviour during an incident.
openssl rand -base64 48 | wrangler secret put SESSION_SIGNING_KEY --env production

# The master key for envelope-encrypting organisation secrets (Daraja credentials, S3
# keys). Losing it makes every stored credential unrecoverable and every integration needs
# reconfiguring — back it up in your organisation's key custody process before proceeding.
openssl rand -base64 48 | wrangler secret put SECRET_ENCRYPTION_KEY --env production

# Fallback shared secret for callbacks. Each organisation additionally gets its own,
# generated when its integration is configured.
openssl rand -base64 48 | wrangler secret put CALLBACK_SHARED_SECRET --env production

# Optional. Omit entirely to disable the AI layer; the deterministic risk engine and the
# failure dictionary are unaffected, and the AI endpoints degrade to returning the
# deterministic findings alone.
wrangler secret put AI_API_KEY --env production
```

> **On `SECRET_ENCRYPTION_KEY`:** it protects the Daraja credentials at rest in R2. If it
> is lost, the ciphertext is unrecoverable by design — AES-GCM with a lost key is not
> recoverable by anyone, including us. Store it in your organisation's existing key custody
> arrangement before the first integration is configured, not after.

---

## 4. Deploy

```bash
pnpm install --frozen-lockfile
pnpm verify              # format, lint, types, invariants, tests, database assertions

pnpm --filter @solvaren/api deploy:production
pnpm --filter @solvaren/web build
pnpm --filter @solvaren/web deploy:production
```

`pnpm verify` is not ceremony. It runs the 45 database assertions and the 29 source
invariants, both of which check properties that a passing unit test would not catch.

---

## 5. Edge configuration

```bash
cd infra/terraform
terraform init
terraform plan  -var-file=production.tfvars
terraform apply -var-file=production.tfvars
```

`production.tfvars` holds zone and account ids and the administrator email list. It is not
committed. `CLOUDFLARE_API_TOKEN` comes from the environment.

**On `safaricom_callback_ranges`:** leave it empty unless you have the current ranges from
`apisupport@safaricom.co.ke`. An out-of-date list silently blocks legitimate callbacks,
and Daraja does not retry a rejected delivery — the payment result is simply lost until
the reconciliation sweep picks it up. The callback endpoint authenticates by per-
organisation shared secret regardless, so an empty list degrades to "the application
check is doing the work", which is an acceptable posture.

---

## 6. First organisation and Level 3 account

There is deliberately no self-service signup: SOLVAREN is a controlled-tenancy platform.
The first L3 account is created directly.

```sql
INSERT INTO organizations (id, name, slug) VALUES (gen_random_uuid(), 'Acme Holdings', 'acme');
INSERT INTO policies (organization_id) SELECT id FROM organizations WHERE slug = 'acme';
```

Then create the user with a generated Argon2id hash (the console's enrolment flow is the
normal path; this is the bootstrap):

```bash
node --experimental-strip-types scripts/create-user.mjs \
  --organization acme --email ceo@acme.test --name "Amina Njeri" --level L3
```

The account is created `PENDING_ENROLMENT`. It cannot sign in until a WebAuthn
authenticator is registered and an authorization PIN is set — the schema's
`users_privileged_requires_pin` constraint refuses to mark an L2 or L3 account ACTIVE
without a PIN, and `issueSession` refuses to issue a usable session for an L2/L3 account
that has not completed WebAuthn.

**Register two authenticators, not one.** An L3 account is the only thing that can release
a payment, and a single lost security key with no second authenticator means a controlled
administrative recovery — which is deliberately slow (spec §8.3).

---

## 7. Daraja integration

Performed in the console, by an L3 user, at **Settings → Daraja**. Three things to know:

1. **Create the API operator on the M-PESA portal first.** It needs the
   `ORG B2C API Initiator` role, assigned by a Business Administrator, and its password
   set by a user holding `Set Restricted ORG API PASSWORD`. Until the password is set the
   operator is "pending active" and every payment fails with result code `2001`.

2. **The portal password character rules are real.** Safaricom permits only `#`, `&`, `%`
   and `$` as special characters, and handles `@` and `.` inconsistently. SOLVAREN
   validates this at configuration time so the constraint is discovered now rather than
   during a payroll run.

3. **You can avoid giving SOLVAREN the initiator password at all.** Generate the
   `SecurityCredential` on the Daraja portal's password-encryption tool and paste that
   instead; SOLVAREN recognises a pre-computed credential and stores it as-is. Otherwise,
   supply the password together with the M-PESA public certificate and SOLVAREN encrypts
   it once, stores the ciphertext, and discards the password.

Then **Test connection** before enabling. The database refuses to set an integration to
`ENABLED` without a passing test on record (`daraja_enabled_requires_passing_test`), which
means a credential problem surfaces during setup rather than mid-payroll.

Register the callback URLs the configuration screen displays with Safaricom. They embed
the organisation id and a per-organisation secret; the secret is generated on save and is
never displayed again.

---

## 8. Backups

At **Settings → Backups**, connect an S3-compatible target, test the connection, then
enable the schedule. The schedule cannot be enabled against an untested target
(`backup_schedule_requires_test`).

**Run a restore before you rely on it.** A backup that has never been restore-validated is
not disaster-recovery proven, and the console says so on the screen. See
[`runbooks/backup-restore.md`](runbooks/backup-restore.md).

---

## 9. Go-live checklist

Verified, not assumed:

- [ ] `scripts/db-test.sh` passes all 45 assertions against the production schema
- [ ] `pnpm check:invariants` passes all 29 checks on the deployed commit
- [ ] The application database role is not the table owner
- [ ] `SECRET_ENCRYPTION_KEY` is in key custody
- [ ] Every L3 account has **two** registered authenticators and an authorization PIN
- [ ] Daraja connection test passes against the **production** environment
- [ ] Callback URLs are registered with Safaricom and a test callback has been received
- [ ] A backup has run, and a restore has been performed into a scratch database
- [ ] Terraform applied; the WAF rules are visible in the Cloudflare dashboard
- [ ] Organisation policy limits are set to the organisation's real thresholds, not defaults
- [ ] The finance team has walked through one sandbox payroll end to end, including a
      deliberate failure, and has downloaded the failed-transactions CSV

The last item matters more than it looks. The first time an operator sees the release
ceremony should not be with real money on the other side of it.

---

## Rollback

Workers and Pages both keep prior deployments:

```bash
wrangler deployments list --name solvaren-api
wrangler rollback --name solvaren-api --message "Reverting <reason>"
```

**Database migrations are forward-only.** The schema is append-only by design and the
immutability triggers mean a "down" migration would have to disable them, which is exactly
the capability the design removes. A schema change that proves wrong is corrected by a new
migration, not by reversing the old one.

A rollback of the Worker against a newer schema is safe: every migration so far is additive.
A rollback across a migration that *removed* something would not be, so such a migration
should be split into two releases — stop using the column in one, drop it in the next.
