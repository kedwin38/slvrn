# SOLVAREN Payment Solutions

**Move money with certainty.**

A security-first business disbursement control plane for Safaricom M-PESA. SOLVAREN
prepares payment instructions, subjects them to layered review, requires cryptographic
authorization at the highest authority level, executes through Daraja B2C, reconciles
ambiguous outcomes, and keeps a tamper-evident record of what happened.

It is not a "send money" application. Its design objective is **controlled financial
execution**, and most of what follows is about the things it refuses to do.

---

## The three properties everything else serves

**1. No single thing can release money.**

Releasing a payment requires L3 authority, an intact approval chain bound to the current
batch version, separation of duties, no declared conflict of interest, a manifest rebuilt
from live database rows that hashes identically to the one authorized, fresh
authentication, a WebAuthn signature over that manifest digest, the SOLVAREN Authorization
PIN, organisation policy limits, a risk gate, and a valid state transition.

There is no override, no parameter that disables a check, and no branch that skips one.
`apps/api/src/services/authorization.ts` is written to be read start to finish by an
auditor.

**2. An unknown outcome is never resolved by guessing.**

If SOLVAREN cannot tell whether a payment reached M-PESA, it does not retry — retrying
pays someone twice, and B2C payments cannot be reversed through the API. It does not
assume failure either, because that leaves someone unpaid. It queries the Transaction
Status API until Safaricom gives a definitive answer, and escalates to a human when it
cannot get one.

**3. No failure is invisible or unexplained.**

Every failed transaction carries a provider code, a human-readable reason, and a concrete
operator action. The database refuses to store a FAILED transaction without a reason, and
refuses to store a SUCCESS without a provider receipt. Unmapped provider codes fall back
to the provider's own description — never blank, never the bare word "Error".

---

## What is here

```
packages/core/       Domain and security kernel — pure, no I/O, exhaustively tested
packages/daraja/     M-PESA Daraja B2C, Transaction Status, Account Balance
apps/api/            Cloudflare Worker: HTTP API, four queue consumers, three cron jobs
apps/web/            The console — React, bespoke design system, no UI framework
db/migrations/       PostgreSQL schema. The immutability guarantees live here.
db/tests/            45 assertions that attack the schema directly
infra/terraform/     Cloudflare WAF, rate limits, Access policies
docs/                Deployment, runbooks, threat model, specification coverage
scripts/             Invariant checks, database harness, bootstrap, restore
```

### The security kernel is pure

`packages/core` has no database, no network and no Cloudflare bindings. The rules that
decide whether money may move are provable in isolation, and they are, before any
infrastructure is involved: the RBAC matrix, the batch and transaction state machines, the
manifest hashing, separation of duties, the failure dictionary, idempotency fingerprinting
and the audit hash chain.

### The database is the last line of defence

Application logic can be bypassed. The schema cannot:

- A `SUCCESS` transaction without an M-PESA receipt is refused by CHECK constraint.
- A `FAILED` transaction without a reason is refused by CHECK constraint.
- `UPDATE` and `DELETE` on `audit_events` are refused by trigger, for every role.
- A settled transaction cannot be re-settled; a receipt cannot be overwritten.
- A batch creator cannot be recorded as its own approver or authorizer.
- Two concurrent authorization ceremonies on one batch are refused by a partial unique index.
- An AI interaction claiming to have changed state is refused by CHECK constraint.

`scripts/db-test.sh` attacks each of these against a real PostgreSQL instance.

---

## Running it

```bash
pnpm install

# PostgreSQL is required for the integration and database suites. The guarantees under
# test are enforced by triggers and constraints, so a mocked database proves nothing.
pnpm db:up
export SOLVAREN_TEST_DATABASE_URL=postgres://postgres@localhost:5433/postgres

pnpm verify     # format, lint, types, invariants, 313 tests, 45 database assertions
```

| Command                 | What it does                                                                                                                                              |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pnpm test`             | 313 unit, integration, HTTP and round-trip tests                                                                                                          |
| `pnpm db:test`          | 45 assertions attacking the schema directly                                                                                                               |
| `pnpm check:invariants` | 31 source properties that must hold (no SMS path, no vacuous permission check, every release gate invoked, no compiled output shadowing a source file, …) |
| `pnpm ui:check`         | Drives the built console in Chromium, both themes, asserts no page errors and no mobile overflow                                                          |
| `pnpm db:generate-seed` | Regenerates the failure-reason migration from the source dictionary                                                                                       |

The invariant checks are verified to _fail_, not merely to pass. Reintroducing a vacuous
permission check, adding a phone column to an identity table, letting the AI route write to
a payment table, deleting a release gate, and leaving compiled output beside a source file
were each deliberately tested.

Linting is type-aware, and the rules are chosen rather than inherited: `no-floating-promises`
is the one that matters most here, because a dropped `await` on an audit write compiles,
reviews cleanly, and loses the record of a payment. Rules that fired only on correct code
are turned off in `eslint.config.mjs` with the reason written down, so nobody has to
rediscover it.

---

## Deployment

See [`docs/deployment.md`](docs/deployment.md). In short: PostgreSQL, then Cloudflare
resources, then secrets as Worker bindings, then `pnpm verify`, then deploy, then
Terraform, then the first L3 account, then Daraja, then a backup **and a restore**.

Runbooks for the situations that actually occur:

- [A payment is stuck in PROCESSING or TIMEOUT](docs/runbooks/payment-stuck.md)
- [Daraja credential rotation and emergency disablement](docs/runbooks/daraja-credential-rotation.md)
- [Backup restoration and disaster-recovery test](docs/runbooks/backup-restore.md)

---

## What this implementation does not do

Stated plainly, because a specification-compliance table with every row ticked is usually
lying.

**Not verified against production Daraja.** The integration is built to the documented
contract and exercised against a scripted provider covering acceptance, rejection,
timeout, duplicate-identifier, callback, duplicate-callback and contradicting-callback
paths. It has not been run against Safaricom's sandbox or production, because that needs
credentials and a shortcode. The `SecurityCredential` implementation _is_ verified — its
output is decrypted with OpenSSL, including keys parsed from a genuine X.509 certificate —
but "Daraja accepts our B2C payload" is an untested claim until someone runs it.

**Not deployed.** `wrangler deploy --dry-run` passes and every binding resolves, but no
Cloudflare account has been touched. Hyperdrive ids are placeholders.

**Coverage is 63.7% overall, and uneven on purpose.** The modules that decide whether money
moves are at or near complete — RBAC, manifest hashing, the batch state machine, the policy
engine and the CSV export are at 100%; the audit chain, crypto and idempotency are above
97%; the release ceremony service is 88%. The shortfall is in analytics, reporting and
administration _handlers_, where queries are exercised but not every branch. That is a
deliberate allocation of effort, stated rather than averaged away. The specification called
for 100%; this is what was actually achieved, and where.

**No load testing.** The architecture is built for the volumes in the specification —
bounded queue concurrency, a token-bucket rate limiter aligned to the Daraja contract,
server-side pagination, indexes matching every sort column — but 10,000 concurrent
transactions have not been run through it.

**Open decisions remain open.** Specification §28 lists choices that are the organisation's
to make: PostgreSQL host and region, whether administrative surfaces sit behind Cloudflare
Access, whether financial data may reach the AI provider, RPO/RTO targets. The deployment
guide says which of them block go-live.

**AI is advisory and degrades to nothing.** Without `AI_API_KEY` the layer is simply off,
and the deterministic risk engine and failure dictionary are unaffected. That is the
intended posture for an organisation whose data may not leave its environment.

---

## Specification coverage

[`docs/specification-coverage.md`](docs/specification-coverage.md) maps every requirement
to where it is implemented and how it is verified, including the items that are partial and
why.
