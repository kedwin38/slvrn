# Threat model

Organised by what an attacker is trying to achieve, not by OWASP category, because the
question that matters for a disbursement platform is "can they move money, and would we
know".

Each control says where it lives and how it is verified. Controls that exist only in
application code are marked as such — they are the ones a bug can bypass.

---

## 1. Move money to an account the attacker controls

The objective everything else serves. Four routes to it.

### 1.1 Compromise a Level 3 account

**Attack.** Phish or steal an L3 officer's password and release a batch.

**Why it fails.** A password alone cannot produce a session: WebAuthn is mandatory for L2
and L3, and `issueSession` refuses to issue a usable session without it. Even with a live
session, release additionally requires fresh authentication (five minutes), a WebAuthn
assertion over the manifest digest, and the SPAC PIN — a separate credential, bound to the
user id, never transmitted or stored in a reversible form.

**Residual risk.** An attacker with the officer's security key _and_ their PIN _and_
physical access during an authenticated session can release. That is the intended floor:
the design makes remote compromise insufficient, not physical coercion.

**Verified by** `routes.test.ts` (session refusal), `crypto.test.ts` (PIN binding),
`integration.test.ts` (each gate refused independently).

### 1.2 Alter a batch after it has been approved

**Attack.** Get a clean batch approved, then change an amount or add a recipient before
release.

**Why it fails.** Three independent layers:

1. The approval is bound to a batch _version_. Any material edit increments it, and
   `loadCurrentApproval` refuses an approval whose version no longer matches.
2. The manifest is rebuilt from live database rows at release and must hash identically to
   the one the ceremony was opened against. Amount, MSISDN, recipient set and approval
   chain are all in the digest.
3. The database refuses the edit outright once the batch leaves DRAFT or VALIDATED
   (`instructions_guard_update`).

**Verified by** `manifest.test.ts` (six mutation classes each move the digest),
`integration.test.ts` (release refused with `MANIFEST_CHANGED`, and the database refuses
the edit independently), `db/tests/immutability.sql`.

### 1.3 Alter a payment message in the queue

**Attack.** Modify an `EXECUTE_INSTRUCTION` message to redirect a payment.

**Why it fails.** The message carries an idempotency fingerprint derived from the
organisation, batch, instruction, batch version, MSISDN, amount and manifest hash. The
executor re-derives it from live database rows and refuses any mismatch, writing a
`payment.execution.fingerprint_mismatch` denial to the audit log.

**Residual risk.** An attacker who can write to the queue _and_ to the database can make
both agree. At that point they have the database, and the audit chain is the remaining
control.

### 1.4 Self-approval or collusion

**Attack.** Create a batch and approve or authorize it yourself.

**Why it fails.** Creator ≠ approver, modifier ≠ approver, approver ≠ authorizer, and
creator ≠ authorizer — enforced in `sod.ts` at every workflow boundary _and_ as CHECK
constraints on `payment_batches`. A cooling-off window blocks an edit immediately before
submission. A conflict-of-interest registry blocks a named officer for a named recipient or
department.

Repeated approval by the same pair is surfaced as a risk finding rather than blocked: the
legitimate version (a small finance team) and the illegitimate version look identical from
inside the data, so the decision belongs to a human.

**Verified by** `governance.test.ts`, `integration.test.ts`, `db/tests/immutability.sql`.

---

## 2. Get paid twice

Not an external attack so much as a systems failure, and the more likely of the two.

**The scenario.** A payment is submitted to M-PESA, the worker dies before recording the
response, and the queue redelivers the message.

**Why it fails.** The idempotency claim transitions to `SUBMITTED` and **commits before**
the provider call. A redelivered message finds that claim and takes the
`RECONCILE_FIRST` branch: it queries the Transaction Status API rather than resubmitting.
Daraja's own duplicate-`OriginatorConversationID` check is the backstop, not the control —
by the time it fires, we have already lost track of the first attempt.

The Daraja client additionally never retries a B2C submission, at any level, for any reason.

**Verified by** `integration.test.ts` — a redelivered message after submission produces
exactly one request to the provider and one reconciliation message. `client.test.ts`
asserts no retry even on a token error.

---

## 3. Forge an outcome

**Attack.** Make a payment that failed appear successful, or vice versa.

**Why it fails.** `SUCCESS` requires a provider receipt — as a state-machine
precondition, as a CHECK constraint, and because a `SYSTEM`-sourced transition to SUCCESS
is refused outright. `FAILED` requires a failure code, likewise doubly enforced. A settled
transaction cannot be re-settled: a later callback or status query that disagrees opens a
discrepancy case for a human and leaves the ledger untouched.

**Verified by** `state-machines.test.ts`, `db/tests/immutability.sql` ("a SUCCESS
transaction cannot be inserted without an M-PESA receipt"), `integration.test.ts` (a
contradicting callback does not rewrite a settled transaction).

---

## 4. Forge or replay a provider callback

**Attack.** POST a success callback for a payment that did not happen.

**Why it fails, in layers.**

1. The organisation comes from the URL path, not the payload, so a forged body cannot
   direct a result at another tenant.
2. A per-organisation shared secret, compared in constant time. A wrong secret returns 200
   — indistinguishable from success — and writes a CRITICAL security event.
3. A callback that matches no transaction is retained as evidence and marked `UNMATCHED`.
   **It never creates a transaction**, so the endpoint cannot be used to invent a payment.
4. Identical payloads are deduplicated by content digest before they are enqueued.
5. The application enforces method, content type and body size before parsing.
   **There is no longer an IP allowlist for Safaricom's ranges**: that was a Cloudflare WAF
   rule, and the Railway deployment has no edge. Layers 1–4 are unchanged and are what the
   endpoint's safety actually rests on; the allowlist was defence in depth, and its loss is
   the reason to put a proxy in front of the API in production.

**Residual risk.** An attacker who obtains the shared secret _and_ a valid
`OriginatorConversationID` for an in-flight payment could settle it early with a forged
receipt. Mitigated by the reconciliation sweep, which independently queries the Transaction
Status API and raises a discrepancy when the provider disagrees.

**Verified by** `routes.test.ts` (forged secret, deduplication, malformed organisation id),
`integration.test.ts` (unmatched callback invents nothing).

---

## 5. Steal the Daraja credentials

**Attack.** Read the consumer secret or SecurityCredential and pay directly from the
shortcode, bypassing SOLVAREN entirely.

**Why it fails.** No code path returns a plaintext Daraja secret to any caller at any
authority level — spec §4.4 forbids it even to L3, and the configuration API deals only in
masked views. Secrets are AES-GCM envelope-encrypted _before_ leaving the process and stored
by reference; the database holds binding names and four characters of the _public_ consumer
key. The initiator password is never persisted: it is encrypted once against the M-PESA
certificate and discarded, and an organisation may supply a pre-computed credential
instead so SOLVAREN never sees it.

Compromising the object storage alone yields nothing: `SECRET_ENCRYPTION_KEY` is a separate
environment variable, held by Railway and never written to the bucket it protects. The
storage credential is likewise scoped to one bucket and four operations.

**Verified by** `routes.test.ts` (a seeded secret never appears in any response),
`check-invariants.sh` (no credential-shaped string in the repository; no secret assigned a
value in a deployment manifest), `crypto.test.ts` (envelope integrity and tamper detection).

---

## 6. Erase the evidence

**Attack.** Move money, then delete or alter the audit trail.

**Why it fails.** `UPDATE` and `DELETE` on `audit_events` are refused by trigger for every
role. Each event commits to its predecessor with SHA-256, so removal, reordering or
alteration breaks verification at a known index. The sequence and the chain link are
assigned and checked _by the database_, not trusted from the caller. The audit write happens
in the same transaction as the state change it records, so there is no window in which money
moved without a record.

**Residual risk.** A database superuser can disable the triggers. The chain makes the
resulting gap detectable, which is the property an auditor needs; the deployment guide
requires the application role not to own the tables, so the application cannot do it.

**Verified by** `governance.test.ts` (alteration, deletion and reordering each localised),
`db/tests/immutability.sql`, `integration.test.ts` (chain verifies after a real release),
`backup-restore.test.ts` (chain still verifies after a restore).

---

## 7. Exfiltrate payroll data

**Attack.** Use a compromised session to enumerate the ledger.

**Why it fails, partially.** Every export is role-scoped by organisation policy and audited
with actor, filter and row count. Exports are rate-limited in the application. Explorer pages are
capped at 200 rows and exports at the organisation's configured limit. Recipient numbers are
masked in list views.

**Residual risk.** A legitimate L2 or L3 session _can_ export the failed-transaction set —
that is the point of §6. The control is detective, not preventive: every export leaves an
audit record naming who took what.

---

## 8. Denial of service

| Vector                    | Control                                                                                    |
| ------------------------- | ------------------------------------------------------------------------------------------ |
| Volumetric                | **Not defended.** No edge, no WAF, no managed DDoS since the move off Cloudflare           |
| Credential stuffing       | Ten sign-in attempts per minute per IP, in the application; five failures lock the account |
| Export flooding           | Twenty per five minutes; row caps                                                          |
| Expensive queries         | Server-side pagination; an index per sort column; 10-second statement timeout              |
| Oversized bodies          | Checked before parsing; 8 MB for CSV, 64 KB for callbacks, 16 KB for auth                  |
| Memory-hard hashing abuse | Password length bounded before Argon2 is invoked                                           |
| Provider rate limits      | PostgreSQL token bucket, aligned to the Daraja contract, correct across replicas           |

---

## What is not defended against

Stated rather than implied.

**A compromised Railway account.** Whoever controls the project controls the application
and its environment variables, which is to say every secret. Mitigations are
organisational: hardware MFA on the account, scoped deploy tokens, and the audit chain as
the detective control.

**Volumetric denial of service.** Stated plainly because it changed: the Cloudflare
deployment inherited DDoS protection and a WAF at the edge, and the Railway one has
neither. Everything in the table above is application-level, which means an attacker can
exhaust the service before any of it applies. Putting a proxy in front of the API restores
this; until that is done, it is an accepted gap rather than a covered one.

**A malicious database superuser.** They can disable the immutability triggers. The chain
makes it detectable; nothing in software makes it impossible.

**A coerced Level 3 officer.** Two-person control makes a single compromised officer
insufficient for approval _and_ authorization, but a genuinely coerced officer with their
key and PIN can release a payment. The controls are detective: the audit record, the risk
findings, and the executive dashboard.

**Supply chain.** Dependencies are pinned and the lockfile is committed; CI runs secret
scanning. There is no reproducible-build guarantee and no vendored dependency tree.

**Safaricom-side compromise.** SOLVAREN trusts M-PESA's word on whether a payment
succeeded. There is no independent settlement source to reconcile against, and the
specification does not contemplate one.
