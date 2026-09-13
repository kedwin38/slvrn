# Specification coverage

Every requirement from the SOLVAREN v2.0 specification, where it is implemented, and how it
is verified. The **Verified** column is the important one: "implemented" is a claim,
"verified" is a test you can run.

Status values are used precisely:

- **Verified** — implemented, and a test fails if it regresses.
- **Implemented** — built to the specification, but the verification is indirect or the
  claim cannot be closed without a live provider or deployment.
- **Partial** — deliberately incomplete; the gap is stated.

Run `pnpm verify` to execute everything referenced here.

---

## §4 — Roles and command hierarchy

| Requirement                                          | Where                                            | Verified                                                                                     |
| ---------------------------------------------------- | ------------------------------------------------ | -------------------------------------------------------------------------------------------- |
| Three authority levels, server-side enforced         | `packages/core/src/rbac.ts`                      | **Verified** — `rbac.test.ts` (19 tests), matrix at 100% coverage                            |
| Default deny on every permission                     | `rbac.ts` `MATRIX`                               | **Verified** — a permission absent from a level's set is refused                             |
| L1 cannot approve or release                         | `rbac.ts`, `batch-state.ts`                      | **Verified** — `state-machines.test.ts`, `routes.test.ts` (HTTP 403)                         |
| L2 cannot release; L3 cannot perform the L2 approval | `rbac.ts`                                        | **Verified** — `rbac.test.ts` asserts both directions                                        |
| L3-only Daraja, users, policies, security, backups   | `rbac.ts`, `routes/admin.ts`                     | **Verified** — `routes.test.ts` asserts 403 for L1 and L2 at the HTTP layer                  |
| Non-active account holds no permission               | `rbac.ts` `hasPermission`                        | **Verified** — every permission checked for DISABLED and LOCKED                              |
| §4.3 "Even L3 cannot" — alter history, force SUCCESS | `db/migrations/0003` triggers                    | **Verified** — `db/tests/immutability.sql`, 45 assertions                                    |
| Tenant isolation                                     | `rbac.ts` `requireSameOrganization`, every query | **Verified** — `routes.test.ts` cross-tenant batch returns 404 without leaking the reference |

## §5 — Batch lifecycle

| Requirement                              | Where                              | Verified                                                                  |
| ---------------------------------------- | ---------------------------------- | ------------------------------------------------------------------------- |
| Full state machine, no backward mutation | `packages/core/src/batch-state.ts` | **Verified** — 100% coverage; no human-traversable edge reaches SUCCESS   |
| Execution transitions are system-only    | `batch-state.ts` `systemOnly`      | **Verified** — and `system: true` is not a skeleton key past a human edge |
| Submission freezes the approval version  | `routes/batches.ts`                | **Verified** — `integration.test.ts` refuses a stale approval             |
| CSV ingest with row-level reasons        | `packages/core/src/csv.ts`         | **Verified** — `ingest.test.ts` (36 tests), 95% coverage                  |
| L2 review, approve, reject, hold         | `routes/batches.ts`                | **Implemented** — service paths verified; handler coverage is partial     |

## §6 — Transaction status tracking _(the v2.0 centrepiece)_

| ID      | Requirement                                                           | Verified                                                                                                              |
| ------- | --------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| TRK-001 | Every status visible, updated only through validated transitions      | **Verified** — `txn-state.ts` 100%; `integration.test.ts`                                                             |
| TRK-002 | Failure code + human reason; unknown codes shown raw, never blank     | **Verified** — `governance.test.ts`, plus a CHECK constraint and a `lower(reason) <> 'error'` constraint              |
| TRK-003 | Server-side filter and sort by status, date, amount, recipient, batch | **Verified** — `reporting.test.ts`, and `routes.test.ts` asserts the filter genuinely filters, not merely returns 200 |
| TRK-004 | One-click failed CSV with FailureCode and FailureReason               | **Verified** — `routes.test.ts` asserts the columns over HTTP                                                         |
| TRK-005 | Exports from authoritative records, provider identifiers preserved    | **Verified** — `reporting.test.ts`                                                                                    |
| TRK-006 | Export access role-scoped; every export audited                       | **Verified** — `routes.test.ts` asserts both the policy denial and the audit row                                      |
| TRK-007 | On-demand status refresh, L2/L3                                       | **Verified** — 403 for L1 at the HTTP layer                                                                           |
| TRK-008 | Scheduled sweeps update TIMEOUT and AWAITING_CALLBACK                 | **Implemented** — `reconciliation-worker.ts`; the sweep's provider call is scripted, not live                         |
| TRK-009 | Dictionary versioned and mappable without a deploy                    | **Verified** — administrator override precedence tested                                                               |
| TRK-010 | Full-set export (P2)                                                  | **Partial** — the permission exists; only the failed-transaction export has a handler                                 |

## §7–8 — Authentication and authorization

| Requirement                              | Where                             | Verified                                                                                                        |
| ---------------------------------------- | --------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| No SMS anywhere                          | schema, `routes/auth.ts`          | **Verified** — `check-invariants.sh` fails on an SMS integration or a phone column; the check is tested to fail |
| Argon2id, production parameters          | `services/crypto.ts`              | **Verified** — 98% coverage; OWASP 2024 parameters asserted                                                     |
| WebAuthn mandatory for L2/L3             | `services/auth.ts` `issueSession` | **Verified** — refuses to issue a usable session without it                                                     |
| Cloned-authenticator detection           | `routes/auth.ts`                  | **Implemented** — counter regression raises a CRITICAL security event                                           |
| SPAC PIN, separate credential            | `services/crypto.ts`              | **Verified** — bound to the user id; a stolen hash cannot be tested against another account                     |
| Manifest hashing; any change invalidates | `packages/core/src/manifest.ts`   | **Verified** — 100% coverage, six distinct mutations each move the digest                                       |
| Challenge replay, expiry, user binding   | `manifest.ts`, `authorization.ts` | **Verified** — `manifest.test.ts` and `integration.test.ts`; also a DB trigger                                  |
| Session tokens stored as keyed digests   | `services/crypto.ts`              | **Verified**                                                                                                    |
| Device trust and revocation              | `routes/auth.ts`, schema          | **Implemented** — revocation is checked on every request in `resolveSession`                                    |
| Recovery without SMS                     | `routes/auth.ts`                  | **Implemented** — recovery codes generated and hashed; the redemption flow is not built                         |

## §9 — Daraja integration

| Requirement                                   | Where                                        | Verified                                                                                                                           |
| --------------------------------------------- | -------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| B2C v3, Transaction Status, Account Balance   | `packages/daraja/`                           | **Verified** against a scripted provider (42 tests)                                                                                |
| SecurityCredential, RSA PKCS#1 v1.5           | `security-credential.ts`                     | **Verified** — output decrypted with OpenSSL, including keys parsed from a real X.509 certificate                                  |
| Token lifecycle, concurrent refresh collapsed | `client.ts`                                  | **Verified** — 200 concurrent callers produce one token request                                                                    |
| Idempotency; no blind retry                   | `core/idempotency.ts`, `payment-executor.ts` | **Verified** — a redelivered message after submission reconciles instead of resubmitting; exactly one request reaches the provider |
| Callback validation, replay protection        | `routes/callbacks.ts`                        | **Verified** — forged secret refused indistinguishably; identical re-delivery deduplicated                                         |
| Ambiguous outcomes enter reconciliation       | `payment-executor.ts`                        | **Verified** — a provider timeout opens a case and never resends                                                                   |
| **Live provider**                             | —                                            | **Not verified** — requires Safaricom credentials and a shortcode                                                                  |

## §11 — Risk and the AI boundary

| Requirement                                  | Where                                    | Verified                                                                                                                                    |
| -------------------------------------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Deterministic signals, explainable evidence  | `packages/core/src/risk.ts`              | **Verified** — 90% coverage, deterministic by test                                                                                          |
| Risk gate blocks release until dispositioned | `core/policy.ts`, `authorization.ts`     | **Verified** — both directions in `integration.test.ts`                                                                                     |
| AI is advisory and cannot release            | `routes/ai.ts`, `ai_never_mutates_state` | **Verified** — a CHECK constraint refuses the claim, an invariant check refuses a write in the route group, and the check is tested to fail |
| AI degrades gracefully                       | `routes/ai.ts`                           | **Implemented** — no `AI_API_KEY` returns deterministic findings alone                                                                      |

## §13 — Backups

| ID          | Requirement                                                                | Verified                                                                                                                        |
| ----------- | -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| BAK-001/002 | S3-compatible target; credentials masked and held by the secrets mechanism | **Verified** — `routes.test.ts` asserts no plaintext in any response                                                            |
| BAK-003/004 | On-demand snapshot, asynchronous and observable                            | **Verified** — `backup-restore.test.ts`                                                                                         |
| BAK-005     | Every attempt persisted with a terminal status                             | **Verified** — plus CHECK constraints                                                                                           |
| BAK-006/007 | Schedule and retention                                                     | **Verified** — retention removes the oldest and the objects are genuinely gone from storage                                     |
| BAK-008     | Latest result always visible, failure shown as failure                     | **Verified**                                                                                                                    |
| **Restore** | The snapshot can become a working database                                 | **Verified** — full round-trip with the audit chain verifying, batch totals reconciling and settled-transaction evidence intact |

## §14 — Audit and immutability

| Requirement                       | Where                            | Verified                                                                                                                         |
| --------------------------------- | -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Append-only, tamper-evident       | `core/audit.ts`, `0003` triggers | **Verified** — alteration, deletion and reordering each detected at the exact event                                              |
| Sequence assigned by the database | `seal_audit_event`               | **Verified** — a caller-supplied sequence is ignored                                                                             |
| Secrets never reach the log       | `redactForAudit`                 | **Verified** — recursive redaction at every depth                                                                                |
| All critical actions logged       | every handler                    | **Implemented** — release, approval, export, backup and credential paths are asserted; broader coverage follows handler coverage |

## §20 — Non-functional

| ID           | Requirement                                     | Verified                                                                                                                         |
| ------------ | ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| NFR-SEC-001  | Privileged endpoints deny by default            | **Verified** — HTTP-level 403 assertions                                                                                         |
| NFR-SEC-003  | No secrets in logs, bundles or ordinary columns | **Verified** — `check-invariants.sh`, redaction tests, masked-response test                                                      |
| NFR-REL-002  | Ambiguous outcomes reconcile, never duplicate   | **Verified**                                                                                                                     |
| NFR-DATA-001 | Historical records append-only                  | **Verified** — 45 database assertions                                                                                            |
| NFR-OPS-002  | Status pages responsive at scale                | **Implemented** — server-side pagination and an index per sort column; not load-tested                                           |
| NFR-A11Y-001 | Keyboard navigation, contrast, clear errors     | **Implemented** — focus management, a focus trap on the ceremony, status never by colour alone; not audited with a screen reader |

## §24 — Acceptance criteria

| ID                  | Status          | Evidence                                                                       |
| ------------------- | --------------- | ------------------------------------------------------------------------------ |
| AC-01, AC-02, AC-03 | **Verified**    | Authority separation, at the service and HTTP layers                           |
| AC-04               | **Verified**    | WebAuthn enforced for L2/L3                                                    |
| AC-05               | **Verified**    | Manifest tampering voids an in-flight authorization                            |
| AC-06               | **Verified**    | No SMS path exists, and cannot be added without failing CI                     |
| AC-07               | **Verified**    | Credentials masked; no plaintext in any response                               |
| AC-08               | **Verified**    | Callbacks and ambiguous transactions reconcile safely                          |
| AC-09               | **Verified**    | Audit chain verifies end to end after a release                                |
| AC-10, AC-12, AC-13 | **Verified**    | Backup, retention and result visibility                                        |
| AC-11               | **Implemented** | Schedule fires from cron; not observed over a real 24-hour window              |
| AC-14               | **Implemented** | Report queries exist; export handlers beyond failed transactions are not built |
| AC-15               | **Verified**    | AI cannot bypass the authorization boundary                                    |
| AC-16, AC-17, AC-18 | **Verified**    | Explorer, failure reasons and audited export, over HTTP                        |
| AC-19               | **Verified**    | Executive panels rejected for L1 and L2 at the data API                        |
| AC-20               | **Implemented** | Refresh and sweep paths built; provider call is scripted                       |

---

## Measured, not claimed

```
313 tests                         pnpm test
 45 database assertions           pnpm db:test
 31 source invariants             pnpm check:invariants
63.7% statement coverage overall  pnpm test:coverage
```

Coverage is uneven by design. The modules that decide whether money moves are at or near
complete:

| Module                      | Statements |
| --------------------------- | ---------- |
| `rbac.ts`                   | 100%       |
| `manifest.ts`               | 100%       |
| `batch-state.ts`            | 100%       |
| `policy.ts`                 | 100%       |
| `export-csv.ts`             | 100%       |
| `audit.ts`                  | 98%        |
| `crypto.ts`                 | 99%        |
| `idempotency.ts`            | 97%        |
| `services/authorization.ts` | 88%        |

The shortfall is in analytics, reporting and administration _handlers_, where the queries
are exercised but every branch is not. That is a deliberate allocation of effort, not an
oversight — and it is stated here rather than averaged away.
