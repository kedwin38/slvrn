# Deployment (Railway)

SOLVAREN runs as two Railway services and one database:

| Service        | What it is                                                 | Image                 |
| -------------- | ---------------------------------------------------------- | --------------------- |
| `solvaren-api` | Hono HTTP API, the four queue consumers, and the scheduler | `apps/api/Dockerfile` |
| `solvaren-web` | The console, static, behind nginx                          | `apps/web/Dockerfile` |
| `Postgres`     | System of record, job queue, rate limiter                  | Railway PostgreSQL    |

Object storage is **not** on Railway. Railway has no S3 service, so backups go to any
S3-compatible target you already have — Cloudflare R2, Backblaze B2, AWS S3, or MinIO run
as a fourth Railway service. Spec BAK-001 always required an S3-compatible target, so this
is not a concession.

---

## Order matters

Each step assumes the last one succeeded. The order is chosen so that a mistake is caught
by a failed deploy rather than by a payment.

### 1. PostgreSQL

Add a PostgreSQL service to the project. Railway sets `DATABASE_URL` on services that
reference it; use the **private** URL (`*.railway.internal`) so the database is never
exposed to the public internet (spec 16.1).

Confirm it is private:

```bash
railway variables --service solvaren-api | grep DATABASE_URL
# postgres://...@postgres.railway.internal:5432/railway   ← private, correct
# postgres://...@viaduct.proxy.rlwy.net:12345/railway     ← public, do not use for the app
```

The public proxy URL is fine for `psql` during an incident. It is not fine as the
application's `DATABASE_URL`.

### 2. Object storage

Create a bucket and a scoped key pair. The key needs `PutObject`, `GetObject`,
`HeadObject` and `DeleteObject` on that bucket and nothing else — SOLVAREN never lists
buckets and never touches another prefix.

### 3. Secrets

Generate each one. Do not reuse a value between them; `config.ts` refuses to start if
`SESSION_SIGNING_KEY` and `SECRET_ENCRYPTION_KEY` match, because a leaked session key would
then also decrypt every stored Daraja credential.

```bash
openssl rand -base64 48   # SESSION_SIGNING_KEY
openssl rand -base64 48   # SECRET_ENCRYPTION_KEY
openssl rand -base64 48   # CALLBACK_SHARED_SECRET
```

Set them as Railway variables on `solvaren-api`. They are never committed; the invariant
check fails the build if a secret is assigned a literal value in any Dockerfile,
`railway.json` or workflow file.

### 4. API service variables

| Variable                 | Example                                           | Notes                                                                       |
| ------------------------ | ------------------------------------------------- | --------------------------------------------------------------------------- |
| `DATABASE_URL`           | `${{Postgres.DATABASE_PRIVATE_URL}}`              | **Private** URL — not `DATABASE_URL`, which is the public proxy             |
| `SESSION_SIGNING_KEY`    | _(generated)_                                     | ≥ 32 chars, refused otherwise                                               |
| `SECRET_ENCRYPTION_KEY`  | _(generated)_                                     | ≥ 32 chars, must differ from the above                                      |
| `CALLBACK_SHARED_SECRET` | _(generated)_                                     | Daraja callback authentication (§9.4)                                       |
| `ENVIRONMENT`            | `production`                                      | `development` \| `staging` \| `production`                                  |
| `APP_ORIGIN`             | `https://${{solvaren-web.RAILWAY_PUBLIC_DOMAIN}}` | Must match the console's public URL exactly; the reference keeps it in step |
| `API_BASE_URL`           | `https://api.solvaren.example`                    | Used to build provider callback URLs                                        |
| `WEBAUTHN_RP_ID`         | `${{solvaren-web.RAILWAY_PUBLIC_DOMAIN}}`         | Must equal the `APP_ORIGIN` host or be a registrable parent                 |
| `DARAJA_ENVIRONMENT`     | `sandbox`                                         | `production` is refused unless `ENVIRONMENT=production`                     |
| `S3_ENDPOINT`            | `https://s3.eu-central-003.backblazeb2.com`       |                                                                             |
| `S3_BUCKET`              | `solvaren-backups`                                |                                                                             |
| `S3_REGION`              | `auto`                                            |                                                                             |
| `S3_ACCESS_KEY_ID`       | _(from step 2)_                                   |                                                                             |
| `S3_SECRET_ACCESS_KEY`   | _(from step 2)_                                   |                                                                             |
| `S3_FORCE_PATH_STYLE`    | `false`                                           | `true` for MinIO                                                            |
| `AI_API_KEY`             | _(optional)_                                      | Omit to disable the AI layer entirely                                       |
| `RUN_WORKERS`            | `true`                                            | `false` for a web-only replica                                              |
| `RUN_SCHEDULER`          | `true`                                            | Safe on every replica; advisory-locked                                      |

`PORT` is injected by Railway. Do not set it.

**The config validator is the gate.** Start the service with anything missing, weak, or
internally inconsistent and it exits non-zero with the complete list, before binding a
port. A failed deploy is cheap; a deploy that serves payments with no encryption key is
not.

### 5. Deploy the API

`railway.json` sets `preDeployCommand` to `node scripts/migrate.mjs`, so migrations run
before the new image takes traffic. The migrator takes an advisory lock, so two replicas
released together do not race, and it refuses to run if an already-applied migration file
has been edited.

Verify:

```bash
curl -s https://<api-url>/health          # {"status":"ok"}
curl -s https://<api-url>/health/ready    # {"status":"ready","databaseLatencyMs":N}
```

`/health/ready` reports `degraded` with HTTP 503 if the database is unreachable. It never
echoes the driver's error text, because a connection string can appear in it.

### 6. Deploy the console

The API base URL is inlined at build time by Vite, so it is a **build** variable, not a
runtime one:

```
VITE_API_BASE_URL=https://api.solvaren.example
```

Set it under the service's build variables, then deploy. If `APP_ORIGIN` on the API does
not exactly match the console's public URL, every request fails CORS — that is the single
most common way this deployment goes wrong, and the symptom (every call failing, no useful
error) does not point at the cause.

### 7. First administrator

```bash
railway run --service solvaren-api node scripts/create-user.mjs \
  --organization "Acme Holdings" --email ceo@acme.example --level L3
```

Then enrol a security key immediately. L2 and L3 sessions are refused without WebAuthn, so
an L3 account without a key cannot do anything.

### 8. Daraja

Configure through the console (L3 only). The callback URL must be
`https://<api-url>/integrations/daraja/<organization-id>/...` and must be HTTPS — the
database refuses a plaintext callback URL by CHECK constraint.

### 9. Backup, and then a restore

A backup that has never been restored is a file, not a backup:

```bash
railway run --service solvaren-api node scripts/restore-snapshot.mjs \
  --snapshot /tmp/snapshot.json --database "$SCRATCH_DATABASE_URL"
```

Restore into a scratch database. The script refuses to run against a database that already
holds transactions unless forced. See [the runbook](runbooks/backup-restore.md) for what to
verify afterwards — a restore that loads rows but breaks the audit chain has not worked.

---

## What changed from the Cloudflare deployment

Worth reading if you knew the previous architecture, because two of these are behaviour
changes rather than swaps.

| Was                    | Now                      | Note                                   |
| ---------------------- | ------------------------ | -------------------------------------- |
| Worker `fetch`         | `@hono/node-server`      | Same Hono app, unchanged routes        |
| Hyperdrive             | `postgres.js` pool       | Pool is process-wide; `max: 10`        |
| Cloudflare Queues      | `job_queue` table        | **Stronger**: enqueue is transactional |
| Durable Object limiter | `rate_limit_buckets` row | Correct across replicas                |
| Cron triggers          | In-process timers        | **Needs the advisory lock**; see below |
| R2 binding             | S3 API (SigV4)           | Any S3-compatible target               |
| Secrets Store          | Railway variables        | Validated at boot                      |
| Pages `_headers`       | `apps/web/nginx.conf`    | Asserted by the invariant check        |
| WAF / rate limiting    | Application-level only   | **This is a real loss**; see below     |

### Scheduled jobs need the lock

Cloudflare guaranteed a cron fired once per schedule. Railway does not: every replica runs
every timer. `scheduler.ts` takes `pg_try_advisory_lock` before each run and the losers
return immediately. **If you scale the API past one replica, that lock is the only thing
preventing duplicated reconciliation sweeps**, so do not remove it.

### The edge is gone

There is no WAF, no managed DDoS protection, no Cloudflare Access on `/health/*`, and no
edge rate limiting. What remains is in the application: per-organisation throttling, the
sign-in attempt limits, body-size caps and export limits.

For an internet-facing production deployment, put something in front — Cloudflare in proxy
mode over the Railway domain is the least-change option and keeps the edge controls the
threat model assumes. Until then, the threat model's denial-of-service row is materially
weaker than it was. This is stated in `docs/threat-model.md` rather than left implicit.

---

## Splitting workers from the API

One process runs everything by default. To separate them, deploy the same image twice:

|                 | API replica | Worker replica |
| --------------- | ----------- | -------------- |
| `RUN_WORKERS`   | `false`     | `true`         |
| `RUN_SCHEDULER` | `false`     | `true`         |
| Public domain   | yes         | no             |

Both read the same code and the same database, so this is a deployment decision rather than
a rewrite. The queue is in PostgreSQL, so the worker replica needs no additional service.

---

## Go-live checklist

- [ ] `DATABASE_URL` uses the private `*.railway.internal` host
- [ ] `SESSION_SIGNING_KEY` and `SECRET_ENCRYPTION_KEY` are distinct and freshly generated
- [ ] `APP_ORIGIN` exactly matches the console's public URL
- [ ] `WEBAUTHN_RP_ID` is the `APP_ORIGIN` host or a registrable parent of it
- [ ] `DARAJA_ENVIRONMENT=production` only where `ENVIRONMENT=production`
- [ ] `pnpm verify` passes on the deployed commit (350 tests, 53 DB assertions, 34 invariants)
- [ ] `/health/ready` returns `ready`
- [ ] The first L3 account has a security key enrolled
- [ ] A backup has been taken **and restored into a scratch database**
- [ ] Something is in front of the API providing WAF and DDoS protection
- [ ] Spec §28 open decisions are answered: database region, whether financial data may
      reach the AI provider, RPO/RTO targets
