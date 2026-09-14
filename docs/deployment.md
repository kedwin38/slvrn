# Deployment (Railway)

SOLVAREN runs as two Railway services and one database:

| Service        | What it is                                                 | Image                  |
| -------------- | ---------------------------------------------------------- | ---------------------- |
| `solvaren-api` | Hono HTTP API, the four queue consumers, and the scheduler | `apps/api/Dockerfile`  |
| `solvaren-web` | The console, static, behind nginx                          | `apps/web/Dockerfile`  |
| `Postgres`     | System of record, job queue, rate limiter                  | Railway PostgreSQL     |
| a Bucket       | Encrypted backups                                          | Railway Storage Bucket |

Spec BAK-001 always required an S3-compatible target. Railway's own Buckets are one, so
backups no longer need an outside provider — though any S3-compatible target still works.

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

Railway has native S3-compatible **Buckets**; create one in the same region as the
services. Wire it with variable references (`${{<bucket>.ENDPOINT}}`, `.BUCKET`, `.REGION`,
`.ACCESS_KEY_ID`, `.SECRET_ACCESS_KEY`) rather than copying credentials. `S3_BUCKET` must
be the bucket's `BUCKET` value, not its display name — Railway appends a hash to keep the
real S3 name unique — and `S3_FORCE_PATH_STYLE` is `false`, because buckets are
virtual-hosted style.

With any other provider, create a bucket and a scoped key pair. The key needs `PutObject`,
`GetObject`, `HeadObject` and `DeleteObject` on that bucket and nothing else — SOLVAREN
never lists buckets and never touches another prefix.

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
check fails the build if a secret is assigned a literal value in any Dockerfile or
workflow file.

### 4. API service variables

| Variable                 | Example                                           | Notes                                                                        |
| ------------------------ | ------------------------------------------------- | ---------------------------------------------------------------------------- |
| `DATABASE_URL`           | `${{Postgres.DATABASE_PRIVATE_URL}}`              | **Private** URL — not `DATABASE_URL`, which is the public proxy              |
| `SESSION_SIGNING_KEY`    | _(generated)_                                     | ≥ 32 chars, refused otherwise                                                |
| `SECRET_ENCRYPTION_KEY`  | _(generated)_                                     | ≥ 32 chars, must differ from the above                                       |
| `CALLBACK_SHARED_SECRET` | _(generated)_                                     | Daraja callback authentication (§9.4)                                        |
| `ENVIRONMENT`            | `production`                                      | `development` \| `staging` \| `production`                                   |
| `APP_ORIGIN`             | `https://${{solvaren-web.RAILWAY_PUBLIC_DOMAIN}}` | Must match the console's public URL exactly; the reference keeps it in step  |
| `API_BASE_URL`           | `https://api.solvaren.example`                    | Used to build provider callback URLs                                         |
| `WEBAUTHN_RP_ID`         | `${{solvaren-web.RAILWAY_PUBLIC_DOMAIN}}`         | Must equal the `APP_ORIGIN` host or be a registrable parent                  |
| `DARAJA_ENVIRONMENT`     | `sandbox`                                         | `production` is refused unless `ENVIRONMENT=production`                      |
| `S3_ENDPOINT`            | `${{solvaren-backups.ENDPOINT}}`                  | A Railway Bucket, or any S3-compatible endpoint                              |
| `S3_BUCKET`              | `${{solvaren-backups.BUCKET}}`                    | The `BUCKET` value, **not** the bucket's display name                        |
| `S3_REGION`              | `${{solvaren-backups.REGION}}`                    |                                                                              |
| `S3_ACCESS_KEY_ID`       | `${{solvaren-backups.ACCESS_KEY_ID}}`             |                                                                              |
| `S3_SECRET_ACCESS_KEY`   | `${{solvaren-backups.SECRET_ACCESS_KEY}}`         |                                                                              |
| `S3_FORCE_PATH_STYLE`    | `false`                                           | Railway Buckets are virtual-hosted style; `true` only for path-style targets |
| `AI_API_KEY`             | _(optional)_                                      | Omit to disable the AI layer entirely                                        |
| `RUN_WORKERS`            | `true`                                            | `false` for a web-only replica                                               |
| `RUN_SCHEDULER`          | `true`                                            | Safe on every replica; advisory-locked                                       |

`PORT` is injected by Railway. Do not set it.

**The config validator is the gate.** Start the service with anything missing, weak, or
internally inconsistent and it exits non-zero with the complete list, before binding a
port. A failed deploy is cheap; a deploy that serves payments with no encryption key is
not.

### 5. Deploy the API

The service's **pre-deploy command** is `node scripts/predeploy.mjs`, which migrates, then
optionally seeds, then checks the deployment that is still live. Migrations run before the
new image takes traffic; the migrator takes an advisory lock, so two replicas released
together do not race, and it refuses to run if an already-applied migration file has been
edited.

Set it in the service's deploy settings. Railway's config-as-code (`railway.json`,
`railway.toml`) is **deprecated and is not read**, so a committed config file will be
silently ignored — the repo used to carry one, and every setting in it was inert. Its
replacement is [Infrastructure as Code](https://docs.railway.com/infrastructure-as-code)
(`.railway/railway.ts`), applied with the Railway CLI.

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

Set it under the service's build variables, then deploy. **Changing it requires a rebuild,
not a restart** — the value is compiled into the JavaScript.

The build now refuses to run without it. That is deliberate: an unconfigured bundle called
the console's own origin, the static server answered with `index.html` or a 405, and the
first anyone knew of it was an operator who could not sign in.

This value does one more thing than name an address. The console ships a `default-src
'none'` CSP with `connect-src 'self'`, and the API is a different origin, so the build
appends exactly this URL's origin to `connect-src`. Get it wrong and the browser blocks
every API call _before it reaches the network_, which looks identical to the API being
down — no request in the API's logs, no CORS message, just a failure to connect. Check it
after deploying:

```bash
curl -s https://<console-url>/ | grep -o "connect-src[^;]*"
# connect-src 'self' https://api.solvaren.example
```

Then confirm the other direction: if `APP_ORIGIN` on the API does not exactly match the
console's public URL, every request fails CORS instead. The two settings are a pair — the
CSP decides whether the browser will send the request, `APP_ORIGIN` decides whether the API
will accept it, and both symptoms look like an outage.

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
- [ ] `VITE_API_BASE_URL` was set **at build time** and the console was rebuilt after it changed
- [ ] The deployed console's `connect-src` names the API's origin (see step 6)
- [ ] `WEBAUTHN_RP_ID` is the `APP_ORIGIN` host or a registrable parent of it
- [ ] `DARAJA_ENVIRONMENT=production` only where `ENVIRONMENT=production`
- [ ] `pnpm verify` passes on the deployed commit (350 tests, 53 DB assertions, 34 invariants)
- [ ] `/health/ready` returns `ready`
- [ ] The first L3 account has a security key enrolled
- [ ] A backup has been taken **and restored into a scratch database**
- [ ] Something is in front of the API providing WAF and DDoS protection
- [ ] Spec §28 open decisions are answered: database region, whether financial data may
      reach the AI provider, RPO/RTO targets
