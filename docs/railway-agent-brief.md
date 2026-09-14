# Brief for the Railway agent

Paste the block below into Railway's agent. It is written to be executed without further
questions, and it front-loads the two things that otherwise cause a crash loop: the object
storage credentials (the app refuses to boot without them) and the config-file path for
each service.

---

```
Deploy a two-service app plus a database from this GitHub repo.

REPO:   kedwin38/slvrn
BRANCH: claude/zen-mendel-n0d4x1

Create everything in one new project called "solvaren".

================================================================
READ THIS FIRST — the two things that will otherwise fail
================================================================

1. The API validates its entire environment at boot and EXITS if anything is
   missing, weak, or inconsistent. It will not start half-configured. If the
   deploy crash-loops, read the logs: it prints the complete list of problems
   in plain English. Fix those; do not retry blindly.

2. Both services build from Dockerfiles that COPY from the REPO ROOT.
   For each service you MUST:
     - leave Root Directory as "/" (do NOT set it to apps/api or apps/web)
     - set the config-as-code file path explicitly, per service:
         solvaren-api  ->  apps/api/railway.json
         solvaren-web  ->  apps/web/railway.json
   If you set Root Directory to the app folder, the Docker build fails because
   it cannot see packages/ or pnpm-lock.yaml.

================================================================
STEP 1 — PostgreSQL
================================================================

Add a PostgreSQL database to the project. Name it "Postgres".

Nothing else to configure. The app creates its own schema via a pre-deploy
migration command (already declared in apps/api/railway.json).

================================================================
STEP 2 — Service "solvaren-api"
================================================================

Source:            GitHub repo above, branch claude/zen-mendel-n0d4x1
Root Directory:    /
Config file path:  apps/api/railway.json
Builder:           Dockerfile (declared in the config file)

Generate a public domain for this service.

Set these variables. Use Railway's reference syntax exactly as written for the
three that reference other services:

  DATABASE_URL            = ${{Postgres.DATABASE_PRIVATE_URL}}
  APP_ORIGIN              = https://${{solvaren-web.RAILWAY_PUBLIC_DOMAIN}}
  API_BASE_URL            = https://${{RAILWAY_PUBLIC_DOMAIN}}
  WEBAUTHN_RP_ID          = ${{solvaren-web.RAILWAY_PUBLIC_DOMAIN}}

  ENVIRONMENT             = staging
  DARAJA_ENVIRONMENT      = sandbox

  SESSION_SIGNING_KEY     = <<GENERATE: 48 random bytes, base64>>
  SECRET_ENCRYPTION_KEY   = <<GENERATE: 48 random bytes, base64, MUST DIFFER from the above>>
  CALLBACK_SHARED_SECRET  = <<GENERATE: 48 random bytes, base64>>

  S3_ENDPOINT             = <<from Step 4>>
  S3_BUCKET               = <<from Step 4>>
  S3_REGION               = auto
  S3_ACCESS_KEY_ID        = <<from Step 4>>
  S3_SECRET_ACCESS_KEY    = <<from Step 4>>
  S3_FORCE_PATH_STYLE     = false

  RUN_WORKERS             = true
  RUN_SCHEDULER           = true

IMPORTANT about DATABASE_URL: use DATABASE_PRIVATE_URL, not DATABASE_URL.
Railway's plain DATABASE_URL is the public TCP proxy; routing a payment
database over the public internet when a private network exists is wrong, and
it is also slower and metered.

IMPORTANT about the three generated keys: they must each be at least 32
characters, and SESSION_SIGNING_KEY and SECRET_ENCRYPTION_KEY must NOT be the
same value. The app refuses to start otherwise, on purpose — one value for both
would mean a leaked session key also decrypts every stored payment credential.
Do not use a memorable placeholder; values like "changeme" or "secret" are
explicitly rejected.

Do NOT set PORT. Railway injects it and the app reads it.

================================================================
STEP 3 — Service "solvaren-web"
================================================================

Source:            same repo and branch
Root Directory:    /
Config file path:  apps/web/railway.json
Builder:           Dockerfile

Generate a public domain for this service.

Set ONE variable:

  VITE_API_BASE_URL = https://${{solvaren-api.RAILWAY_PUBLIC_DOMAIN}}

This is consumed at BUILD time (Vite inlines it into the bundle) and the
Dockerfile declares it as an ARG. It must be available to the build, not only
to the runtime. If your build does not pass service variables through as Docker
build args, pass it explicitly as --build-arg VITE_API_BASE_URL=...

Changing this value requires a REBUILD, not a restart.

================================================================
STEP 4 — Object storage (REQUIRED; the API will not boot without it)
================================================================

Railway has no S3 service, and the app needs one for encrypted backups.
Pick ONE of these.

OPTION A (preferred if the user already has Cloudflare R2):
  The user's Cloudflare account id is c3807a0785783519c7b9c174ede659ef.
  Ask them to create an R2 bucket named "solvaren-backups" and an R2 API token
  scoped to that bucket with read+write. Then:
    S3_ENDPOINT          = https://c3807a0785783519c7b9c174ede659ef.r2.cloudflarestorage.com
    S3_BUCKET            = solvaren-backups
    S3_REGION            = auto
    S3_ACCESS_KEY_ID     = <R2 access key id>
    S3_SECRET_ACCESS_KEY = <R2 secret access key>
    S3_FORCE_PATH_STYLE  = false

OPTION B (everything inside Railway):
  Deploy MinIO as a third service in this project, from image
  minio/minio:latest, command: server /data --console-address ":9001"
  Give it a volume mounted at /data and set MINIO_ROOT_USER and
  MINIO_ROOT_PASSWORD. Create a bucket "solvaren-backups". Then:
    S3_ENDPOINT          = http://minio.railway.internal:9000
    S3_BUCKET            = solvaren-backups
    S3_REGION            = us-east-1
    S3_ACCESS_KEY_ID     = <MINIO_ROOT_USER>
    S3_SECRET_ACCESS_KEY = <MINIO_ROOT_PASSWORD>
    S3_FORCE_PATH_STYLE  = true      <-- MinIO requires path-style; this matters

  Note for Option B: that endpoint is http:// on Railway's private network,
  which the config validator allows for ENVIRONMENT=staging but REFUSES for
  ENVIRONMENT=production. If this ever moves to ENVIRONMENT=production, MinIO
  needs TLS or the storage moves to Option A.

Whichever you pick, fill the S3_* variables on solvaren-api from Step 2.

================================================================
STEP 5 — Deploy and verify
================================================================

Deploy solvaren-api first, then solvaren-web.

The API runs "node scripts/migrate.mjs" as a pre-deploy command. On the first
deploy this creates the whole schema (8 migrations). It is safe to re-run: each
migration is applied at most once, under an advisory lock so concurrent deploys
cannot race.

Verify, and report the actual output of each:

  curl https://<solvaren-api domain>/health
    expect: {"status":"ok"}

  curl https://<solvaren-api domain>/health/ready
    expect: {"status":"ready","databaseLatencyMs":<n>}
    a 503 with "database unreachable" means DATABASE_URL is wrong

  curl -o /dev/null -w "%{http_code}" https://<solvaren-api domain>/batches
    expect: 401   (this endpoint requires a session; 401 is correct and proves
                   the auth layer is active)

  open https://<solvaren-web domain>
    expect: the SOLVAREN sign-in page renders

In the API deploy logs you should see, as JSON lines:
  "Queue workers started"     with four queues listed
  "Scheduler started"
  "SOLVAREN API listening"

If you see "SOLVAREN cannot start: the environment is not valid", the log lists
exactly which variables are wrong. Fix those specific ones.

================================================================
DO NOT
================================================================

- Do not set PORT on either service.
- Do not put any secret value into railway.json, a Dockerfile, or any committed
  file. Secrets are Railway variables only. The repo's CI fails the build if a
  secret literal appears in a deployment manifest.
- Do not set ENVIRONMENT=production together with DARAJA_ENVIRONMENT=production
  unless the user explicitly asks. That combination configures the system to
  move real money through M-PESA, and this build has never been tested against
  a real shortcode.
- Do not scale solvaren-api above 1 replica yet without telling the user. The
  app is designed for it (scheduled jobs take advisory locks, the rate limiter
  is in Postgres), but nothing has been load-tested.
- Do not modify application code. If something does not build, report the error.

================================================================
REPORT BACK
================================================================

Tell the user:
  - both public URLs
  - the output of the three curl checks above
  - which object-storage option was used
  - anything you could not complete and why
```

---

## After the agent finishes

Two things the agent cannot do for you.

**Create the first account.** There is no sign-up flow — that is deliberate for a
disbursement platform.

```bash
railway run --service solvaren-api node scripts/create-user.mjs \
  --organization "Your Company" --email you@example.com --level L3
```

Then enrol a security key immediately: L2 and L3 sessions are refused without WebAuthn, so
an L3 account without a key can do nothing.

**Put something in front of the API.** There is no WAF, no managed DDoS protection and no
rate limiting at the edge — that all came from Cloudflare and did not survive the move.
Everything protecting the service now is application-level, which means an attacker can
exhaust the process before any of it applies. `docs/threat-model.md` records this as an
accepted gap rather than pretending otherwise.

## A note on WebAuthn and railway.app domains

`WEBAUTHN_RP_ID` is set to the console's full Railway hostname, which works. But a
passkey is bound to the RP ID, so **every enrolled key stops working if that hostname
changes** — which it does if you rename the service or move to a custom domain. Enrol
throwaway keys until the final domain is set, then re-enrol.
