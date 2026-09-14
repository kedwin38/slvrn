# Brief for the Railway agent

Paste the block below into Railway's agent. It is written to be executed without further
questions, and it front-loads the two things that otherwise cause a crash loop: the object
storage credentials (the app refuses to boot without them) and the per-service build and
deploy settings, which must be set on the service because railway.json is deprecated and
no longer read.

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
     - set the Dockerfile path explicitly, per service:
         solvaren-api  ->  apps/api/Dockerfile
         solvaren-web  ->  apps/web/Dockerfile
     - set the deploy settings listed in each step below IN THE SERVICE
       SETTINGS. There is no config file to point at: railway.json is
       deprecated and is NOT read, so anything it once declared has to be set
       on the service itself.
   If you set Root Directory to the app folder, the Docker build fails because
   it cannot see packages/ or pnpm-lock.yaml.

================================================================
STEP 1 — PostgreSQL
================================================================

Add a PostgreSQL database to the project. Name it "Postgres".

Nothing else to configure. The app creates its own schema via the pre-deploy
command set on solvaren-api in Step 2.

================================================================
STEP 2 — Service "solvaren-api"
================================================================

Source:            GitHub repo above, branch claude/zen-mendel-n0d4x1
Root Directory:    /
Builder:           Dockerfile
Dockerfile path:   apps/api/Dockerfile

Deploy settings (set these on the service; there is no config file):
  Pre-deploy command:  node scripts/predeploy.mjs
  Healthcheck path:    /health
  Healthcheck timeout: 30
  Restart policy:      ON_FAILURE, max 5 retries

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
Builder:           Dockerfile
Dockerfile path:   apps/web/Dockerfile

Deploy settings (set these on the service; there is no config file):
  Healthcheck path:    /healthz
  Healthcheck timeout: 30
  Restart policy:      ON_FAILURE, max 5 retries

Generate a public domain for this service.

Set ONE variable:

  VITE_API_BASE_URL = https://${{solvaren-api.RAILWAY_PUBLIC_DOMAIN}}

This is consumed at BUILD time (Vite inlines it into the bundle) and the
Dockerfile declares it as an ARG. It must be available to the build, not only
to the runtime. If your build does not pass service variables through as Docker
build args, pass it explicitly as --build-arg VITE_API_BASE_URL=...

Changing this value requires a REBUILD, not a restart.

The build FAILS if this is missing, by design, with a message naming it. If the
console build stops with "VITE_API_BASE_URL is not set", that is this variable
not reaching the build step — not a code error. Do not work around it by
editing the app.

This value also drives the console's Content-Security-Policy. The console ships
default-src 'none' with connect-src 'self', and the API is a different origin,
so the build appends this URL's origin to connect-src. If it is wrong, the
browser refuses every API call BEFORE sending it: nothing appears in the API's
logs, and the console reports only that it could not connect. After deploying,
confirm the policy actually names the API:

  curl -s https://<solvaren-web domain>/ | grep -o "connect-src[^;]*"
    expect: connect-src 'self' https://<solvaren-api domain>

================================================================
STEP 4 — Object storage (REQUIRED; the API will not boot without it)
================================================================

The app needs S3-compatible storage for encrypted backups and refuses to boot
without it.

OPTION A (PREFERRED — Railway's own object storage):
  Railway now has native S3-compatible Buckets. Create one in the SAME REGION
  as the services and name it "solvaren-backups". No extra service, no volume,
  no image pull.

  Wire it with variable references, so credentials are never copied by hand:
    S3_ENDPOINT          = ${{solvaren-backups.ENDPOINT}}
    S3_BUCKET            = ${{solvaren-backups.BUCKET}}
    S3_REGION            = ${{solvaren-backups.REGION}}
    S3_ACCESS_KEY_ID     = ${{solvaren-backups.ACCESS_KEY_ID}}
    S3_SECRET_ACCESS_KEY = ${{solvaren-backups.SECRET_ACCESS_KEY}}
    S3_FORCE_PATH_STYLE  = false

  Note S3_BUCKET must be the bucket's BUCKET value, not its display name:
  Railway appends a hash to keep the real S3 name globally unique. Buckets are
  virtual-hosted style, which is why S3_FORCE_PATH_STYLE is false.

OPTION B (an external provider, e.g. Cloudflare R2 or Backblaze B2):
  Create a bucket and a key pair scoped to it with PutObject, GetObject,
  HeadObject and DeleteObject and nothing else. Then set the same six
  variables with that provider's endpoint, bucket, region and credentials.

DO NOT run MinIO for this. It was tried here and cost an afternoon: the image
tag must be an exact `RELEASE.*` string (`latest` and date-like tags such as
`2024.10.02` do not exist and fail with "could not be pulled from the
registry"), anonymous Docker Hub pulls are rate-limited, and it needs a volume
and a service of its own to do what Option A does with none.

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

  curl -s https://<solvaren-web domain>/ | grep -o "connect-src[^;]*"
    expect: connect-src 'self' https://<solvaren-api domain>
    if it reads just "connect-src 'self'", VITE_API_BASE_URL did not reach the
    console BUILD. Sign-in will fail with a generic connection error and the
    API will log nothing at all, because the browser blocks the request before
    sending it. Fix the build variable and REBUILD the console.

  Then actually sign in. A page that renders proves nothing: the console is
  static, so it renders fine with no working API whatsoever.

In the API deploy logs you should see, as JSON lines:
  "Queue workers started"     with four queues listed
  "Scheduler started"
  "SOLVAREN API listening"

If you see "SOLVAREN cannot start: the environment is not valid", the log lists
exactly which variables are wrong. Fix those specific ones.

READING A STARTUP FAILURE: if the BUILD log ends normally (image pushed) and
the deploy shows only

    Starting Container
    Stopping Container

a second or two apart, the build is fine and the process exited on purpose.
That is the config validator. Its output is in the DEPLOY log, not the build
log — look there, not at the build output. A crash loop with no message at all
would be something else; a clean two-second exit is nearly always a missing or
invalid variable.

================================================================
DO NOT
================================================================

- Do not set PORT on either service.
- Do not put any secret value into a Dockerfile or any other committed file. Secrets are Railway variables only. The repo's CI fails the build if a
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

That account cannot sign in yet — L2 and L3 need a WebAuthn key, and enrolling one
normally needs a session. Issue a single-use enrolment token:

```bash
railway run --service solvaren-api node scripts/issue-enrolment-token.mjs \
  --email you@example.com
```

Then use **Enrol a security key** on the sign-in page with the email, password and token.
Enrol two keys for an L3: it is the only level that can release a payment.

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
