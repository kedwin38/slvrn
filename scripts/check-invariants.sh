#!/usr/bin/env bash
#
# Source-level invariant checks.
#
# These assert properties that must hold in the code itself, not only at runtime. Each one
# corresponds to a specification guarantee that a plausible future change could silently
# weaken while every happy-path test still passed.
#
# Run locally with `pnpm check:invariants`; CI runs the same script, so a check that passes
# here passes there. Written as a script rather than inline YAML precisely so it *can* be
# run locally — an unrunnable gate is a gate that gets disabled.
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

failures=0
checks=0

pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; checks=$((checks + 1)); }
fail() { printf '  \033[31m✗\033[0m %s\n' "$1"; failures=$((failures + 1)); checks=$((checks + 1)); }

# Search the project's own source, never dependencies or build output.
sources() {
  find . \
    -path ./node_modules -prune -o \
    -path ./.git -prune -o \
    -path '*/node_modules' -prune -o \
    -path '*/dist' -prune -o \
    -path ./coverage -prune -o \
    -type f \( "$@" \) -print
}

# Capture matches into a variable rather than piping into `head`: a pipeline whose last
# command is `head` exits 0 even when grep found nothing, which silently inverts the test.
matches() {
  local pattern="$1"; shift
  grep -rInE "$pattern" "$@" 2>/dev/null || true
}

echo ""
echo "SOLVAREN source invariants"
echo ""

# ---------------------------------------------------------------------------
echo "No SMS in any authentication path (spec 7.1, AC-06)"
# ---------------------------------------------------------------------------

sms_hits="$(matches '\b(twilio|africastalking|send_?sms|sendSms|smsProvider|otpSms|sms_code)\b' \
  --include='*.ts' --include='*.tsx' --include='*.sql' \
  --exclude-dir=node_modules --exclude-dir=dist .)"
if [ -z "$sms_hits" ]; then
  pass "no SMS integration exists"
else
  fail "an SMS integration was found:"
  echo "$sms_hits" | sed 's/^/      /'
fi

# Match a column *definition*, not prose. The schema comments deliberately mention the
# absence of a phone column, and a check that cannot tell the difference is a check that
# gets switched off.
phone_columns="$(grep -InE '^\s+(phone|phone_number|mobile|msisdn|otp|otp_code|sms_code)\s+(TEXT|VARCHAR|CITEXT|CHAR)' \
  db/migrations/0001_foundation.sql 2>/dev/null || true)"
if [ -z "$phone_columns" ]; then
  pass "no phone, OTP or SMS column on any identity table"
else
  fail "a phone or OTP column was added to an identity table:"
  echo "$phone_columns" | sed 's/^/      /'
fi

# ---------------------------------------------------------------------------
echo ""
echo "The AI layer cannot mutate payment state (spec 11)"
# ---------------------------------------------------------------------------

ai_writes="$(grep -nE '\b(UPDATE|DELETE FROM|INSERT INTO)\b' apps/api/src/routes/ai.ts 2>/dev/null \
  | grep -v 'INSERT INTO ai_interactions' || true)"
if [ -z "$ai_writes" ]; then
  pass "the AI route group performs no write except its own interaction log"
else
  fail "a write to a payment table was found in the AI route group:"
  echo "$ai_writes" | sed 's/^/      /'
fi

if grep -q 'caused_state_change = FALSE' db/migrations/0004_backups_exports.sql; then
  pass "the ai_never_mutates_state constraint is present"
else
  fail "the ai_never_mutates_state constraint is missing"
fi

# ---------------------------------------------------------------------------
echo ""
echo "Historical records are immutable (spec 4.3, 14)"
# ---------------------------------------------------------------------------

for trigger in audit_events_no_update audit_events_no_delete transactions_no_delete \
               transactions_guard_update approvals_no_update approvals_no_delete \
               challenges_no_delete challenges_guard_update instructions_guard_update \
               batches_guard_update; do
  if grep -q "$trigger" db/migrations/0003_audit_immutability.sql; then
    pass "$trigger"
  else
    fail "$trigger is missing"
  fi
done

# ---------------------------------------------------------------------------
echo ""
echo "Payment release requires every gate (spec 7.5)"
# ---------------------------------------------------------------------------

# Matched as a *call*, not as an identifier: grepping for the bare name would be satisfied
# by the import statement alone, so deleting the call and leaving the import would pass.
# (That exact weakness was found by deliberately removing a gate and watching the check
# stay green.)
for gate in assertFreshAuthentication assertWebAuthnSession verifyAuthorizationPin \
            verifyChallengeBinding assertNotSelfAuthorization assertReleasePolicy \
            assertNoDeclaredConflict assertTransition; do
  if grep -qE "(^|[^A-Za-z0-9_.])${gate}\(" apps/api/src/services/authorization.ts; then
    pass "$gate is invoked"
  else
    fail "release gate $gate is imported but never called"
  fi
done

# The state machine's authority check must be given the actor's real permissions, not the
# permission the edge happens to require — that shorthand makes the check vacuous, and it
# is an easy mistake to reintroduce.
vacuous="$(grep -nE "permissions: new Set<Permission>\(\['" \
  apps/api/src/services/authorization.ts apps/api/src/routes/*.ts 2>/dev/null || true)"
if [ -z "$vacuous" ]; then
  pass "authority checks derive permissions from the matrix, not from the call site"
else
  fail "a vacuous permission check was found (it supplies the permission it verifies):"
  echo "$vacuous" | sed 's/^/      /'
fi

# ---------------------------------------------------------------------------
echo ""
echo "No payment is retried into an unknown outcome (spec 9.3)"
# ---------------------------------------------------------------------------

if grep -q 'allowRetry: false' packages/daraja/src/client.ts; then
  pass "B2C submission is never retried by the client"
else
  fail "the B2C no-retry guarantee is missing from the Daraja client"
fi

if grep -q 'RECONCILE_FIRST' packages/core/src/idempotency.ts; then
  pass "a submitted-but-unconfirmed instruction reconciles rather than resubmitting"
else
  fail "the reconcile-before-retry decision is missing"
fi

# ---------------------------------------------------------------------------
echo ""
echo "No credential material in the repository (NFR-SEC-003)"
# ---------------------------------------------------------------------------

# A Daraja SecurityCredential is base64 of a 2048-bit ciphertext — a long unbroken base64
# run. Test fixtures and lockfiles legitimately contain long hashes, so both are excluded.
base64_hits="$(matches '[A-Za-z0-9+/]{200,}={0,2}' \
  --include='*.ts' --include='*.tsx' --include='*.sql' --include='*.toml' --include='*.json' \
  --exclude='*.test.ts' --exclude='pnpm-lock.yaml' --exclude='package-lock.json' \
  --exclude-dir=node_modules --exclude-dir=dist .)"
if [ -z "$base64_hits" ]; then
  pass "no credential-length base64 run outside test fixtures"
else
  fail "a long base64 run was found — if this is a credential, remove it and rotate:"
  echo "$base64_hits" | cut -c1-160 | sed 's/^/      /'
fi

# A connection string with an inline password. CI workflows legitimately reference a
# throwaway local service, so .github is excluded.
dsn_hits="$(matches 'postgres(ql)?://[^:@/]+:[^@/]+@' \
  --include='*.ts' --include='*.toml' --include='*.sh' \
  --exclude='*.test.ts' --exclude='test-harness.ts' \
  --exclude-dir=node_modules --exclude-dir=.github --exclude-dir=dist .)"
if [ -z "$dsn_hits" ]; then
  pass "no PostgreSQL connection string with an embedded password"
else
  fail "a connection string with an embedded password was found:"
  echo "$dsn_hits" | cut -c1-160 | sed 's/^/      /'
fi

# Secrets must be bindings, never values in the Worker configuration.
if grep -qE '^\s*(CONSUMER_SECRET|SECURITY_CREDENTIAL|SESSION_SIGNING_KEY|SECRET_ENCRYPTION_KEY|AI_API_KEY)\s*=' \
     apps/api/wrangler.toml 2>/dev/null; then
  fail "a secret is assigned a value in wrangler.toml; use 'wrangler secret put' instead"
else
  pass "no secret is assigned a value in wrangler.toml"
fi

# ---------------------------------------------------------------------------
echo ""
echo "Sorting cannot reach SQL text (explorer)"
# ---------------------------------------------------------------------------

# The one place user input influences SQL text is the ORDER BY, and it must come from the
# allowlist helper. A template literal building an ORDER BY from a variable would be an
# injection.
order_by_interp="$(grep -rnE 'ORDER BY \$\{(?!orderBy)' apps/api/src --include='*.ts' -P 2>/dev/null || true)"
if [ -z "$order_by_interp" ]; then
  pass "ORDER BY is built only from the allowlist helper"
else
  fail "an ORDER BY is interpolated from something other than buildOrderBy:"
  echo "$order_by_interp" | sed 's/^/      /'
fi

# ---------------------------------------------------------------------------
echo ""
echo "The source tree holds no compiled output"
# ---------------------------------------------------------------------------

# A `tsc` invocation that emits into `src` leaves a .js beside every .ts. Node and the
# bundler will then happily resolve the stale compiled copy instead of the source, so a
# security fix can be edited, committed and reviewed while the build keeps running the old
# code. This happened here: apps/web's typecheck script passed `--noEmit false`.
emitted="$(find packages apps -path '*/node_modules' -prune -o -path '*/dist' -prune -o \
  \( -name '*.js' -o -name '*.d.ts' -o -name '*.js.map' -o -name '*.d.ts.map' \) -print 2>/dev/null \
  | while read -r f; do
      base="$f"
      base="${base%.js}"; base="${base%.d.ts}"
      base="${base%.js.map}"; base="${base%.d.ts.map}"
      if [ -f "$base.ts" ] || [ -f "$base.tsx" ]; then echo "$f"; fi
    done)"
if [ -z "$emitted" ]; then
  pass "no compiled artifact sits beside a TypeScript source"
else
  fail "compiled output found in the source tree (a stale copy can shadow the source):"
  echo "$emitted" | sed 's/^/      /'
fi

# The script that caused it must stay non-emitting.
if grep -qE '"typecheck".*--noEmit false' apps/web/package.json 2>/dev/null; then
  fail "apps/web typecheck forces emission; it must run with --noEmit"
else
  pass "apps/web typecheck does not force emission"
fi

# ---------------------------------------------------------------------------
echo ""
if [ "$failures" -eq 0 ]; then
  printf '\033[32m%d invariants hold.\033[0m\n\n' "$checks"
  exit 0
fi
printf '\033[31m%d of %d invariants FAILED.\033[0m\n\n' "$failures" "$checks"
exit 1
