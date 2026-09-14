#!/usr/bin/env bash
#
# Run the SOLVAREN database security assertions against a disposable PostgreSQL database.
#
# The database is dropped and recreated on every run, deliberately: the schema's own
# immutability triggers make audit_events and transactions impossible to clean up in place,
# which is exactly the property being tested. A test suite that could tidy up after itself
# would prove the guarantee does not hold.
#
# Usage:  scripts/db-test.sh [PGHOST] [PGPORT] [PGUSER]
set -euo pipefail

HOST="${1:-${PGHOST:-/tmp}}"
PORT="${2:-${PGPORT:-5433}}"
USER="${3:-${PGUSER:-postgres}}"
DB="${SOLVAREN_TEST_DB:-solvaren_test}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PSQL=(psql -h "$HOST" -p "$PORT" -U "$USER" -v ON_ERROR_STOP=1 --quiet)

echo "==> Recreating $DB on $HOST:$PORT"
"${PSQL[@]}" -d postgres -c "DROP DATABASE IF EXISTS $DB WITH (FORCE);" >/dev/null
"${PSQL[@]}" -d postgres -c "CREATE DATABASE $DB;" >/dev/null

echo "==> Applying migrations"
for migration in "$ROOT"/db/migrations/*.sql; do
    printf '    %s\n' "$(basename "$migration")"
    "${PSQL[@]}" -d "$DB" -f "$migration" >/dev/null
done

echo "==> Running security assertions"
output="$("${PSQL[@]}" -d "$DB" -f "$ROOT/db/tests/immutability.sql" 2>&1)" || {
    echo "$output" | grep -E 'FAIL|INCONCLUSIVE|ERROR' || echo "$output" | tail -20
    echo ""
    echo "DATABASE SECURITY ASSERTIONS FAILED"
    exit 1
}

echo "$output" | grep -E 'NOTICE:  (PASS|FAIL)' | sed -E 's/^psql:[^ ]+ NOTICE:  /    /'
passed="$(echo "$output" | grep -c 'NOTICE:  PASS' || true)"
echo ""
echo "==> $passed database security assertions passed"
