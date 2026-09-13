#!/usr/bin/env bash
#
# Start a local PostgreSQL for the integration suite and the database assertions.
#
# The integration tests need a real server, not a mock: the guarantees under test are
# enforced by triggers and constraints, so a fake database would prove nothing.
#
#   scripts/dev-postgres.sh start   # initialise and start on port 5433
#   scripts/dev-postgres.sh stop
#   scripts/dev-postgres.sh status
#
set -euo pipefail

PORT="${SOLVAREN_PG_PORT:-5433}"
DATA="${SOLVAREN_PG_DATA:-/var/tmp/solvaren-pgdata}"
PGBIN="${SOLVAREN_PG_BIN:-$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1)}"

if [ -z "${PGBIN}" ] || [ ! -x "${PGBIN}/pg_ctl" ]; then
    echo "PostgreSQL server binaries not found. Install postgresql, or set SOLVAREN_PG_BIN." >&2
    exit 1
fi

case "${1:-start}" in
  start)
    if [ ! -d "${DATA}/base" ]; then
        echo "==> Initialising cluster at ${DATA}"
        mkdir -p "${DATA}"
        # initdb refuses to run as root, so use an unprivileged account when we are root.
        if [ "$(id -u)" -eq 0 ]; then
            id pgtest >/dev/null 2>&1 || useradd -m pgtest
            chown -R pgtest "${DATA}"
            su pgtest -c "${PGBIN}/initdb -D ${DATA} -U postgres --auth=trust" >/dev/null
        else
            "${PGBIN}/initdb" -D "${DATA}" -U postgres --auth=trust >/dev/null
        fi
    fi

    echo "==> Starting on port ${PORT}"
    if [ "$(id -u)" -eq 0 ]; then
        su pgtest -c "${PGBIN}/pg_ctl -D ${DATA} -o '-p ${PORT} -k /tmp' -l /tmp/solvaren-pg.log start" || true
    else
        "${PGBIN}/pg_ctl" -D "${DATA}" -o "-p ${PORT} -k /tmp" -l /tmp/solvaren-pg.log start || true
    fi

    for _ in $(seq 1 20); do
        if "${PGBIN}/pg_isready" -h localhost -p "${PORT}" >/dev/null 2>&1; then
            echo ""
            echo "PostgreSQL is ready. Export this before running the integration suite:"
            echo ""
            echo "    export SOLVAREN_TEST_DATABASE_URL=postgres://postgres@localhost:${PORT}/postgres"
            echo ""
            exit 0
        fi
        sleep 0.5
    done
    echo "PostgreSQL did not become ready; see /tmp/solvaren-pg.log" >&2
    exit 1
    ;;
  stop)
    if [ "$(id -u)" -eq 0 ]; then
        su pgtest -c "${PGBIN}/pg_ctl -D ${DATA} stop" || true
    else
        "${PGBIN}/pg_ctl" -D "${DATA}" stop || true
    fi
    ;;
  status)
    "${PGBIN}/pg_isready" -h localhost -p "${PORT}"
    ;;
  *)
    echo "Usage: $0 {start|stop|status}" >&2
    exit 1
    ;;
esac
