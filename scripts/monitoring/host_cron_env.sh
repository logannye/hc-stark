#!/usr/bin/env bash
# Run a TinyZKP host cron Python job with the same env file as systemd services.
set -euo pipefail

REPO="${TINYZKP_REPO:-/opt/hc-stark}"
PYTHON="${TINYZKP_PYTHON:-$REPO/.venv/bin/python}"
ENV_FILE="${TINYZKP_ENV_FILE:-$REPO/.env}"

if [ "$#" -lt 1 ]; then
    echo "usage: host_cron_env.sh <python-script> [args...]" >&2
    exit 64
fi

if [ -f "$ENV_FILE" ]; then
    set -a
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    set +a
fi

cd "$REPO"
exec "$PYTHON" "$@"
