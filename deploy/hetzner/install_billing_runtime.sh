#!/usr/bin/env bash
# Install/update the host-level billing webhook Python runtime.
#
# The billing webhook is intentionally a host systemd unit, not a Compose
# service. Keep its dependencies isolated from the OS Python so Debian/Ubuntu
# PEP 668 protections cannot silently break deploys.
set -euo pipefail

REPO="${HC_STARK_REPO:-/opt/hc-stark}"
VENV="${HC_BILLING_VENV:-$REPO/.venv}"
REQ="$REPO/billing/requirements.txt"

if [ ! -d "$REPO" ]; then
    echo "ERROR: repo directory not found: $REPO" >&2
    exit 1
fi

if [ ! -f "$REQ" ]; then
    echo "ERROR: billing requirements file not found: $REQ" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1 && [ "$(id -u)" -eq 0 ]; then
        apt-get update -qq
        apt-get install -y -qq python3 python3-venv
    else
        echo "ERROR: python3 is required to install the billing runtime" >&2
        exit 1
    fi
fi

if ! python3 -m venv --help >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1 && [ "$(id -u)" -eq 0 ]; then
        apt-get update -qq
        apt-get install -y -qq python3-venv
    else
        echo "ERROR: python3-venv is required to install the billing runtime" >&2
        exit 1
    fi
fi

python3 -m venv "$VENV"
"$VENV/bin/python" -m pip install --quiet --upgrade pip
"$VENV/bin/python" -m pip install --quiet -r "$REQ"

"$VENV/bin/python" - <<'PY'
import flask
import gunicorn
import psycopg
import stripe

print("billing runtime OK")
PY
