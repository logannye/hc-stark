#!/usr/bin/env bash
# Verify that production growth metrics read the real host stores and persist
# non-repo daily snapshots. Intended to run on the production host after deploy.
set -euo pipefail

REPO="${TINYZKP_REPO:-/opt/hc-stark}"
PYTHON="${TINYZKP_PYTHON:-/var/lib/tinyzkp-runtime/billing-venv/bin/python}"
ENV_FILE="${TINYZKP_ENV_FILE:-$REPO/.env}"
RUN_CRON="${TINYZKP_VERIFY_GROWTH_RUN_CRON:-1}"

if [ -f "$ENV_FILE" ]; then
    set -a
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    set +a
fi

cd "$REPO"

TENANT_DB="${HC_TENANT_STORE_PATH:-$REPO/data/tenant_store.sqlite}"
USAGE_DB="${HC_USAGE_DB_PATH:-$REPO/data/usage.sqlite}"
SNAPSHOT_DIR="${TINYZKP_GROWTH_SNAPSHOT_DIR:-$REPO/data/growth_snapshots}"
EXPERIMENT_LEDGER="${TINYZKP_GROWTH_EXPERIMENT_LEDGER:-$REPO/data/growth_experiment_ledger.json}"

require_file() {
    label="$1"
    path="$2"
    if [ ! -s "$path" ]; then
        echo "FAIL $label missing or empty: $path" >&2
        exit 1
    fi
}

require_file "tenant store" "$TENANT_DB"
require_file "usage store" "$USAGE_DB"
mkdir -p "$SNAPSHOT_DIR"

monitor_json="$(mktemp -t tinyzkp-growth-monitor.XXXXXX)"
cron_log="$(mktemp -t tinyzkp-growth-cron.XXXXXX)"
cleanup() {
    rm -f "$monitor_json" "$cron_log"
}
trap cleanup EXIT

"$PYTHON" scripts/monitoring/gtm_growth_monitor.py \
    --offline \
    --tenant-db "$TENANT_DB" \
    --usage-db "$USAGE_DB" \
    --json > "$monitor_json"

"$PYTHON" - "$monitor_json" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
revenue = payload.get("revenue") or {}
missing = []
if not revenue.get("tenant_db_exists"):
    missing.append("tenant_store.sqlite")
if not revenue.get("usage_db_exists"):
    missing.append("usage.sqlite")
if missing:
    print("FAIL growth monitor did not load: " + ", ".join(missing), file=sys.stderr)
    sys.exit(1)
failed = [
    f"{check.get('category')}: {check.get('name')} - {check.get('detail')}"
    for check in payload.get("checks", [])
    if check.get("status") == "FAIL"
]
if failed:
    print("FAIL growth monitor reported failures:", file=sys.stderr)
    for item in failed:
        print("  " + item, file=sys.stderr)
    sys.exit(1)
PY

bash -n scripts/monitoring/daily_growth_decision_cron.sh

if [ "$RUN_CRON" = "1" ] || [ "$RUN_CRON" = "true" ]; then
    TINYZKP_REPO="$REPO" \
    TINYZKP_PYTHON="$PYTHON" \
    TINYZKP_ENV_FILE="$ENV_FILE" \
    TINYZKP_GROWTH_SNAPSHOT_DIR="$SNAPSHOT_DIR" \
    TINYZKP_GROWTH_EXPERIMENT_LEDGER="$EXPERIMENT_LEDGER" \
        bash scripts/monitoring/daily_growth_decision_cron.sh | tee "$cron_log"

    if ! grep -q "daily_growth_decision_redaction_scan=ok" "$cron_log"; then
        echo "FAIL daily growth cron did not report redaction scan success" >&2
        exit 1
    fi

    latest_snapshot="$(find "$SNAPSHOT_DIR" -maxdepth 1 -type f -name '*.json' -print 2>/dev/null | sort | tail -n 1 || true)"
    require_file "latest growth snapshot" "$latest_snapshot"
    require_file "growth experiment ledger" "$EXPERIMENT_LEDGER"
fi

echo "growth_data_wiring=ok"
