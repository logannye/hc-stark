#!/usr/bin/env bash
# Production cron wrapper for the daily TinyZKP growth decision memo.
#
# The base memo always runs from production tenant/usage stores. Stripe Checkout
# metrics are included only when the host explicitly configures either the
# LN Holdings API-key validation path or a TinyZKP Stripe CLI profile.
set -euo pipefail

REPO="${TINYZKP_REPO:-/opt/hc-stark}"
PYTHON="${TINYZKP_PYTHON:-/var/lib/tinyzkp-runtime/billing-venv/bin/python}"
SNAPSHOT_DIR="${TINYZKP_GROWTH_SNAPSHOT_DIR:-$REPO/data/growth_snapshots}"
EXPERIMENT_LEDGER="${TINYZKP_GROWTH_EXPERIMENT_LEDGER:-$REPO/data/growth_experiment_ledger.json}"
ENV_FILE="${TINYZKP_ENV_FILE:-$REPO/.env}"

if [ -f "$ENV_FILE" ]; then
    set -a
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    set +a
fi

cd "$REPO"
TENANT_DB="${HC_TENANT_STORE_PATH:-$REPO/data/tenant_store.sqlite}"
USAGE_DB="${HC_USAGE_DB_PATH:-$REPO/data/usage.sqlite}"

require_growth_store() {
    label="$1"
    path="$2"
    if [ ! -s "$path" ]; then
        echo "ERROR: production growth data store missing or empty: $label ($path)" >&2
        echo "Run scripts/monitoring/verify_growth_data_wiring.sh on the production host after deploy." >&2
        exit 1
    fi
}

require_growth_store "tenant store" "$TENANT_DB"
require_growth_store "usage store" "$USAGE_DB"
mkdir -p "$SNAPSHOT_DIR"

args=(
    scripts/monitoring/daily_growth_decision.py
    --tenant-db "$TENANT_DB"
    --usage-db "$USAGE_DB"
    --snapshot-dir "$SNAPSHOT_DIR"
    --experiment-ledger "$EXPERIMENT_LEDGER"
)

stripe_profile="${TINYZKP_GROWTH_STRIPE_PROJECT_NAME:-${TINYZKP_STRIPE_PROJECT_NAME:-}}"
stripe_checkout="${TINYZKP_GROWTH_STRIPE_CHECKOUT:-}"
stripe_account_source="${TINYZKP_GROWTH_STRIPE_ACCOUNT_SOURCE:-${TINYZKP_STRIPE_ACCOUNT_SOURCE:-cli}}"
stripe_api_key_env="${TINYZKP_GROWTH_STRIPE_API_KEY_ENV:-${TINYZKP_STRIPE_API_KEY_ENV:-STRIPE_SECRET_KEY}}"
if [ "$stripe_checkout" = "1" ] || [ "$stripe_checkout" = "true" ]; then
    if [ "$stripe_account_source" = "api" ]; then
        args+=(
            --stripe-checkout
            --stripe-account-source api
            --stripe-api-key-env "$stripe_api_key_env"
            --stripe-expected-display-name "${TINYZKP_STRIPE_EXPECTED_DISPLAY_NAME:-LN Holdings}"
        )
    elif [ -n "$stripe_profile" ]; then
        args+=(
            --stripe-checkout
            --stripe-bin "${TINYZKP_STRIPE_BIN:-stripe}"
            --stripe-project-name "$stripe_profile"
            --stripe-account-source cli
            --stripe-expected-display-name "${TINYZKP_STRIPE_EXPECTED_DISPLAY_NAME:-LN Holdings}"
        )
    else
        echo "ERROR: TINYZKP_GROWTH_STRIPE_CHECKOUT is enabled but no trusted Stripe account source is configured." >&2
        echo "Set TINYZKP_GROWTH_STRIPE_ACCOUNT_SOURCE=api with TINYZKP_GROWTH_STRIPE_API_KEY_ENV=STRIPE_SECRET_KEY after API account validation passes," >&2
        echo "or set TINYZKP_GROWTH_STRIPE_PROJECT_NAME after billing/stripe_account_context_check.py verifies the LN Holdings CLI profile." >&2
        exit 1
    fi
elif [ -n "$stripe_profile" ]; then
    args+=(
        --stripe-checkout
        --stripe-bin "${TINYZKP_STRIPE_BIN:-stripe}"
        --stripe-project-name "$stripe_profile"
        --stripe-account-source cli
        --stripe-expected-display-name "${TINYZKP_STRIPE_EXPECTED_DISPLAY_NAME:-LN Holdings}"
    )
fi

memo_file="$(mktemp -t tinyzkp-daily-growth.XXXXXX)"
cleanup() {
    rm -f "$memo_file"
}
trap cleanup EXIT

"$PYTHON" "${args[@]}" | tee "$memo_file"

latest_snapshot="$(find "$SNAPSHOT_DIR" -maxdepth 1 -type f -name '*.json' -print 2>/dev/null | sort | tail -n 1 || true)"
redaction_re='([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|https://checkout\.stripe\.com/|(^|[^A-Za-z0-9_])((cs|cus|acct|sk|pk|rk|whsec)_(live|test)?_?[A-Za-z0-9]{8,}))'
scan_files=("$memo_file")

if [ -n "$latest_snapshot" ]; then
    scan_files+=("$latest_snapshot")
fi
if [ -f "$EXPERIMENT_LEDGER" ]; then
    scan_files+=("$EXPERIMENT_LEDGER")
fi

if grep -E "$redaction_re" "${scan_files[@]}" >/dev/null; then
    echo "ERROR: daily growth output redaction scan failed." >&2
    exit 1
fi

echo "daily_growth_decision_redaction_scan=ok"
