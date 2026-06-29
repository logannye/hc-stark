#!/usr/bin/env bash
# Production cron wrapper for the daily TinyZKP growth decision memo.
#
# The base memo always runs from production tenant/usage stores. Stripe Checkout
# metrics are included only when the host explicitly configures a TinyZKP Stripe
# CLI profile, so cron cannot accidentally trust another account.
set -euo pipefail

REPO="${TINYZKP_REPO:-/opt/hc-stark}"
PYTHON="${TINYZKP_PYTHON:-$REPO/.venv/bin/python}"
SNAPSHOT_DIR="${TINYZKP_GROWTH_SNAPSHOT_DIR:-$REPO/data/growth_snapshots}"
ENV_FILE="${TINYZKP_ENV_FILE:-$REPO/.env}"

if [ -f "$ENV_FILE" ]; then
    set -a
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    set +a
fi

cd "$REPO"
mkdir -p "$SNAPSHOT_DIR"

args=(
    scripts/monitoring/daily_growth_decision.py
    --snapshot-dir "$SNAPSHOT_DIR"
)

stripe_profile="${TINYZKP_GROWTH_STRIPE_PROJECT_NAME:-${TINYZKP_STRIPE_PROJECT_NAME:-}}"
stripe_checkout="${TINYZKP_GROWTH_STRIPE_CHECKOUT:-}"
if [ -n "$stripe_profile" ]; then
    args+=(
        --stripe-checkout
        --stripe-bin "${TINYZKP_STRIPE_BIN:-stripe}"
        --stripe-project-name "$stripe_profile"
        --stripe-expected-display-name "${TINYZKP_STRIPE_EXPECTED_DISPLAY_NAME:-TinyZKP}"
    )
elif [ "$stripe_checkout" = "1" ] || [ "$stripe_checkout" = "true" ]; then
    echo "ERROR: TINYZKP_GROWTH_STRIPE_CHECKOUT is enabled but no explicit TinyZKP Stripe project/profile is configured." >&2
    echo "Set TINYZKP_GROWTH_STRIPE_PROJECT_NAME after billing/stripe_account_context_check.py verifies the profile." >&2
    exit 1
fi

memo_file="$(mktemp -t tinyzkp-daily-growth.XXXXXX)"
cleanup() {
    rm -f "$memo_file"
}
trap cleanup EXIT

"$PYTHON" "${args[@]}" | tee "$memo_file"

latest_snapshot="$(find "$SNAPSHOT_DIR" -maxdepth 1 -type f -name '*.json' -print 2>/dev/null | sort | tail -n 1 || true)"
redaction_re='([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|https://checkout\.stripe\.com/|(^|[^A-Za-z0-9_])((cs|cus|acct|sk|pk|rk|whsec)_(live|test)?_?[A-Za-z0-9]{8,}))'

if [ -n "$latest_snapshot" ]; then
    if grep -E "$redaction_re" "$memo_file" "$latest_snapshot" >/dev/null; then
        echo "ERROR: daily growth output redaction scan failed." >&2
        exit 1
    fi
else
    if grep -E "$redaction_re" "$memo_file" >/dev/null; then
        echo "ERROR: daily growth memo redaction scan failed." >&2
        exit 1
    fi
fi

echo "daily_growth_decision_redaction_scan=ok"
