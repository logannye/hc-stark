#!/usr/bin/env bash
# Idempotent setup of TinyZKP Stripe products.
#
# Usage (run from the hc-stark repo root):
#   STRIPE_API_KEY=sk_live_YOUR_FULL_KEY bash billing/setup_stripe_products.sh
#   bash billing/setup_stripe_products.sh --stripe-cli
#   bash billing/setup_stripe_products.sh --stripe-cli --push-cloudflare
#   bash billing/setup_stripe_products.sh --stripe-cli --stripe-project-name tinyzkp-prod
#
# The script:
#   1. Pre-flight checks the live key or authenticated Stripe CLI profile.
#   2. Creates two meters and six products with stable idempotency keys, so
#      running this twice in a row produces zero duplicates.
#   3. Creates nine prices (Developer monthly + annual, Pro monthly + annual,
#      Scale monthly + annual, proof-usage metered, Compute trace-step usage,
#      and the one-time Production Pilot).
#   4. Writes every resulting Stripe ID to billing/STRIPE_PRODUCT_IDS.md and
#      billing/.stripe_ids.json (the .json is gitignored).
#
# The price IDs that flow into Cloudflare Pages secrets are printed at the end
# of the run, or pushed directly with --push-cloudflare.

set -euo pipefail

# ── Pre-flight ─────────────────────────────────────────────────────────

USE_STRIPE_CLI=0
PUSH_CLOUDFLARE=0
STRIPE_BIN="${STRIPE_BIN:-stripe}"
STRIPE_PROJECT_NAME="${STRIPE_PROJECT_NAME:-}"
PROJECT_NAME="${CLOUDFLARE_PAGES_PROJECT:-tinyzkp}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stripe-cli)
      USE_STRIPE_CLI=1
      ;;
    --push-cloudflare)
      PUSH_CLOUDFLARE=1
      ;;
    --stripe-bin)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --stripe-bin requires a path." >&2
        exit 2
      fi
      STRIPE_BIN="$2"
      shift
      ;;
    --stripe-project-name)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --stripe-project-name requires a Stripe CLI project profile name." >&2
        exit 2
      fi
      STRIPE_PROJECT_NAME="$2"
      shift
      ;;
    --project-name)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --project-name requires a Cloudflare Pages project name." >&2
        exit 2
      fi
      PROJECT_NAME="$2"
      shift
      ;;
    *)
      echo "Usage: STRIPE_API_KEY=sk_live_... bash billing/setup_stripe_products.sh [--push-cloudflare] [--stripe-cli] [--stripe-bin PATH] [--stripe-project-name NAME] [--project-name NAME]" >&2
      exit 2
      ;;
  esac
  shift
done

if [[ -z "${STRIPE_API_KEY:-}" ]]; then
  USE_STRIPE_CLI=1
fi

if [[ "$USE_STRIPE_CLI" -eq 0 && ! "${STRIPE_API_KEY:-}" =~ ^sk_live_ ]]; then
  echo "ERROR: STRIPE_API_KEY does not start with sk_live_." >&2
  echo "This script creates LIVE products. Use a live secret key from" >&2
  echo "https://dashboard.stripe.com/apikeys" >&2
  echo "Or use: bash billing/setup_stripe_products.sh --stripe-cli" >&2
  exit 1
fi

if ! command -v "$STRIPE_BIN" >/dev/null; then
  echo "ERROR: stripe CLI not found. Install via 'brew install stripe/stripe-cli/stripe'." >&2
  exit 1
fi

if [[ "$USE_STRIPE_CLI" -eq 0 ]] && ! command -v curl >/dev/null; then
  echo "ERROR: curl is required when STRIPE_API_KEY mode is used." >&2
  exit 1
fi

if ! command -v python3 >/dev/null; then
  echo "ERROR: python3 not found." >&2
  exit 1
fi

if [[ "$PUSH_CLOUDFLARE" -eq 1 ]] && ! command -v wrangler >/dev/null; then
  echo "ERROR: wrangler is required for --push-cloudflare." >&2
  exit 1
fi

redact_output() {
  python3 -c '
import re
import sys

text = sys.stdin.read()
text = re.sub(r"\b(?:sk|rk|whsec)_(?:live|test)_[^\s\"'\''}]+", "[redacted-key]", text)
text = re.sub(r"\b(?:acct|cs|cus|pi|sub|price|prod|mtr|req)_[A-Za-z0-9_]+", "[redacted-id]", text)
print(text, end="")
'
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JSON_OUT="${REPO_ROOT}/billing/.stripe_ids.json"
MD_OUT="${REPO_ROOT}/billing/STRIPE_PRODUCT_IDS.md"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
STRIPE_CLI_GLOBAL_ARGS=()
if [[ -n "$STRIPE_PROJECT_NAME" ]]; then
  STRIPE_CLI_GLOBAL_ARGS+=(--project-name "$STRIPE_PROJECT_NAME")
fi

if [[ "$USE_STRIPE_CLI" -eq 1 && "${STRIPE_SKIP_ACCOUNT_CONTEXT_CHECK:-0}" != "1" ]]; then
  ACCOUNT_CONTEXT_CMD=(
    python3 "${REPO_ROOT}/billing/stripe_account_context_check.py"
    --stripe-bin "$STRIPE_BIN"
    --expected-display-name "${TINYZKP_STRIPE_EXPECTED_DISPLAY_NAME:-LN Holdings}"
  )
  if [[ -n "$STRIPE_PROJECT_NAME" ]]; then
    ACCOUNT_CONTEXT_CMD+=(--stripe-project-name "$STRIPE_PROJECT_NAME")
  fi
  if ! "${ACCOUNT_CONTEXT_CMD[@]}"; then
    echo >&2
    echo "ERROR: Stripe CLI profile is not the expected LN Holdings account for TinyZKP. Switch profiles with stripe login before running catalog setup." >&2
    echo "Set STRIPE_SKIP_ACCOUNT_CONTEXT_CHECK=1 only if the account was intentionally renamed and independently verified." >&2
    exit 1
  fi
  echo
fi

# Pre-flight smoke test: list one product to confirm the key works.
if [[ "$USE_STRIPE_CLI" -eq 1 ]]; then
  PREFLIGHT_CMD=("$STRIPE_BIN" products list --limit 1 --live --color off --log-level error "${STRIPE_CLI_GLOBAL_ARGS[@]}")
  echo "Using authenticated Stripe CLI live profile." >&2
else
  PREFLIGHT_CMD=("$STRIPE_BIN" products list --limit 1 --color off --log-level error)
  echo "Using STRIPE_API_KEY live key from the environment." >&2
fi
if ! "${PREFLIGHT_CMD[@]}" >/tmp/stripe_preflight.json 2>&1; then
  echo "ERROR: Stripe API call failed. See /tmp/stripe_preflight.json for details." >&2
  head -20 /tmp/stripe_preflight.json | redact_output >&2
  exit 1
fi

echo "Pre-flight OK. Stripe key authenticated."
echo

if [[ "${STRIPE_SKIP_WRITE_PREFLIGHT:-0}" != "1" ]]; then
  WRITE_PREFLIGHT_CMD=(python3 "${REPO_ROOT}/billing/stripe_catalog_write_preflight.py" --stripe-bin "$STRIPE_BIN" --scope full --skip-account-check)
  if [[ "$USE_STRIPE_CLI" -eq 1 ]]; then
    WRITE_PREFLIGHT_CMD+=(--live)
  fi
  if [[ -n "$STRIPE_PROJECT_NAME" ]]; then
    WRITE_PREFLIGHT_CMD+=(--stripe-project-name "$STRIPE_PROJECT_NAME")
  fi
  if ! "${WRITE_PREFLIGHT_CMD[@]}"; then
    echo >&2
    echo "ERROR: Stripe catalog write preflight failed. Use a write-capable live Stripe key/profile before running catalog setup." >&2
    echo "Set STRIPE_SKIP_WRITE_PREFLIGHT=1 only if you intentionally want the setup script to attempt writes anyway." >&2
    exit 1
  fi
  echo
fi

# ── Helper ─────────────────────────────────────────────────────────────

# Extract the 'id' field from a Stripe API JSON response, fail loudly on error.
extract_id() {
  python3 -c "
import json, re, sys

def redact(text):
    text = re.sub(r'\b(?:sk|rk|whsec)_(?:live|test)_[^\s\"\\'}]+', '[redacted-key]', str(text))
    return re.sub(r'\b(?:acct|cs|cus|pi|sub|price|prod|mtr|req)_[A-Za-z0-9_]+', '[redacted-id]', text)

d = json.load(sys.stdin)
err = d.get('error')
if err:
    print('ERROR: ' + redact(err.get('message', 'unknown')), file=sys.stderr)
    sys.exit(2)
print(d.get('id', ''))
"
}

# Run a stripe create command, save full response to a temp file, return ID.
# Display output goes to stderr; only the bare ID goes to stdout (so callers
# can capture it with $(...)) without contaminating the variable.
create_resource() {
  local label="$1"
  local response_file="$2"
  shift 2
  printf '  %-40s ... ' "$label" >&2
  local command=("$STRIPE_BIN" "$@")
  if [[ "$USE_STRIPE_CLI" -eq 1 ]]; then
    command+=(--live --confirm --color off --log-level error "${STRIPE_CLI_GLOBAL_ARGS[@]}")
  else
    command+=(--color off --log-level error)
  fi
  if "${command[@]}" >"$response_file" 2>&1; then
    local id
    id="$(cat "$response_file" | extract_id)" || {
      echo "FAIL" >&2
      head -10 "$response_file" | redact_output >&2
      exit 1
    }
    echo "$id" >&2          # show to user
    printf '%s' "$id"        # only the ID lands in $(...) capture
  else
    echo "FAIL" >&2
    head -10 "$response_file" | redact_output >&2
    exit 1
  fi
}

# Lookups in STRIPE_API_KEY mode bypass the Stripe CLI's resource subcommands
# and call the HTTP API directly via curl with Basic auth. In --stripe-cli mode
# all reads and writes use the authenticated local CLI profile.
STRIPE_API="https://api.stripe.com/v1"

if [[ "$USE_STRIPE_CLI" -eq 0 ]]; then
  if ! curl -sS -o /tmp/stripe_diag.json -w '%{http_code}\n' \
    "${STRIPE_API}/billing/meters?limit=3" \
    -u "${STRIPE_API_KEY}:" >/tmp/stripe_diag.code 2>/dev/null; then
    echo "  [diag] curl invocation failed" >&2
  fi
  DIAG_CODE="$(cat /tmp/stripe_diag.code 2>/dev/null || echo '?')"
  echo "  [diag] /v1/billing/meters returned HTTP ${DIAG_CODE}" >&2
  if [[ "$DIAG_CODE" != "200" ]]; then
    echo "  [diag] response body (first 300 chars):" >&2
    head -c 300 /tmp/stripe_diag.json | redact_output >&2
    echo "" >&2
  fi
fi

find_product_id_by_name() {
  local name="$1"
  if [[ "$USE_STRIPE_CLI" -eq 1 ]]; then
    TARGET="$name" "$STRIPE_BIN" products list --live --limit 100 --color off --log-level error "${STRIPE_CLI_GLOBAL_ARGS[@]}" 2>/dev/null | python3 -c "
import json, sys, os
target = os.environ.get('TARGET', '')
try:
    d = json.load(sys.stdin)
    for p in d.get('data', []):
        if p.get('name') == target and p.get('active'):
            print(p.get('id', ''))
            sys.exit(0)
except Exception:
    pass
"
    return 0
  fi
  TARGET="$name" curl -sS "${STRIPE_API}/products?limit=100" \
    -u "${STRIPE_API_KEY}:" 2>/dev/null | python3 -c "
import json, sys, os
target = os.environ.get('TARGET', '')
try:
    d = json.load(sys.stdin)
    for p in d.get('data', []):
        if p.get('name') == target and p.get('active'):
            print(p.get('id', ''))
            sys.exit(0)
except Exception:
    pass
"
}

find_meter_id_by_event() {
  local event="$1"
  local body
  if [[ "$USE_STRIPE_CLI" -eq 1 ]]; then
    body="$("$STRIPE_BIN" billing meters list --live --limit 100 --color off --log-level error "${STRIPE_CLI_GLOBAL_ARGS[@]}" 2>/dev/null || true)"
  else
    body="$(curl -sS "${STRIPE_API}/billing/meters?limit=100" -u "${STRIPE_API_KEY}:" 2>/dev/null)"
  fi
  local found
  found="$(TARGET="$event" python3 -c "
import json, sys, os
target = os.environ.get('TARGET', '')
try:
    d = json.loads(sys.stdin.read())
    for m in d.get('data', []):
        if m.get('event_name') == target:  # match regardless of status
            print(m.get('id', ''))
            sys.exit(0)
except Exception as e:
    sys.stderr.write(f'parse error: {e}\n')
" <<<"$body")"
  if [[ -z "$found" ]]; then
    # Diagnostic on miss — print the raw body so the user can see why.
    echo "  [diag] meter find returned no match. Response (first 300 chars):" >&2
    echo "$body" | head -c 300 | redact_output >&2
    echo "" >&2
  fi
  printf '%s' "$found"
}

find_price_id_by_nickname() {
  local product_id="$1"
  local nickname="$2"
  if [[ "$USE_STRIPE_CLI" -eq 1 ]]; then
    TARGET_NICK="$nickname" "$STRIPE_BIN" prices list --live --product "$product_id" --limit 100 --color off --log-level error "${STRIPE_CLI_GLOBAL_ARGS[@]}" 2>/dev/null | python3 -c "
import json, sys, os
target_nick = os.environ.get('TARGET_NICK', '')
try:
    d = json.load(sys.stdin)
    for p in d.get('data', []):
        if p.get('nickname') == target_nick and p.get('active'):
            print(p.get('id', ''))
            sys.exit(0)
except Exception:
    pass
"
    return 0
  fi
  TARGET_NICK="$nickname" curl -sS "${STRIPE_API}/prices?product=${product_id}&limit=100" \
    -u "${STRIPE_API_KEY}:" 2>/dev/null | python3 -c "
import json, sys, os
target_nick = os.environ.get('TARGET_NICK', '')
try:
    d = json.load(sys.stdin)
    for p in d.get('data', []):
        if p.get('nickname') == target_nick and p.get('active'):
            print(p.get('id', ''))
            sys.exit(0)
except Exception:
    pass
"
}

# Reuse an existing product if the name matches; otherwise create.
find_or_create_product() {
  local label="$1"; local name="$2"; local description="$3"; local response_file="$4"
  local existing
  existing="$(find_product_id_by_name "$name")"
  if [[ -n "$existing" ]]; then
    printf '  %-40s ... %s (existing)\n' "$label" "$existing" >&2
    printf '%s' "$existing"
    return 0
  fi
  create_resource "$label" "$response_file" \
    products create --name "$name" --description "$description"
}

find_or_create_meter() {
  local label="$1"; local event_name="$2"; local display_name="$3"; local response_file="$4"
  # Manual override: set OVERRIDE_METER_ID=mtr_... if the find function
  # can't recover an existing meter (Dashboard URL: https://dashboard.stripe.com/billing/meters).
  if [[ -n "${OVERRIDE_METER_ID:-}" ]]; then
    printf '  %-40s ... %s (override)\n' "$label" "$OVERRIDE_METER_ID" >&2
    printf '%s' "$OVERRIDE_METER_ID"
    return 0
  fi
  local existing
  existing="$(find_meter_id_by_event "$event_name")"
  if [[ -n "$existing" ]]; then
    printf '  %-40s ... %s (existing)\n' "$label" "$existing" >&2
    printf '%s' "$existing"
    return 0
  fi
  create_resource "$label" "$response_file" \
    billing meters create \
      --display-name "$display_name" \
      --event-name "$event_name" \
      -d "default_aggregation[formula]=sum" \
      -d "customer_mapping[event_payload_key]=stripe_customer_id" \
      -d "customer_mapping[type]=by_id" \
      -d "value_settings[event_payload_key]=value"
}

# Reuse an existing price by nickname; otherwise create. The 5th+ args are
# passed through to `stripe prices create`.
find_or_create_price() {
  local label="$1"; local product_id="$2"; local nickname="$3"; local response_file="$4"
  shift 4
  local existing
  existing="$(find_price_id_by_nickname "$product_id" "$nickname")"
  if [[ -n "$existing" ]]; then
    printf '  %-40s ... %s (existing)\n' "$label" "$existing" >&2
    printf '%s' "$existing"
    return 0
  fi
  create_resource "$label" "$response_file" prices create "$@"
}

# ── 1. Meters ──────────────────────────────────────────────────────────

echo "=== Step 1: meters ==="
METER_ID="$(find_or_create_meter "proof_usage meter" "proof_usage" "Proof Usage" "${TMP_DIR}/meter.json")"
TRACE_STEP_METER_ID="$(find_or_create_meter "trace_step_usage meter" "trace_step_usage" "TinyZKP trace step usage" "${TMP_DIR}/meter_trace.json")"
echo

# ── 2. Products ────────────────────────────────────────────────────────

echo "=== Step 2: products ==="
DEVELOPER_PROD="$(find_or_create_product \
  "Developer product" \
  "TinyZKP Developer" \
  "Developer plan — base per-proof rates, 100 RPM, 4 concurrent jobs, \$500/mo cap" \
  "${TMP_DIR}/prod_dev.json")"
PRO_PROD="$(find_or_create_product \
  "Pro product" \
  "TinyZKP Pro" \
  "Pro plan — 25% off per-proof rates, 300 RPM, 8 concurrent jobs, \$2,500/mo cap" \
  "${TMP_DIR}/prod_pro.json")"
SCALE_PROD="$(find_or_create_product \
  "Scale product" \
  "TinyZKP Scale" \
  "Scale plan — 40% off per-proof rates, 500 RPM, 16 concurrent jobs, \$10,000/mo cap" \
  "${TMP_DIR}/prod_scale.json")"
METERED_PROD="$(find_or_create_product \
  "Proof Generation (metered)" \
  "TinyZKP Proof Generation" \
  "STARK state-transition receipt generation API — metered usage (cents per proof)" \
  "${TMP_DIR}/prod_metered.json")"
COMPUTE_PROD="$(find_or_create_product \
  "Compute (trace-step metered)" \
  "TinyZKP Compute" \
  "Usage-based proving for long state-transition traces — \$0.50 per million trace steps" \
  "${TMP_DIR}/prod_compute.json")"
PILOT_PROD="$(find_or_create_product \
  "Production Pilot product" \
  "TinyZKP Production Pilot" \
  "14-day scoped proof-receipt workflow pilot — creditable toward annual, platform, or reserved-capacity agreement" \
  "${TMP_DIR}/prod_pilot.json")"
echo

# ── 3. Prices ──────────────────────────────────────────────────────────

echo "=== Step 3: prices ==="

DEV_MONTHLY_PRICE="$(find_or_create_price \
  "Developer monthly (\$19)" "$DEVELOPER_PROD" "Developer Monthly v2" \
  "${TMP_DIR}/price_dev_m.json" \
  --currency usd --unit-amount 1900 --product "$DEVELOPER_PROD" \
  --nickname "Developer Monthly v2" \
  -d "recurring[interval]=month" -d "recurring[usage_type]=licensed")"

DEV_ANNUAL_PRICE="$(find_or_create_price \
  "Developer annual (\$182.40)" "$DEVELOPER_PROD" "Developer Annual v2" \
  "${TMP_DIR}/price_dev_y.json" \
  --currency usd --unit-amount 18240 --product "$DEVELOPER_PROD" \
  --nickname "Developer Annual v2" \
  -d "recurring[interval]=year" -d "recurring[usage_type]=licensed")"

PRO_MONTHLY_PRICE="$(find_or_create_price \
  "Pro monthly (\$79)" "$PRO_PROD" "Pro Monthly v2" \
  "${TMP_DIR}/price_pro_m.json" \
  --currency usd --unit-amount 7900 --product "$PRO_PROD" \
  --nickname "Pro Monthly v2" \
  -d "recurring[interval]=month" -d "recurring[usage_type]=licensed")"

PRO_ANNUAL_PRICE="$(find_or_create_price \
  "Pro annual (\$758.40)" "$PRO_PROD" "Pro Annual v2" \
  "${TMP_DIR}/price_pro_y.json" \
  --currency usd --unit-amount 75840 --product "$PRO_PROD" \
  --nickname "Pro Annual v2" \
  -d "recurring[interval]=year" -d "recurring[usage_type]=licensed")"

SCALE_MONTHLY_PRICE="$(find_or_create_price \
  "Scale monthly (\$199)" "$SCALE_PROD" "Scale Monthly" \
  "${TMP_DIR}/price_scale_m.json" \
  --currency usd --unit-amount 19900 --product "$SCALE_PROD" \
  --nickname "Scale Monthly" \
  -d "recurring[interval]=month" -d "recurring[usage_type]=licensed")"

SCALE_ANNUAL_PRICE="$(find_or_create_price \
  "Scale annual (\$1,910.40)" "$SCALE_PROD" "Scale Annual" \
  "${TMP_DIR}/price_scale_y.json" \
  --currency usd --unit-amount 191040 --product "$SCALE_PROD" \
  --nickname "Scale Annual" \
  -d "recurring[interval]=year" -d "recurring[usage_type]=licensed")"

METERED_PRICE="$(find_or_create_price \
  "Metered usage (\$0.01/unit)" "$METERED_PROD" "Per-proof usage (cents)" \
  "${TMP_DIR}/price_metered.json" \
  --currency usd --product "$METERED_PROD" --nickname "Per-proof usage (cents)" \
  -d "recurring[interval]=month" -d "recurring[usage_type]=metered" \
  -d "recurring[meter]=$METER_ID" \
  -d "billing_scheme=per_unit" -d "unit_amount_decimal=1.0")"

COMPUTE_PRICE="$(find_or_create_price \
  "Compute usage (\$0.50/M steps)" "$COMPUTE_PROD" "Trace-step usage" \
  "${TMP_DIR}/price_compute.json" \
  --currency usd --product "$COMPUTE_PROD" --nickname "Trace-step usage" \
  -d "recurring[interval]=month" -d "recurring[usage_type]=metered" \
  -d "recurring[meter]=$TRACE_STEP_METER_ID" \
  -d "billing_scheme=per_unit" -d "unit_amount_decimal=0.00005")"

PILOT_PRICE="$(find_or_create_price \
  "Production Pilot (\$5,000)" "$PILOT_PROD" "Production Pilot" \
  "${TMP_DIR}/price_pilot.json" \
  --currency usd --unit-amount 500000 --product "$PILOT_PROD" \
  --nickname "Production Pilot")"

echo

# ── 4. Write outputs ───────────────────────────────────────────────────

STRIPE_ACCOUNT_ID="$("$STRIPE_BIN" config --list "${STRIPE_CLI_GLOBAL_ARGS[@]}" 2>/dev/null | awk -F"'" '/^account_id/ {print $2; exit}')"

cat >"$JSON_OUT" <<JSON
{
  "stripe_account": "$STRIPE_ACCOUNT_ID",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "meter": "$METER_ID",
  "meter_trace_step": "$TRACE_STEP_METER_ID",
  "products": {
    "developer": "$DEVELOPER_PROD",
    "pro": "$PRO_PROD",
    "scale": "$SCALE_PROD",
    "proof_generation": "$METERED_PROD",
    "compute": "$COMPUTE_PROD",
    "production_pilot": "$PILOT_PROD"
  },
  "prices": {
    "developer_monthly": "$DEV_MONTHLY_PRICE",
    "developer_annual": "$DEV_ANNUAL_PRICE",
    "pro_monthly": "$PRO_MONTHLY_PRICE",
    "pro_annual": "$PRO_ANNUAL_PRICE",
    "scale_monthly": "$SCALE_MONTHLY_PRICE",
    "scale_annual": "$SCALE_ANNUAL_PRICE",
    "metered": "$METERED_PRICE",
    "compute": "$COMPUTE_PRICE",
    "production_pilot": "$PILOT_PRICE"
  }
}
JSON

cat >"$MD_OUT" <<MD
# TinyZKP Stripe Product IDs

Generated by \`billing/setup_stripe_products.sh\` on $(date -u +%Y-%m-%d).

> **Live mode.** All IDs below correspond to real, billable Stripe objects. Store them as Cloudflare Pages secrets and in \`/opt/hc-stark/.env\` per \`billing/STRIPE_SETUP.md\`.

## Meters

| Resource | ID |
|---|---|
| \`proof_usage\` meter (cents-per-proof, all plans except Compute) | \`$METER_ID\` |
| \`trace_step_usage\` meter (raw trace steps, Compute plan only) | \`$TRACE_STEP_METER_ID\` |

## Products

| Plan | Product ID |
|---|---|
| TinyZKP Proof Generation (metered) | \`$METERED_PROD\` |
| TinyZKP Compute | \`$COMPUTE_PROD\` |
| TinyZKP Developer | \`$DEVELOPER_PROD\` |
| TinyZKP Pro | \`$PRO_PROD\` |
| TinyZKP Scale | \`$SCALE_PROD\` |
| TinyZKP Production Pilot | \`$PILOT_PROD\` |

## Prices

| Plan | Cadence | Amount | Price ID |
|---|---|---|---|
| Developer | monthly | \$19.00 | \`$DEV_MONTHLY_PRICE\` |
| Developer | annual | \$182.40 (20% off) | \`$DEV_ANNUAL_PRICE\` |
| Pro | monthly | \$79.00 | \`$PRO_MONTHLY_PRICE\` |
| Pro | annual | \$758.40 (20% off) | \`$PRO_ANNUAL_PRICE\` |
| Scale | monthly | \$199.00 | \`$SCALE_MONTHLY_PRICE\` |
| Scale | annual | \$1,910.40 (20% off) | \`$SCALE_ANNUAL_PRICE\` |
| Proof Generation (metered) | per proof | \$0.01/unit | \`$METERED_PRICE\` |
| Compute (metered) | per trace step | \$0.50/M steps | \`$COMPUTE_PRICE\` |
| Production Pilot | one-time | \$5,000.00 | \`$PILOT_PRICE\` |

## Cloudflare Pages secrets to push

Run these against the \`${PROJECT_NAME}\` Pages project:

\`\`\`bash
echo -n "$DEV_MONTHLY_PRICE"   | wrangler pages secret put STRIPE_PRICE_ID_DEVELOPER          --project-name ${PROJECT_NAME}
echo -n "$DEV_ANNUAL_PRICE"    | wrangler pages secret put STRIPE_PRICE_ID_DEVELOPER_ANNUAL   --project-name ${PROJECT_NAME}
echo -n "$PRO_MONTHLY_PRICE"   | wrangler pages secret put STRIPE_PRICE_ID_PRO                --project-name ${PROJECT_NAME}
echo -n "$PRO_ANNUAL_PRICE"    | wrangler pages secret put STRIPE_PRICE_ID_PRO_ANNUAL         --project-name ${PROJECT_NAME}
echo -n "$SCALE_MONTHLY_PRICE" | wrangler pages secret put STRIPE_PRICE_ID_SCALE              --project-name ${PROJECT_NAME}
echo -n "$SCALE_ANNUAL_PRICE"  | wrangler pages secret put STRIPE_PRICE_ID_SCALE_ANNUAL       --project-name ${PROJECT_NAME}
echo -n "$METERED_PRICE"       | wrangler pages secret put STRIPE_PRICE_ID_METERED            --project-name ${PROJECT_NAME}
echo -n "$COMPUTE_PRICE"       | wrangler pages secret put STRIPE_PRICE_ID_TRACE_STEP_METERED --project-name ${PROJECT_NAME}
echo -n "$PILOT_PRICE"         | wrangler pages secret put STRIPE_PRICE_ID_PILOT              --project-name ${PROJECT_NAME}
\`\`\`

## Production server \`.env\`

Add to \`/opt/hc-stark/.env\`:

\`\`\`
STRIPE_PRICE_ID_DEVELOPER=$DEV_MONTHLY_PRICE
STRIPE_PRICE_ID_DEVELOPER_ANNUAL=$DEV_ANNUAL_PRICE
STRIPE_PRICE_ID_PRO=$PRO_MONTHLY_PRICE
STRIPE_PRICE_ID_PRO_ANNUAL=$PRO_ANNUAL_PRICE
STRIPE_PRICE_ID_SCALE=$SCALE_MONTHLY_PRICE
STRIPE_PRICE_ID_SCALE_ANNUAL=$SCALE_ANNUAL_PRICE
STRIPE_PRICE_ID_METERED=$METERED_PRICE
STRIPE_PRICE_ID_TRACE_STEP_METERED=$COMPUTE_PRICE
STRIPE_PRICE_ID_PILOT=$PILOT_PRICE
\`\`\`

## Webhook setup

Still required (no CLI for this — Dashboard only):

1. Go to https://dashboard.stripe.com/webhooks
2. Add endpoint: \`https://webhook.tinyzkp.com/webhook\`
3. Listen for: \`checkout.session.completed\`, \`customer.subscription.updated\`, \`customer.subscription.deleted\`, \`invoice.payment_failed\`
4. Copy the signing secret (starts with \`whsec_...\`) into \`STRIPE_WEBHOOK_SECRET\` env var on production.
MD

# ── 5. Optional Cloudflare push ────────────────────────────────────────

push_secret() {
  local name="$1"
  local value="$2"
  local log_file="${TMP_DIR}/wrangler_${name}.log"
  printf '  %-40s ... ' "$name" >&2
  if printf '%s' "$value" | wrangler pages secret put "$name" --project-name "$PROJECT_NAME" >"$log_file" 2>&1; then
    echo "updated" >&2
  else
    echo "FAIL" >&2
    head -20 "$log_file" | redact_output >&2
    exit 1
  fi
}

if [[ "$PUSH_CLOUDFLARE" -eq 1 ]]; then
  echo "=== Step 4b: Cloudflare Pages secrets ==="
  echo "Pushing generated price IDs to Pages project ${PROJECT_NAME}." >&2
  push_secret STRIPE_PRICE_ID_DEVELOPER "$DEV_MONTHLY_PRICE"
  push_secret STRIPE_PRICE_ID_DEVELOPER_ANNUAL "$DEV_ANNUAL_PRICE"
  push_secret STRIPE_PRICE_ID_PRO "$PRO_MONTHLY_PRICE"
  push_secret STRIPE_PRICE_ID_PRO_ANNUAL "$PRO_ANNUAL_PRICE"
  push_secret STRIPE_PRICE_ID_SCALE "$SCALE_MONTHLY_PRICE"
  push_secret STRIPE_PRICE_ID_SCALE_ANNUAL "$SCALE_ANNUAL_PRICE"
  push_secret STRIPE_PRICE_ID_METERED "$METERED_PRICE"
  push_secret STRIPE_PRICE_ID_TRACE_STEP_METERED "$COMPUTE_PRICE"
  push_secret STRIPE_PRICE_ID_PILOT "$PILOT_PRICE"
  echo
fi

# ── 6. Final summary ──────────────────────────────────────────────────

echo "=== Done ==="
echo
echo "Wrote: $MD_OUT"
echo "Wrote: $JSON_OUT (gitignored)"
echo
echo "Quick reference:"
echo "  STRIPE_METER_ID_PROOF_USAGE       = $METER_ID"
echo "  STRIPE_METER_ID_TRACE_STEP_USAGE  = $TRACE_STEP_METER_ID"
echo "  STRIPE_PRICE_ID_DEVELOPER         = $DEV_MONTHLY_PRICE"
echo "  STRIPE_PRICE_ID_DEVELOPER_ANNUAL  = $DEV_ANNUAL_PRICE"
echo "  STRIPE_PRICE_ID_PRO               = $PRO_MONTHLY_PRICE"
echo "  STRIPE_PRICE_ID_PRO_ANNUAL        = $PRO_ANNUAL_PRICE"
echo "  STRIPE_PRICE_ID_SCALE             = $SCALE_MONTHLY_PRICE"
echo "  STRIPE_PRICE_ID_SCALE_ANNUAL      = $SCALE_ANNUAL_PRICE"
echo "  STRIPE_PRICE_ID_METERED           = $METERED_PRICE"
echo "  STRIPE_PRICE_ID_TRACE_STEP_METERED= $COMPUTE_PRICE"
echo "  STRIPE_PRICE_ID_PILOT             = $PILOT_PRICE"
echo
echo "Next steps:"
if [[ "$PUSH_CLOUDFLARE" -eq 1 ]]; then
  echo "  1. Add the same IDs to /opt/hc-stark/.env on the production server."
  echo "  2. Set up the Stripe webhook in the Dashboard (URL + 4 events)."
  echo "  3. Commit billing/STRIPE_PRODUCT_IDS.md to git."
else
  echo "  1. Push the price IDs as Cloudflare Pages secrets (commands in $MD_OUT), or rerun with --push-cloudflare."
  echo "  2. Add the same IDs to /opt/hc-stark/.env on the production server."
  echo "  3. Set up the Stripe webhook in the Dashboard (URL + 4 events)."
  echo "  4. Commit billing/STRIPE_PRODUCT_IDS.md to git."
fi
