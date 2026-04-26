#!/usr/bin/env bash
# Idempotent setup of TinyZKP Stripe products.
#
# Usage (run from the hc-stark repo root):
#   STRIPE_API_KEY=sk_live_YOUR_FULL_KEY bash billing/setup_stripe_products.sh
#
# The script:
#   1. Pre-flight checks the key (must start with sk_live_).
#   2. Creates one meter and four products with stable idempotency keys, so
#      running this twice in a row produces zero duplicates.
#   3. Creates seven prices (Developer monthly + annual, Team monthly + annual,
#      Scale monthly + annual, plus the metered usage price).
#   4. Writes every resulting Stripe ID to billing/STRIPE_PRODUCT_IDS.md and
#      billing/.stripe_ids.json (the .json is gitignored).
#
# The seven price IDs that flow into Cloudflare Pages secrets are also printed
# at the end of the run for easy copy/paste into `wrangler pages secret put`.

set -euo pipefail

# ── Pre-flight ─────────────────────────────────────────────────────────

if [[ -z "${STRIPE_API_KEY:-}" ]]; then
  echo "ERROR: STRIPE_API_KEY is not set in the environment." >&2
  echo "Run with: STRIPE_API_KEY=sk_live_... bash billing/setup_stripe_products.sh" >&2
  exit 1
fi

if [[ ! "$STRIPE_API_KEY" =~ ^sk_live_ ]]; then
  echo "ERROR: STRIPE_API_KEY does not start with sk_live_." >&2
  echo "This script creates LIVE products. Use a live secret key from" >&2
  echo "https://dashboard.stripe.com/apikeys" >&2
  exit 1
fi

if ! command -v stripe >/dev/null; then
  echo "ERROR: stripe CLI not found. Install via 'brew install stripe/stripe-cli/stripe'." >&2
  exit 1
fi

if ! command -v python3 >/dev/null; then
  echo "ERROR: python3 not found." >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JSON_OUT="${REPO_ROOT}/billing/.stripe_ids.json"
MD_OUT="${REPO_ROOT}/billing/STRIPE_PRODUCT_IDS.md"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# Pre-flight smoke test: list one product to confirm the key works.
if ! stripe products list --limit 1 >/tmp/stripe_preflight.json 2>&1; then
  echo "ERROR: Stripe API call failed. See /tmp/stripe_preflight.json for details." >&2
  cat /tmp/stripe_preflight.json | head -20 >&2
  exit 1
fi

echo "Pre-flight OK. Stripe key authenticated."
echo

# ── Helper ─────────────────────────────────────────────────────────────

# Extract the 'id' field from a Stripe API JSON response, fail loudly on error.
extract_id() {
  python3 -c "
import json, sys
d = json.load(sys.stdin)
err = d.get('error')
if err:
    print('ERROR: ' + err.get('message', 'unknown'), file=sys.stderr)
    sys.exit(2)
print(d.get('id', ''))
"
}

# Run a stripe create command, save full response to a temp file, return ID.
create_resource() {
  local label="$1"
  local response_file="$2"
  shift 2
  printf '  %-40s ... ' "$label"
  if stripe "$@" >"$response_file" 2>&1; then
    local id
    id="$(cat "$response_file" | extract_id)" || {
      echo "FAIL"
      cat "$response_file" | head -10 >&2
      exit 1
    }
    echo "$id"
    printf '%s' "$id"
  else
    echo "FAIL"
    cat "$response_file" | head -10 >&2
    exit 1
  fi
}

# ── 1. Meter ───────────────────────────────────────────────────────────

echo "=== Step 1: proof_usage meter ==="
METER_ID="$(create_resource \
  "proof_usage meter" \
  "${TMP_DIR}/meter.json" \
  billing meters create \
    --display-name "Proof Usage" \
    --event-name "proof_usage" \
    -d "default_aggregation[formula]=sum" \
    -d "customer_mapping[event_payload_key]=stripe_customer_id" \
    -d "customer_mapping[type]=by_id" \
    -d "value_settings[event_payload_key]=value" \
    -H "Idempotency-Key: tinyzkp:meter:proof_usage:v1")"
echo

# ── 2. Products ────────────────────────────────────────────────────────

echo "=== Step 2: products ==="
DEVELOPER_PROD="$(create_resource \
  "Developer product" \
  "${TMP_DIR}/prod_dev.json" \
  products create \
    --name "TinyZKP Developer" \
    --description "Developer plan — base per-proof rates, 100 RPM, 4 concurrent jobs, \$500/mo cap" \
    -H "Idempotency-Key: tinyzkp:product:developer:v1")"
TEAM_PROD="$(create_resource \
  "Team product" \
  "${TMP_DIR}/prod_team.json" \
  products create \
    --name "TinyZKP Team" \
    --description "Team plan — 25% off per-proof rates, 300 RPM, 8 concurrent jobs, \$2,500/mo cap" \
    -H "Idempotency-Key: tinyzkp:product:team:v1")"
SCALE_PROD="$(create_resource \
  "Scale product" \
  "${TMP_DIR}/prod_scale.json" \
  products create \
    --name "TinyZKP Scale" \
    --description "Scale plan — 40% off per-proof rates, 500 RPM, 16 concurrent jobs, \$10,000/mo cap" \
    -H "Idempotency-Key: tinyzkp:product:scale:v1")"
METERED_PROD="$(create_resource \
  "Proof Generation (metered)" \
  "${TMP_DIR}/prod_metered.json" \
  products create \
    --name "TinyZKP Proof Generation" \
    --description "ZK-STARK proof generation API — metered usage (cents per proof)" \
    -H "Idempotency-Key: tinyzkp:product:proof_generation:v1")"
echo

# ── 3. Prices ──────────────────────────────────────────────────────────

echo "=== Step 3: prices ==="

DEV_MONTHLY_PRICE="$(create_resource \
  "Developer monthly (\$9)" \
  "${TMP_DIR}/price_dev_m.json" \
  prices create \
    --currency usd \
    --unit-amount 900 \
    --product "$DEVELOPER_PROD" \
    --nickname "Developer Monthly" \
    -d "recurring[interval]=month" \
    -d "recurring[usage_type]=licensed" \
    -H "Idempotency-Key: tinyzkp:price:developer:monthly:v1")"

DEV_ANNUAL_PRICE="$(create_resource \
  "Developer annual (\$86.40)" \
  "${TMP_DIR}/price_dev_y.json" \
  prices create \
    --currency usd \
    --unit-amount 8640 \
    --product "$DEVELOPER_PROD" \
    --nickname "Developer Annual" \
    -d "recurring[interval]=year" \
    -d "recurring[usage_type]=licensed" \
    -H "Idempotency-Key: tinyzkp:price:developer:annual:v1")"

TEAM_MONTHLY_PRICE="$(create_resource \
  "Team monthly (\$49)" \
  "${TMP_DIR}/price_team_m.json" \
  prices create \
    --currency usd \
    --unit-amount 4900 \
    --product "$TEAM_PROD" \
    --nickname "Team Monthly" \
    -d "recurring[interval]=month" \
    -d "recurring[usage_type]=licensed" \
    -H "Idempotency-Key: tinyzkp:price:team:monthly:v1")"

TEAM_ANNUAL_PRICE="$(create_resource \
  "Team annual (\$470.40)" \
  "${TMP_DIR}/price_team_y.json" \
  prices create \
    --currency usd \
    --unit-amount 47040 \
    --product "$TEAM_PROD" \
    --nickname "Team Annual" \
    -d "recurring[interval]=year" \
    -d "recurring[usage_type]=licensed" \
    -H "Idempotency-Key: tinyzkp:price:team:annual:v1")"

SCALE_MONTHLY_PRICE="$(create_resource \
  "Scale monthly (\$199)" \
  "${TMP_DIR}/price_scale_m.json" \
  prices create \
    --currency usd \
    --unit-amount 19900 \
    --product "$SCALE_PROD" \
    --nickname "Scale Monthly" \
    -d "recurring[interval]=month" \
    -d "recurring[usage_type]=licensed" \
    -H "Idempotency-Key: tinyzkp:price:scale:monthly:v1")"

SCALE_ANNUAL_PRICE="$(create_resource \
  "Scale annual (\$1,910.40)" \
  "${TMP_DIR}/price_scale_y.json" \
  prices create \
    --currency usd \
    --unit-amount 191040 \
    --product "$SCALE_PROD" \
    --nickname "Scale Annual" \
    -d "recurring[interval]=year" \
    -d "recurring[usage_type]=licensed" \
    -H "Idempotency-Key: tinyzkp:price:scale:annual:v1")"

METERED_PRICE="$(create_resource \
  "Metered usage (\$0.01/unit)" \
  "${TMP_DIR}/price_metered.json" \
  prices create \
    --currency usd \
    --product "$METERED_PROD" \
    --nickname "Per-proof usage (cents)" \
    -d "recurring[interval]=month" \
    -d "recurring[usage_type]=metered" \
    -d "recurring[meter]=$METER_ID" \
    -d "billing_scheme=per_unit" \
    -d "unit_amount_decimal=1.0" \
    -H "Idempotency-Key: tinyzkp:price:metered:v1")"

echo

# ── 4. Write outputs ───────────────────────────────────────────────────

cat >"$JSON_OUT" <<JSON
{
  "stripe_account": "$(stripe config --list 2>/dev/null | grep '^account_id' | awk -F"'" '{print $2}')",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "meter": "$METER_ID",
  "products": {
    "developer": "$DEVELOPER_PROD",
    "team": "$TEAM_PROD",
    "scale": "$SCALE_PROD",
    "proof_generation": "$METERED_PROD"
  },
  "prices": {
    "developer_monthly": "$DEV_MONTHLY_PRICE",
    "developer_annual": "$DEV_ANNUAL_PRICE",
    "team_monthly": "$TEAM_MONTHLY_PRICE",
    "team_annual": "$TEAM_ANNUAL_PRICE",
    "scale_monthly": "$SCALE_MONTHLY_PRICE",
    "scale_annual": "$SCALE_ANNUAL_PRICE",
    "metered": "$METERED_PRICE"
  }
}
JSON

cat >"$MD_OUT" <<MD
# TinyZKP Stripe Product IDs

Generated by \`billing/setup_stripe_products.sh\` on $(date -u +%Y-%m-%d).

> **Live mode.** All IDs below correspond to real, billable Stripe objects. Store them as Cloudflare Pages secrets and in \`/opt/hc-stark/.env\` per \`billing/STRIPE_SETUP.md\`.

## Meter

| Resource | ID |
|---|---|
| \`proof_usage\` meter | \`$METER_ID\` |

## Products

| Plan | Product ID |
|---|---|
| TinyZKP Proof Generation (metered) | \`$METERED_PROD\` |
| TinyZKP Developer | \`$DEVELOPER_PROD\` |
| TinyZKP Team | \`$TEAM_PROD\` |
| TinyZKP Scale | \`$SCALE_PROD\` |

## Prices

| Plan | Cadence | Amount | Price ID |
|---|---|---|---|
| Developer | monthly | \$9.00 | \`$DEV_MONTHLY_PRICE\` |
| Developer | annual | \$86.40 (20% off) | \`$DEV_ANNUAL_PRICE\` |
| Team | monthly | \$49.00 | \`$TEAM_MONTHLY_PRICE\` |
| Team | annual | \$470.40 (20% off) | \`$TEAM_ANNUAL_PRICE\` |
| Scale | monthly | \$199.00 | \`$SCALE_MONTHLY_PRICE\` |
| Scale | annual | \$1,910.40 (20% off) | \`$SCALE_ANNUAL_PRICE\` |
| Proof Generation (metered) | per proof | \$0.01/unit | \`$METERED_PRICE\` |

## Cloudflare Pages secrets to push

Run these against the \`tinyzkp\` Pages project:

\`\`\`bash
echo -n "$DEV_MONTHLY_PRICE"   | wrangler pages secret put STRIPE_PRICE_ID_DEVELOPER          --project-name tinyzkp
echo -n "$DEV_ANNUAL_PRICE"    | wrangler pages secret put STRIPE_PRICE_ID_DEVELOPER_ANNUAL   --project-name tinyzkp
echo -n "$TEAM_MONTHLY_PRICE"  | wrangler pages secret put STRIPE_PRICE_ID_TEAM               --project-name tinyzkp
echo -n "$TEAM_ANNUAL_PRICE"   | wrangler pages secret put STRIPE_PRICE_ID_TEAM_ANNUAL        --project-name tinyzkp
echo -n "$SCALE_MONTHLY_PRICE" | wrangler pages secret put STRIPE_PRICE_ID_SCALE              --project-name tinyzkp
echo -n "$SCALE_ANNUAL_PRICE"  | wrangler pages secret put STRIPE_PRICE_ID_SCALE_ANNUAL       --project-name tinyzkp
echo -n "$METERED_PRICE"       | wrangler pages secret put STRIPE_PRICE_ID_METERED            --project-name tinyzkp
\`\`\`

## Production server \`.env\`

Add to \`/opt/hc-stark/.env\`:

\`\`\`
STRIPE_PRICE_ID_DEVELOPER=$DEV_MONTHLY_PRICE
STRIPE_PRICE_ID_DEVELOPER_ANNUAL=$DEV_ANNUAL_PRICE
STRIPE_PRICE_ID_TEAM=$TEAM_MONTHLY_PRICE
STRIPE_PRICE_ID_TEAM_ANNUAL=$TEAM_ANNUAL_PRICE
STRIPE_PRICE_ID_SCALE=$SCALE_MONTHLY_PRICE
STRIPE_PRICE_ID_SCALE_ANNUAL=$SCALE_ANNUAL_PRICE
STRIPE_PRICE_ID_METERED=$METERED_PRICE
\`\`\`

## Webhook setup

Still required (no CLI for this — Dashboard only):

1. Go to https://dashboard.stripe.com/webhooks
2. Add endpoint: \`https://webhook.tinyzkp.com/webhook\`
3. Listen for: \`checkout.session.completed\`, \`customer.subscription.updated\`, \`customer.subscription.deleted\`, \`invoice.payment_failed\`
4. Copy the signing secret (starts with \`whsec_...\`) into \`STRIPE_WEBHOOK_SECRET\` env var on production.
MD

# ── 5. Final summary ──────────────────────────────────────────────────

echo "=== Done ==="
echo
echo "Wrote: $MD_OUT"
echo "Wrote: $JSON_OUT (gitignored)"
echo
echo "Quick reference:"
echo "  STRIPE_PRICE_ID_DEVELOPER         = $DEV_MONTHLY_PRICE"
echo "  STRIPE_PRICE_ID_DEVELOPER_ANNUAL  = $DEV_ANNUAL_PRICE"
echo "  STRIPE_PRICE_ID_TEAM              = $TEAM_MONTHLY_PRICE"
echo "  STRIPE_PRICE_ID_TEAM_ANNUAL       = $TEAM_ANNUAL_PRICE"
echo "  STRIPE_PRICE_ID_SCALE             = $SCALE_MONTHLY_PRICE"
echo "  STRIPE_PRICE_ID_SCALE_ANNUAL      = $SCALE_ANNUAL_PRICE"
echo "  STRIPE_PRICE_ID_METERED           = $METERED_PRICE"
echo
echo "Next steps:"
echo "  1. Push the price IDs as Cloudflare Pages secrets (commands in $MD_OUT)."
echo "  2. Add the same IDs to /opt/hc-stark/.env on the production server."
echo "  3. Set up the Stripe webhook in the Dashboard (URL + 4 events)."
echo "  4. Commit billing/STRIPE_PRODUCT_IDS.md to git."
