#!/usr/bin/env bash
# billing/setup_stripe_v2_pricing.sh
#
# Idempotent migration to v2 pricing:
#   - Add public Pro at $79/mo using the old Team economics
#   - Keep Scale at $199/mo
#   - Raise Developer from $9 → $19 (creates new prices, archives old)
#   - Add Compute tier (pure usage-based, $0.50 per million trace steps)
#   - Preserve legacy Team Stripe artifacts only as rollout fallbacks
#
# Safe to re-run; uses application-level idempotency keyed on metadata.
# Requires: STRIPE_SECRET_KEY (sk_live_... or sk_test_...) in env, jq, curl.
#
# Run from repo root:
#   STRIPE_SECRET_KEY=sk_live_... bash billing/setup_stripe_v2_pricing.sh

set -euo pipefail

if [[ "${TINYZKP_ALLOW_LEGACY_RESEARCH_CATALOG:-0}" != "1" ]]; then
  echo "ERROR: legacy v2 self-serve catalog creation is disabled during backend recovery." >&2
  echo "This script is test/research-only and must not be used for TinyZKP live operations." >&2
  exit 64
fi

STRIPE_KEY="${STRIPE_SECRET_KEY:?STRIPE_SECRET_KEY required (sk_live_... or sk_test_...)}"
if [[ "$STRIPE_KEY" == *"_live_"* ]]; then
  echo "ERROR: legacy v2 catalog creation refuses every live-mode Stripe key." >&2
  exit 64
fi
API="https://api.stripe.com/v1"
auth=(-u "${STRIPE_KEY}:")

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq not installed. brew install jq" >&2
  exit 1
fi

# ─── helpers ─────────────────────────────────────────────────────────────────
sk()  { curl -sS "${auth[@]}" "$@"; }
log() { printf "  %s\n" "$*" >&2; }

# Find a billing meter by event_name (returns empty string if not found).
find_meter_by_event() {
  local event_name="$1"
  sk "$API/billing/meters?limit=100" \
    | jq -r --arg e "$event_name" '.data[] | select(.event_name==$e) | .id' | head -1
}

# Find a product by metadata key/value. Returns empty string if not found.
# /products/search is eventually consistent; fall back to /products list +
# client-side filter, which is strongly consistent.
find_product_by_metadata() {
  local key="$1" val="$2"
  local id
  id=$(sk -G "$API/products/search" --data-urlencode "query=metadata['$key']:'$val'" \
    | jq -r '.data[0].id // empty')
  if [ -z "$id" ]; then
    id=$(sk "$API/products?limit=100&active=true" \
      | jq -r --arg k "$key" --arg v "$val" \
          '.data[] | select(.metadata[$k] == $v) | .id' | head -1)
  fi
  echo "$id"
}

# Find a price by metadata key/value. Same fallback pattern as products.
find_price_by_metadata() {
  local key="$1" val="$2"
  local id
  id=$(sk -G "$API/prices/search" --data-urlencode "query=metadata['$key']:'$val'" \
    | jq -r '.data[0].id // empty')
  if [ -z "$id" ]; then
    id=$(sk "$API/prices?limit=100&active=true" \
      | jq -r --arg k "$key" --arg v "$val" \
          '.data[] | select(.metadata[$k] == $v) | .id' | head -1)
  fi
  echo "$id"
}

# ─── 1. trace_step_usage meter ───────────────────────────────────────────────
TRACE_METER=$(find_meter_by_event trace_step_usage || true)
if [ -z "$TRACE_METER" ]; then
  TRACE_METER=$(sk -X POST "$API/billing/meters" \
    -d display_name="TinyZKP trace step usage" \
    -d event_name="trace_step_usage" \
    -d "default_aggregation[formula]=sum" \
    -d "customer_mapping[event_payload_key]=stripe_customer_id" \
    -d "customer_mapping[type]=by_id" \
    -d "value_settings[event_payload_key]=value" \
    | jq -r '.id // empty')
  [ -n "$TRACE_METER" ] || { echo "ERROR: failed to create trace_step_usage meter" >&2; exit 1; }
  log "created trace_step_usage meter: $TRACE_METER"
else
  log "trace_step_usage meter exists: $TRACE_METER"
fi

# ─── 2. Compute product (pure usage-based) ───────────────────────────────────
COMPUTE_PROD=$(find_product_by_metadata tinyzkp_tier compute || true)
if [ -z "$COMPUTE_PROD" ]; then
  COMPUTE_PROD=$(sk -X POST "$API/products" \
    -d name="Compute" \
    -d description="Usage-based proving for long state-transition traces. \$0.50 per million trace steps. No monthly base fee." \
    -d "metadata[tinyzkp_tier]=compute" \
    | jq -r .id)
  log "created Compute product: $COMPUTE_PROD"
else
  log "Compute product exists: $COMPUTE_PROD"
fi

# Compute price: $0.50 per 1,000,000 trace steps = $0.0000005/step.
# Stripe's unit_amount_decimal is in cents, so $0.0000005 = 0.00005 cents.
COMPUTE_PRICE=$(find_price_by_metadata tinyzkp_price_id compute_per_million || true)
if [ -z "$COMPUTE_PRICE" ]; then
  COMPUTE_PRICE=$(sk -X POST "$API/prices" \
    -d product="$COMPUTE_PROD" \
    -d currency=usd \
    -d "recurring[usage_type]=metered" \
    -d "recurring[interval]=month" \
    -d "recurring[meter]=$TRACE_METER" \
    -d billing_scheme=per_unit \
    -d unit_amount_decimal="0.00005" \
    -d "metadata[tinyzkp_price_id]=compute_per_million" \
    | jq -r .id)
  log "created Compute price (per-step metered): $COMPUTE_PRICE"
else
  log "Compute price exists: $COMPUTE_PRICE"
fi

# ─── 3. Developer at $19 (replaces $9) ───────────────────────────────────────
DEV_PROD=$(find_product_by_metadata tinyzkp_tier developer || true)
if [ -z "$DEV_PROD" ]; then
  echo "ERROR: developer product not found. Run setup_stripe_products.sh first." >&2
  exit 1
fi

# v2 monthly: $19 = 1900 cents
DEV_19_MO=$(find_price_by_metadata tinyzkp_price_id developer_monthly_v2 || true)
if [ -z "$DEV_19_MO" ]; then
  DEV_19_MO=$(sk -X POST "$API/prices" \
    -d product="$DEV_PROD" \
    -d currency=usd \
    -d unit_amount=1900 \
    -d "recurring[interval]=month" \
    -d "metadata[tinyzkp_price_id]=developer_monthly_v2" \
    | jq -r .id)
  log "created Developer monthly v2 (\$19/mo): $DEV_19_MO"
else
  log "Developer monthly v2 exists: $DEV_19_MO"
fi

# v2 annual: $19 * 12 * 0.8 = $182.40 → 18240 cents
DEV_19_YR=$(find_price_by_metadata tinyzkp_price_id developer_annual_v2 || true)
if [ -z "$DEV_19_YR" ]; then
  DEV_19_YR=$(sk -X POST "$API/prices" \
    -d product="$DEV_PROD" \
    -d currency=usd \
    -d unit_amount=18240 \
    -d "recurring[interval]=year" \
    -d "metadata[tinyzkp_price_id]=developer_annual_v2" \
    | jq -r .id)
  log "created Developer annual v2 (\$182.40/yr, -20%): $DEV_19_YR"
else
  log "Developer annual v2 exists: $DEV_19_YR"
fi

# ─── 4. Pro at $79 (public intermediate tier) ────────────────────────────────
PRO_PROD=$(find_product_by_metadata tinyzkp_tier pro || true)
if [ -z "$PRO_PROD" ]; then
  PRO_PROD=$(sk -X POST "$API/products" \
    -d name="TinyZKP Pro" \
    -d description="Pro plan — 25% off per-proof rates, 300 RPM, 8 concurrent jobs, \$2,500/mo cap." \
    -d "metadata[tinyzkp_tier]=pro" \
    | jq -r .id)
  log "created Pro product: $PRO_PROD"
else
  log "Pro product exists: $PRO_PROD"
fi

# Pro monthly: $79 = 7900 cents
PRO_79_MO=$(find_price_by_metadata tinyzkp_price_id pro_monthly_v2 || true)
if [ -z "$PRO_79_MO" ]; then
  PRO_79_MO=$(sk -X POST "$API/prices" \
    -d product="$PRO_PROD" \
    -d currency=usd \
    -d unit_amount=7900 \
    -d "recurring[interval]=month" \
    -d "metadata[tinyzkp_price_id]=pro_monthly_v2" \
    | jq -r .id)
  log "created Pro monthly v2 (\$79/mo): $PRO_79_MO"
else
  log "Pro monthly v2 exists: $PRO_79_MO"
fi

# Pro annual: $79 * 12 * 0.8 = $758.40 → 75840 cents
PRO_79_YR=$(find_price_by_metadata tinyzkp_price_id pro_annual_v2 || true)
if [ -z "$PRO_79_YR" ]; then
  PRO_79_YR=$(sk -X POST "$API/prices" \
    -d product="$PRO_PROD" \
    -d currency=usd \
    -d unit_amount=75840 \
    -d "recurring[interval]=year" \
    -d "metadata[tinyzkp_price_id]=pro_annual_v2" \
    | jq -r .id)
  log "created Pro annual v2 (\$758.40/yr, -20%): $PRO_79_YR"
else
  log "Pro annual v2 exists: $PRO_79_YR"
fi

# ─── 5. Keep Scale at $199 ──────────────────────────────────────────────────
SCALE_PROD=$(find_product_by_metadata tinyzkp_tier scale || true)
if [ -z "$SCALE_PROD" ]; then
  log "Scale product not found. Create or map STRIPE_PRICE_ID_SCALE manually."
else
  log "Scale product remains active: $SCALE_PROD"
fi

# ─── 6. Archive old Developer $9 prices ──────────────────────────────────────
for label in developer_monthly developer_annual; do
  P=$(find_price_by_metadata tinyzkp_price_id $label || true)
  if [ -n "$P" ]; then
    ACTIVE=$(sk "$API/prices/$P" | jq -r .active)
    if [ "$ACTIVE" = "true" ]; then
      sk -X POST "$API/prices/$P" -d active=false > /dev/null
      log "archived old $label price: $P"
    fi
  fi
done

# ─── 7. Print Cloudflare Pages secrets to set ────────────────────────────────
SCALE_MONTHLY=$(find_price_by_metadata tinyzkp_price_id scale_monthly || true)
SCALE_ANNUAL=$(find_price_by_metadata tinyzkp_price_id scale_annual || true)

cat <<EOF

═══════════════════════════════════════════════════════════════════════
  ✓ Stripe v2 pricing setup complete.

  Products:
    Compute:           $COMPUTE_PROD
    Developer:         $DEV_PROD
    Pro:               $PRO_PROD
    Scale:             ${SCALE_PROD:-(not found)}
    Team:              legacy fallback only

  Meters:
    proof_usage:       (existing — unchanged)
    trace_step_usage:  $TRACE_METER

  Prices:
    Compute (per-M-steps):       $COMPUTE_PRICE
    Developer monthly (\$19):     $DEV_19_MO
    Developer annual (\$182.40):  $DEV_19_YR
    Pro monthly (\$79):           $PRO_79_MO
    Pro annual (\$758.40):        $PRO_79_YR
    Scale monthly (\$199):        ${SCALE_MONTHLY:-(not found)}
    Scale annual (\$1,910):       ${SCALE_ANNUAL:-(not found)}

═══════════════════════════════════════════════════════════════════════

  Next: deploy these as Cloudflare Pages secrets so create-checkout.js
  can pick them up. Run from repo root:

    wrangler pages secret put STRIPE_PRICE_ID_DEVELOPER \\
      --project-name tinyzkp <<< "$DEV_19_MO"

    wrangler pages secret put STRIPE_PRICE_ID_DEVELOPER_ANNUAL \\
      --project-name tinyzkp <<< "$DEV_19_YR"

    wrangler pages secret put STRIPE_PRICE_ID_PRO \\
      --project-name tinyzkp <<< "$PRO_79_MO"

    wrangler pages secret put STRIPE_PRICE_ID_PRO_ANNUAL \\
      --project-name tinyzkp <<< "$PRO_79_YR"

    wrangler pages secret put STRIPE_PRICE_ID_SCALE \\
      --project-name tinyzkp <<< "${SCALE_MONTHLY:-<set-manually>}"

    wrangler pages secret put STRIPE_PRICE_ID_SCALE_ANNUAL \\
      --project-name tinyzkp <<< "${SCALE_ANNUAL:-<set-manually>}"

    wrangler pages secret put STRIPE_PRICE_ID_TRACE_STEP_METERED \\
      --project-name tinyzkp <<< "$COMPUTE_PRICE"

  Optionally remove these legacy fallback secrets after all old checkout links
  are retired:
    wrangler pages secret delete STRIPE_PRICE_ID_TEAM         --project-name tinyzkp
    wrangler pages secret delete STRIPE_PRICE_ID_TEAM_ANNUAL  --project-name tinyzkp

  Existing subscribers on the old Developer (\$9) and Team (\$49) prices
  remain on their grandfathered rates until renewal. New storefront checkout
  should advertise only Free / Developer / Pro / Scale / Compute.
EOF
