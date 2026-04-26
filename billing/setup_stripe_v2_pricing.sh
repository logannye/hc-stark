#!/usr/bin/env bash
# billing/setup_stripe_v2_pricing.sh
#
# Idempotent migration to v2 pricing:
#   - Drop the Team tier
#   - Rename Scale → Pro (same $199 price, just renamed product)
#   - Raise Developer from $9 → $19 (creates new prices, archives old)
#   - Add Compute tier (pure usage-based, $0.50 per million trace steps)
#
# Safe to re-run; uses application-level idempotency keyed on metadata.
# Requires: STRIPE_SECRET_KEY (sk_live_... or sk_test_...) in env, jq, curl.
#
# Run from repo root:
#   STRIPE_SECRET_KEY=sk_live_... bash billing/setup_stripe_v2_pricing.sh

set -euo pipefail

STRIPE_KEY="${STRIPE_SECRET_KEY:?STRIPE_SECRET_KEY required (sk_live_... or sk_test_...)}"
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

# Find a product by metadata key/value (returns empty if not found).
find_product_by_metadata() {
  local key="$1" val="$2"
  sk -G "$API/products/search" --data-urlencode "query=metadata['$key']:'$val'" \
    | jq -r '.data[0].id // empty'
}

# Find a price by metadata key/value (returns empty if not found).
find_price_by_metadata() {
  local key="$1" val="$2"
  sk -G "$API/prices/search" --data-urlencode "query=metadata['$key']:'$val'" \
    | jq -r '.data[0].id // empty'
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
    -d description="Usage-based ZK proving for zkVMs, zkML, rollups. \$0.50 per million trace steps. No monthly base fee." \
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

# ─── 4. Rename Scale → Pro ───────────────────────────────────────────────────
SCALE_PROD=$(find_product_by_metadata tinyzkp_tier scale || true)
if [ -n "$SCALE_PROD" ]; then
  CURRENT_NAME=$(sk "$API/products/$SCALE_PROD" | jq -r .name)
  if [ "$CURRENT_NAME" != "Pro" ]; then
    sk -X POST "$API/products/$SCALE_PROD" \
      -d name="Pro" \
      -d description="Production agent platforms. 50,000 small-T proofs/mo + 1M trace steps included; \$0.30/M for large-T overage." \
      -d "metadata[tinyzkp_tier]=pro" \
      > /dev/null
    log "renamed Scale → Pro: $SCALE_PROD"
  else
    log "Pro product (formerly Scale) already renamed: $SCALE_PROD"
  fi
  PRO_PROD="$SCALE_PROD"
else
  PRO_PROD=$(find_product_by_metadata tinyzkp_tier pro || true)
  [ -n "$PRO_PROD" ] || log "(neither Scale nor Pro product found — skipping rename)"
fi

# ─── 5. Archive Team product + prices ────────────────────────────────────────
TEAM_PROD=$(find_product_by_metadata tinyzkp_tier team || true)
if [ -n "$TEAM_PROD" ]; then
  ACTIVE=$(sk "$API/products/$TEAM_PROD" | jq -r .active)
  if [ "$ACTIVE" = "true" ]; then
    sk -X POST "$API/products/$TEAM_PROD" -d active=false > /dev/null
    log "archived Team product: $TEAM_PROD"
  else
    log "Team product already archived: $TEAM_PROD"
  fi
fi
for label in team_monthly team_annual; do
  P=$(find_price_by_metadata tinyzkp_price_id $label || true)
  if [ -n "$P" ]; then
    ACTIVE=$(sk "$API/prices/$P" | jq -r .active)
    if [ "$ACTIVE" = "true" ]; then
      sk -X POST "$API/prices/$P" -d active=false > /dev/null
      log "archived $label price: $P"
    fi
  fi
done

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
PRO_MONTHLY=$(find_price_by_metadata tinyzkp_price_id scale_monthly || find_price_by_metadata tinyzkp_price_id pro_monthly || true)
PRO_ANNUAL=$(find_price_by_metadata tinyzkp_price_id scale_annual || find_price_by_metadata tinyzkp_price_id pro_annual || true)

cat <<EOF

═══════════════════════════════════════════════════════════════════════
  ✓ Stripe v2 pricing setup complete.

  Products:
    Compute:           $COMPUTE_PROD
    Developer:         $DEV_PROD
    Pro (was Scale):   ${PRO_PROD:-(not found)}
    Team:              archived

  Meters:
    proof_usage:       (existing — unchanged)
    trace_step_usage:  $TRACE_METER

  Prices:
    Compute (per-M-steps):       $COMPUTE_PRICE
    Developer monthly (\$19):     $DEV_19_MO
    Developer annual (\$182.40):  $DEV_19_YR
    Pro monthly (\$199):          ${PRO_MONTHLY:-(not found)}
    Pro annual (\$1,910):         ${PRO_ANNUAL:-(not found)}

═══════════════════════════════════════════════════════════════════════

  Next: deploy these as Cloudflare Pages secrets so create-checkout.js
  can pick them up. Run from repo root:

    wrangler pages secret put STRIPE_PRICE_ID_DEVELOPER \\
      --project-name tinyzkp <<< "$DEV_19_MO"

    wrangler pages secret put STRIPE_PRICE_ID_DEVELOPER_ANNUAL \\
      --project-name tinyzkp <<< "$DEV_19_YR"

    wrangler pages secret put STRIPE_PRICE_ID_PRO \\
      --project-name tinyzkp <<< "${PRO_MONTHLY:-<set-manually>}"

    wrangler pages secret put STRIPE_PRICE_ID_PRO_ANNUAL \\
      --project-name tinyzkp <<< "${PRO_ANNUAL:-<set-manually>}"

    wrangler pages secret put STRIPE_PRICE_ID_TRACE_STEP_METERED \\
      --project-name tinyzkp <<< "$COMPUTE_PRICE"

  Optionally remove the now-unused legacy secrets:
    wrangler pages secret delete STRIPE_PRICE_ID_TEAM         --project-name tinyzkp
    wrangler pages secret delete STRIPE_PRICE_ID_TEAM_ANNUAL  --project-name tinyzkp
    wrangler pages secret delete STRIPE_PRICE_ID_SCALE        --project-name tinyzkp
    wrangler pages secret delete STRIPE_PRICE_ID_SCALE_ANNUAL --project-name tinyzkp

  Existing subscribers on the old Developer (\$9) and Team (\$49) prices
  remain on their grandfathered rates until renewal. Email them with the
  v2 announcement before their renewal date.
EOF
