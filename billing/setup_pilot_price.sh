#!/usr/bin/env bash
# Create or find the live one-time Stripe price for the $5,000 TinyZKP
# Production Pilot, then optionally push it to Cloudflare Pages.
#
# Usage:
#   STRIPE_API_KEY=sk_live_... bash billing/setup_pilot_price.sh
#   STRIPE_API_KEY=sk_live_... bash billing/setup_pilot_price.sh --push-cloudflare
#   bash billing/setup_pilot_price.sh --stripe-cli --push-cloudflare
#   bash billing/setup_pilot_price.sh --stripe-cli --stripe-bin /opt/homebrew/bin/stripe
#   bash billing/setup_pilot_price.sh --stripe-cli --stripe-project-name tinyzkp-prod
#
# This is intentionally narrow. Use setup_stripe_products.sh when rebuilding
# the full product catalog; use this script when only STRIPE_PRICE_ID_PILOT is
# missing from the Pages project.

set -euo pipefail

PUSH_CLOUDFLARE=0
USE_STRIPE_CLI=0
STRIPE_BIN="${STRIPE_BIN:-stripe}"
STRIPE_PROJECT_NAME="${STRIPE_PROJECT_NAME:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --push-cloudflare)
      PUSH_CLOUDFLARE=1
      ;;
    --stripe-cli)
      USE_STRIPE_CLI=1
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
    *)
      echo "Usage: STRIPE_API_KEY=sk_live_... bash billing/setup_pilot_price.sh [--push-cloudflare] [--stripe-cli] [--stripe-bin PATH] [--stripe-project-name NAME]" >&2
      exit 2
      ;;
  esac
  shift
done

if [[ -z "${STRIPE_API_KEY:-}" && "$USE_STRIPE_CLI" -eq 0 ]]; then
  USE_STRIPE_CLI=1
fi

if [[ "$USE_STRIPE_CLI" -eq 0 && ! "$STRIPE_API_KEY" =~ ^sk_live_ ]]; then
  echo "ERROR: STRIPE_API_KEY must be a live secret key (sk_live_...)." >&2
  exit 1
fi

if [[ "$USE_STRIPE_CLI" -eq 0 ]] && ! command -v curl >/dev/null; then
  echo "ERROR: curl is required." >&2
  exit 1
fi

if [[ "$USE_STRIPE_CLI" -eq 1 ]] && ! command -v "$STRIPE_BIN" >/dev/null; then
  echo "ERROR: stripe CLI is required when using --stripe-cli or when STRIPE_API_KEY is absent." >&2
  exit 1
fi

if ! command -v python3 >/dev/null; then
  echo "ERROR: python3 is required." >&2
  exit 1
fi

if [[ "$PUSH_CLOUDFLARE" -eq 1 ]] && ! command -v wrangler >/dev/null; then
  echo "ERROR: wrangler is required for --push-cloudflare." >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
stripe_cli_global_args=()
if [[ -n "$STRIPE_PROJECT_NAME" ]]; then
  stripe_cli_global_args+=(--project-name "$STRIPE_PROJECT_NAME")
fi

if [[ "$USE_STRIPE_CLI" -eq 1 && "${STRIPE_SKIP_ACCOUNT_CONTEXT_CHECK:-0}" != "1" ]]; then
  account_context_cmd=(
    python3 "${repo_root}/billing/stripe_account_context_check.py"
    --stripe-bin "$STRIPE_BIN"
    --expected-display-name "${TINYZKP_STRIPE_EXPECTED_DISPLAY_NAME:-TinyZKP}"
  )
  if [[ -n "$STRIPE_PROJECT_NAME" ]]; then
    account_context_cmd+=(--stripe-project-name "$STRIPE_PROJECT_NAME")
  fi
  if ! "${account_context_cmd[@]}"; then
    echo >&2
    echo "ERROR: Stripe CLI profile is not the expected TinyZKP account. Switch profiles with stripe login before creating the pilot catalog price." >&2
    echo "Set STRIPE_SKIP_ACCOUNT_CONTEXT_CHECK=1 only if the account was intentionally renamed and independently verified." >&2
    exit 1
  fi
  echo
fi

if [[ "${STRIPE_SKIP_WRITE_PREFLIGHT:-0}" != "1" ]]; then
  write_preflight_cmd=(python3 "${repo_root}/billing/stripe_catalog_write_preflight.py" --stripe-bin "$STRIPE_BIN" --scope pilot --skip-account-check)
  if [[ "$USE_STRIPE_CLI" -eq 1 ]]; then
    write_preflight_cmd+=(--live)
  fi
  if [[ -n "$STRIPE_PROJECT_NAME" ]]; then
    write_preflight_cmd+=(--stripe-project-name "$STRIPE_PROJECT_NAME")
  fi
  if ! "${write_preflight_cmd[@]}"; then
    echo >&2
    echo "ERROR: Stripe pilot catalog write preflight failed. Use a write-capable live Stripe key/profile before creating the pilot catalog price." >&2
    echo "Set STRIPE_SKIP_WRITE_PREFLIGHT=1 only if you intentionally want this script to attempt writes anyway." >&2
    exit 1
  fi
  echo
fi

STRIPE_API="https://api.stripe.com/v1"
PRODUCT_NAME="TinyZKP Production Pilot"
PRODUCT_DESCRIPTION="14-day scoped TinyZKP proof-receipt workflow pilot, creditable toward annual, platform, or reserved-capacity agreement if converted within 60 days"
PRICE_LOOKUP_KEY="tinyzkp_production_pilot_5000"
UNIT_AMOUNT_CENTS="500000"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

redact_output() {
  python3 -c '
import re
import sys

text = sys.stdin.read()
text = re.sub(r"\b(?:sk|rk|whsec)_(?:live|test)_[^\s\"'\''}]+", "[redacted-key]", text)
text = re.sub(r"\b(?:acct|cs|cus|pi|sub|price|prod|mtr|req)_[A-Za-z0-9_*]+", "[redacted-id]", text)
print(text, end="")
'
}

run_stripe_cli_json() {
  local label="$1"
  local response_file="$2"
  shift 2
  local error_file="${response_file}.err"
  if "$STRIPE_BIN" "$@" "${stripe_cli_global_args[@]}" --color off --log-level error >"$response_file" 2>"$error_file"; then
    cat "$response_file"
    return 0
  fi
  echo "ERROR: Stripe CLI ${label} failed." >&2
  {
    head -20 "$error_file" 2>/dev/null || true
    head -20 "$response_file" 2>/dev/null || true
  } | redact_output >&2
  exit 1
}

extract_id() {
  python3 -c '
import json, sys
import re

def redact(text):
    text = re.sub(r"\b(?:sk|rk|whsec)_(?:live|test)_[^\s\"'\''}]+", "[redacted-key]", str(text))
    return re.sub(r"\b(?:acct|cs|cus|pi|sub|price|prod|mtr|req)_[A-Za-z0-9_*]+", "[redacted-id]", text)

d = json.load(sys.stdin)
err = d.get("error")
if err:
    print("ERROR: " + redact(err.get("message", "unknown Stripe error")), file=sys.stderr)
    sys.exit(2)
print(d.get("id", ""))
'
}

extract_first_id() {
  python3 -c '
import json, sys
import re

def redact(text):
    text = re.sub(r"\b(?:sk|rk|whsec)_(?:live|test)_[^\s\"'\''}]+", "[redacted-key]", str(text))
    return re.sub(r"\b(?:acct|cs|cus|pi|sub|price|prod|mtr|req)_[A-Za-z0-9_*]+", "[redacted-id]", text)

d = json.load(sys.stdin)
err = d.get("error")
if err:
    print("ERROR: " + redact(err.get("message", "unknown Stripe error")), file=sys.stderr)
    sys.exit(2)
items = d.get("data") or []
print((items[0] or {}).get("id", "") if items else "")
'
}

extract_pilot_price_id() {
  python3 -c '
import json, sys
import re

def redact(text):
    text = re.sub(r"\b(?:sk|rk|whsec)_(?:live|test)_[^\s\"'\''}]+", "[redacted-key]", str(text))
    return re.sub(r"\b(?:acct|cs|cus|pi|sub|price|prod|mtr|req)_[A-Za-z0-9_*]+", "[redacted-id]", text)

d = json.load(sys.stdin)
err = d.get("error")
if err:
    print("ERROR: " + redact(err.get("message", "unknown Stripe error")), file=sys.stderr)
    sys.exit(2)
for price in d.get("data") or []:
    if (
        price.get("active") is True
        and price.get("currency") == "usd"
        and price.get("unit_amount") == 500000
        and not price.get("recurring")
    ):
        print(price.get("id", ""))
        break
else:
    print("")
'
}

stripe_get() {
  local path="$1"
  shift
  curl -fsS -G "${STRIPE_API}${path}" -u "${STRIPE_API_KEY}:" "$@"
}

stripe_post() {
  local path="$1"
  local idempotency_key="$2"
  shift 2
  curl -fsS -X POST "${STRIPE_API}${path}" \
    -u "${STRIPE_API_KEY}:" \
    -H "Idempotency-Key: ${idempotency_key}" \
    "$@"
}

stripe_cli_product_search() {
  run_stripe_cli_json product-search "${tmp_dir}/product_search.json" \
    products search --live --query "name:'${PRODUCT_NAME}'" --limit 1
}

stripe_cli_product_create() {
  run_stripe_cli_json product-create "${tmp_dir}/product_create.json" \
    products create --live --confirm \
    --name "$PRODUCT_NAME" \
    --description "$PRODUCT_DESCRIPTION" \
    -d "metadata[package]=production_pilot" \
    -d "metadata[offer]=paid_pilot" \
    --idempotency tinyzkp-production-pilot-product-2026-06-25
}

stripe_cli_price_lookup() {
  run_stripe_cli_json price-lookup "${tmp_dir}/price_lookup.json" \
    prices list --live --lookup-keys "$PRICE_LOOKUP_KEY" --limit 100
}

stripe_cli_price_create() {
  run_stripe_cli_json price-create "${tmp_dir}/price_create.json" \
    prices create --live --confirm \
    --currency usd \
    --unit-amount "$UNIT_AMOUNT_CENTS" \
    --product "$product_id" \
    --lookup-key "$PRICE_LOOKUP_KEY" \
    --nickname "Production Pilot" \
    -d "metadata[package]=production_pilot" \
    -d "metadata[offer]=paid_pilot" \
    --idempotency tinyzkp-production-pilot-price-5000-2026-06-25
}

echo "Searching live Stripe product: ${PRODUCT_NAME}" >&2
if [[ "$USE_STRIPE_CLI" -eq 1 ]]; then
  echo "Using authenticated Stripe CLI live profile." >&2
  product_id="$(stripe_cli_product_search | extract_first_id)"
else
  product_id="$(
    stripe_get /products/search \
      --data-urlencode "query=name:'${PRODUCT_NAME}'" \
      --data-urlencode "limit=1" \
      | extract_first_id
  )"
fi

if [[ -z "$product_id" ]]; then
  echo "Creating live Stripe product: ${PRODUCT_NAME}" >&2
  if [[ "$USE_STRIPE_CLI" -eq 1 ]]; then
    stripe_cli_product_create >"${tmp_dir}/product.json"
    product_id="$(cat "${tmp_dir}/product.json" | extract_id)"
  else
    product_id="$(
      stripe_post /products tinyzkp-production-pilot-product-2026-06-25 \
        --data-urlencode "name=${PRODUCT_NAME}" \
        --data-urlencode "description=${PRODUCT_DESCRIPTION}" \
        -d "metadata[package]=production_pilot" \
        -d "metadata[offer]=paid_pilot" \
        >"${tmp_dir}/product.json"
      cat "${tmp_dir}/product.json" | extract_id
    )"
  fi
else
  echo "Found live Stripe product: ${product_id}" >&2
fi

echo "Searching live one-time $5,000 pilot price for product ${product_id}" >&2
if [[ "$USE_STRIPE_CLI" -eq 1 ]]; then
  price_id="$(stripe_cli_price_lookup | extract_pilot_price_id)"
else
  price_id="$(
    stripe_get /prices \
      --data-urlencode "product=${product_id}" \
      --data-urlencode "active=true" \
      --data-urlencode "limit=100" \
      | extract_pilot_price_id
  )"
fi

if [[ -z "$price_id" ]]; then
  echo "Creating live one-time pilot price." >&2
  if [[ "$USE_STRIPE_CLI" -eq 1 ]]; then
    stripe_cli_price_create >"${tmp_dir}/price.json"
    price_id="$(cat "${tmp_dir}/price.json" | extract_id)"
  else
    price_id="$(
      stripe_post /prices tinyzkp-production-pilot-price-5000-2026-06-25 \
        -d "currency=usd" \
        -d "unit_amount=${UNIT_AMOUNT_CENTS}" \
        -d "product=${product_id}" \
        -d "lookup_key=${PRICE_LOOKUP_KEY}" \
        --data-urlencode "nickname=Production Pilot" \
        -d "metadata[package]=production_pilot" \
        -d "metadata[offer]=paid_pilot" \
        >"${tmp_dir}/price.json"
      cat "${tmp_dir}/price.json" | extract_id
    )"
  fi
else
  echo "Found live pilot price: ${price_id}" >&2
fi

echo
echo "STRIPE_PRICE_ID_PILOT=${price_id}"
echo
echo "Cloudflare secret command:"
echo "  echo -n '${price_id}' | wrangler pages secret put STRIPE_PRICE_ID_PILOT --project-name tinyzkp"

if [[ "$PUSH_CLOUDFLARE" -eq 1 ]]; then
  echo
  echo "Pushing STRIPE_PRICE_ID_PILOT to Cloudflare Pages project tinyzkp." >&2
  echo -n "$price_id" | wrangler pages secret put STRIPE_PRICE_ID_PILOT --project-name tinyzkp
fi
