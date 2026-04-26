#!/usr/bin/env bash
# Idempotent Stripe webhook endpoint setup for TinyZKP.
#
# Usage:
#   STRIPE_API_KEY=sk_live_YOUR_FULL_KEY bash billing/setup_stripe_webhook.sh
#
# The script:
#   1. Pre-flight checks the key and probes webhook.tinyzkp.com to confirm
#      the handler is reachable.
#   2. Lists existing webhooks; if one already matches the URL we're trying
#      to register, prints its ID and bails (to avoid duplicates). The user
#      can then either delete the existing webhook in the Dashboard, or
#      run this script with FORCE_ROTATE=1 to rotate the secret on the
#      existing endpoint.
#   3. Creates a new webhook subscribed to the 4 required events, OR
#      rotates the secret on the existing one if FORCE_ROTATE=1.
#   4. Writes the signing secret (whsec_...) to billing/.stripe_webhook_secret
#      (gitignored). Caller is then expected to deploy that secret to
#      whichever environment runs the webhook handler — typically
#      /opt/hc-stark/.env on the production server, NOT Cloudflare Pages.

set -euo pipefail

WEBHOOK_URL="https://webhook.tinyzkp.com/webhook"
EVENTS='checkout.session.completed,customer.subscription.updated,customer.subscription.deleted,invoice.payment_failed'
STRIPE_API="https://api.stripe.com/v1"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECRET_OUT="${REPO_ROOT}/billing/.stripe_webhook_secret"

# ── Pre-flight ────────────────────────────────────────────────────────

if [[ -z "${STRIPE_API_KEY:-}" ]]; then
  echo "ERROR: STRIPE_API_KEY is not set." >&2
  echo "Run with: STRIPE_API_KEY=sk_live_... bash billing/setup_stripe_webhook.sh" >&2
  exit 1
fi
if [[ ! "$STRIPE_API_KEY" =~ ^sk_live_ ]]; then
  echo "ERROR: STRIPE_API_KEY must start with sk_live_." >&2
  exit 1
fi

echo "Pre-flight: probing $WEBHOOK_URL ..."
PROBE="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$WEBHOOK_URL" -H 'Content-Type: application/json' -d '{}')"
if [[ "$PROBE" == "400" || "$PROBE" == "401" || "$PROBE" == "403" ]]; then
  echo "  Handler is responding (HTTP $PROBE — expected for unsigned probe)"
elif [[ "$PROBE" == "405" ]]; then
  echo "  Handler accepts POST but rejected this empty body (HTTP 405). Continuing."
elif [[ "$PROBE" == "5"* ]]; then
  echo "WARNING: Handler returned HTTP $PROBE (server error). Continuing anyway." >&2
elif [[ -z "$PROBE" || "$PROBE" == "000" ]]; then
  echo "ERROR: Could not reach $WEBHOOK_URL — DNS or network issue." >&2
  exit 1
else
  echo "  Handler returned HTTP $PROBE on probe. Continuing."
fi
echo

# ── 1. Look up existing webhook endpoints ──────────────────────────────

urlencode() { python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$1"; }

echo "Step 1: checking for existing webhook endpoint at $WEBHOOK_URL ..."
LIST_BODY="$(curl -sS "${STRIPE_API}/webhook_endpoints?limit=100" -u "${STRIPE_API_KEY}:")"
EXISTING_ID="$(WEBHOOK_URL="$WEBHOOK_URL" python3 -c "
import json, sys, os
target = os.environ.get('WEBHOOK_URL', '')
try:
    d = json.loads(sys.stdin.read())
    for ep in d.get('data', []):
        if ep.get('url') == target:
            print(ep.get('id', ''))
            sys.exit(0)
except Exception as e:
    sys.stderr.write(f'parse error: {e}\n')
" <<<"$LIST_BODY")"

if [[ -n "$EXISTING_ID" ]]; then
  echo "  Found existing webhook: $EXISTING_ID"
  if [[ "${FORCE_ROTATE:-}" != "1" ]]; then
    echo
    echo "Webhook already exists. Two paths:"
    echo "  A) Reuse it. The current signing secret is NOT retrievable via the"
    echo "     API; reveal it once via the Dashboard:"
    echo "       https://dashboard.stripe.com/webhooks/${EXISTING_ID}"
    echo "     Then deploy STRIPE_WEBHOOK_SECRET to /opt/hc-stark/.env."
    echo "  B) Rotate the secret. Re-run with FORCE_ROTATE=1:"
    echo "       FORCE_ROTATE=1 STRIPE_API_KEY=\$STRIPE_API_KEY bash $0"
    echo "     A NEW whsec_ is generated; the old one stops verifying."
    exit 0
  fi
  echo "  FORCE_ROTATE=1 set — rotating signing secret on the existing endpoint."
  RESP="$(curl -sS -X POST "${STRIPE_API}/webhook_endpoints/${EXISTING_ID}" \
    -u "${STRIPE_API_KEY}:" -d 'rotate_secret=true')"
  WEBHOOK_ID="$EXISTING_ID"
else
  echo "  No existing webhook for this URL. Creating a new one."
  echo
  POST_DATA="url=$(urlencode "$WEBHOOK_URL")"
  IFS=',' read -ra EVT <<< "$EVENTS"
  for e in "${EVT[@]}"; do
    POST_DATA+="&enabled_events[]=$(urlencode "$e")"
  done
  POST_DATA+="&description=$(urlencode "TinyZKP production webhook")"
  RESP="$(curl -sS -X POST "${STRIPE_API}/webhook_endpoints" \
    -u "${STRIPE_API_KEY}:" --data "$POST_DATA")"
  WEBHOOK_ID="$(python3 -c "
import json, sys
d = json.loads(sys.stdin.read())
err = d.get('error')
if err:
    sys.stderr.write('ERROR: ' + err.get('message', 'unknown') + '\n')
    sys.exit(2)
print(d.get('id', ''))
" <<<"$RESP")" || { echo "$RESP" | head -5 >&2; exit 1; }
fi

# ── 2. Extract the signing secret ─────────────────────────────────────

WHSEC="$(python3 -c "
import json, sys
d = json.loads(sys.stdin.read())
err = d.get('error')
if err:
    sys.stderr.write('ERROR: ' + err.get('message', 'unknown') + '\n')
    sys.exit(2)
print(d.get('secret', ''))
" <<<"$RESP")" || { echo "$RESP" | head -5 >&2; exit 1; }

if [[ -z "$WHSEC" ]]; then
  echo "ERROR: Webhook was created/rotated but response did not include 'secret'." >&2
  echo "Full response:" >&2
  echo "$RESP" | head -20 >&2
  exit 1
fi

# ── 3. Persist the secret ─────────────────────────────────────────────

umask 077  # owner-only permissions on the secret file
cat >"$SECRET_OUT" <<EOF
# TinyZKP Stripe webhook signing secret
# Generated $(date -u +%Y-%m-%dT%H:%M:%SZ) by setup_stripe_webhook.sh
# DO NOT COMMIT — billing/.stripe_webhook_secret is gitignored.
#
# WEBHOOK_ID=$WEBHOOK_ID
# Subscribed events: $EVENTS

STRIPE_WEBHOOK_SECRET=$WHSEC
EOF

echo
echo "=== Done ==="
echo "Webhook endpoint: $WEBHOOK_ID"
echo "Subscribed events: $EVENTS"
echo
echo "Signing secret saved to: $SECRET_OUT (gitignored, owner-readable only)"
echo
echo "Next: deploy STRIPE_WEBHOOK_SECRET to the webhook handler's environment."
echo "Typical sequence (adjust hostname/path/service to your setup):"
echo "  scp \"$SECRET_OUT\" prod-server:/tmp/whsec"
echo "  ssh prod-server 'cat /tmp/whsec >> /opt/hc-stark/.env && rm /tmp/whsec && systemctl restart hc-webhook'"
