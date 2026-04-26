#!/usr/bin/env bash
# Deploy the Stripe webhook signing secret to the Hetzner production server.
#
# Usage:
#   bash billing/deploy_webhook_secret.sh <ssh-host>
#
# Example:
#   bash billing/deploy_webhook_secret.sh root@5.78.123.45
#   bash billing/deploy_webhook_secret.sh hetzner-prod          # uses ~/.ssh/config alias
#
# What it does:
#   1. Reads STRIPE_WEBHOOK_SECRET from billing/.stripe_webhook_secret
#      (created by setup_stripe_webhook.sh).
#   2. SCPs the secret file to /tmp/whsec on the prod server.
#   3. Idempotently updates /opt/hc-stark/.env:
#        - If STRIPE_WEBHOOK_SECRET=... already exists, replaces it.
#        - Otherwise appends the new line.
#   4. Removes the temp file from /tmp.
#   5. Restarts ONLY the billing-webhook container (faster than the full
#      stack — minimal customer impact, ~2s downtime on the webhook).
#   6. Verifies the handler comes back up by probing webhook.tinyzkp.com.
#
# The secret value never appears in stdout, the SSH command line, or git.

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: bash $0 <ssh-host>" >&2
  echo "Example: bash $0 root@5.78.123.45" >&2
  exit 1
fi

SSH_HOST="$1"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECRET_FILE="${REPO_ROOT}/billing/.stripe_webhook_secret"
ENV_PATH="/opt/hc-stark/.env"
COMPOSE_BASE="/opt/hc-stark/docker-compose.yml"
COMPOSE_PROD="/opt/hc-stark/deploy/hetzner/docker-compose.prod.yml"

# ── Pre-flight ────────────────────────────────────────────────────────

if [[ ! -f "$SECRET_FILE" ]]; then
  echo "ERROR: $SECRET_FILE not found." >&2
  echo "Run setup_stripe_webhook.sh first to generate the signing secret." >&2
  exit 1
fi

# Verify the file actually contains a STRIPE_WEBHOOK_SECRET=whsec_... line.
if ! grep -qE '^STRIPE_WEBHOOK_SECRET=whsec_' "$SECRET_FILE"; then
  echo "ERROR: $SECRET_FILE does not contain a valid STRIPE_WEBHOOK_SECRET=whsec_... line." >&2
  exit 1
fi

echo "Pre-flight: testing SSH connectivity to $SSH_HOST ..."
if ! ssh -o BatchMode=yes -o ConnectTimeout=10 "$SSH_HOST" 'echo ok' >/dev/null 2>&1; then
  echo "ERROR: Could not reach $SSH_HOST via SSH (BatchMode, no password prompts)." >&2
  echo "Try: ssh $SSH_HOST 'echo ok'  manually first to confirm key-based auth is set up." >&2
  exit 1
fi
echo "  SSH reachable."
echo

# ── 1. Transfer the secret file to the server ─────────────────────────

echo "Step 1: transferring secret file to $SSH_HOST:/tmp/whsec ..."
scp -q -o BatchMode=yes "$SECRET_FILE" "$SSH_HOST:/tmp/whsec"
ssh -o BatchMode=yes "$SSH_HOST" 'chmod 600 /tmp/whsec'
echo "  Transferred."
echo

# ── 2. Update /opt/hc-stark/.env idempotently ─────────────────────────

echo "Step 2: updating $ENV_PATH ..."
# The remote one-liner:
#   - If $ENV_PATH doesn't exist yet, copy /tmp/whsec to it (creates the file).
#   - Otherwise: extract the new STRIPE_WEBHOOK_SECRET= line from /tmp/whsec.
#     If $ENV_PATH already has a STRIPE_WEBHOOK_SECRET= line, replace it via
#     sed; if not, append. Use a backup copy in case anything goes wrong.
ssh -o BatchMode=yes "$SSH_HOST" bash -s <<'REMOTE_SCRIPT'
set -euo pipefail
ENV_PATH=/opt/hc-stark/.env
TMP_NEW=/tmp/whsec

# Extract just the data line, ignoring comments.
NEW_LINE=$(grep -E '^STRIPE_WEBHOOK_SECRET=whsec_' "$TMP_NEW" | head -1)
if [[ -z "$NEW_LINE" ]]; then
  echo "ERROR: $TMP_NEW did not contain a valid line" >&2
  exit 1
fi

if [[ ! -f "$ENV_PATH" ]]; then
  # First time: copy the data line into a fresh .env (mode 600).
  install -m 600 -D /dev/null "$ENV_PATH"
  echo "$NEW_LINE" >> "$ENV_PATH"
  echo "  Created $ENV_PATH with STRIPE_WEBHOOK_SECRET set."
else
  cp "$ENV_PATH" "${ENV_PATH}.bak.$(date +%Y%m%d%H%M%S)"
  if grep -qE '^STRIPE_WEBHOOK_SECRET=' "$ENV_PATH"; then
    # Replace existing line. Use a temp file so we don't truncate on error.
    awk -v new="$NEW_LINE" '
      /^STRIPE_WEBHOOK_SECRET=/ { print new; replaced=1; next }
      { print }
      END { if (!replaced) print new }
    ' "$ENV_PATH" > "${ENV_PATH}.new"
    mv "${ENV_PATH}.new" "$ENV_PATH"
    chmod 600 "$ENV_PATH"
    echo "  Replaced existing STRIPE_WEBHOOK_SECRET in $ENV_PATH."
  else
    echo "$NEW_LINE" >> "$ENV_PATH"
    chmod 600 "$ENV_PATH"
    echo "  Appended STRIPE_WEBHOOK_SECRET to $ENV_PATH."
  fi
fi

# Clean up the temp file immediately. Don't leave secrets in /tmp.
rm -f "$TMP_NEW"
echo "  Cleaned up /tmp/whsec."
REMOTE_SCRIPT
echo

# ── 3. Restart the billing-webhook container ──────────────────────────

echo "Step 3: restarting billing-webhook container ..."
ssh -o BatchMode=yes "$SSH_HOST" bash -s <<REMOTE_SCRIPT
set -euo pipefail
cd /opt/hc-stark
# The 'up -d billing-webhook' picks up the new env without restarting the
# rest of the stack. If the .env value changed, docker-compose recreates
# only the billing-webhook container.
docker compose -f "${COMPOSE_BASE#/opt/hc-stark/}" -f "${COMPOSE_PROD#/opt/hc-stark/}" up -d billing-webhook 2>&1 | tail -5
REMOTE_SCRIPT
echo

# ── 4. Verify the handler is back up ─────────────────────────────────

echo "Step 4: verifying webhook.tinyzkp.com is responding ..."
sleep 3
PROBE="$(curl -sS -o /dev/null -w '%{http_code}' -X POST https://webhook.tinyzkp.com/webhook \
  -H 'Content-Type: application/json' -d '{}')"
case "$PROBE" in
  400|401|403|405)
    echo "  Handler healthy (HTTP $PROBE — expected for unsigned probe)"
    ;;
  5*)
    echo "WARNING: Handler returned HTTP $PROBE — check container logs:" >&2
    echo "  ssh $SSH_HOST 'cd /opt/hc-stark && docker compose logs --tail=30 billing-webhook'" >&2
    ;;
  *)
    echo "  Handler returned HTTP $PROBE on probe."
    ;;
esac

echo
echo "=== Done ==="
echo "STRIPE_WEBHOOK_SECRET is now live on $SSH_HOST:$ENV_PATH"
echo "billing-webhook container has been recreated with the new env."
echo
echo "Test it end-to-end with a real Stripe event:"
echo "  STRIPE_API_KEY=\$STRIPE_API_KEY stripe trigger checkout.session.completed"
echo "  ssh $SSH_HOST 'cd /opt/hc-stark && docker compose logs --tail=10 billing-webhook'"
