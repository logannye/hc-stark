#!/usr/bin/env bash
# TinyZKP — one-shot production deploy for the Hetzner host.
#
# Deploys ALL THREE production tiers in the correct order so the host-level
# billing-webhook (a systemd unit, NOT a docker service) is never left
# running stale code after a `git pull`. That exact omission broke the
# Phase 0.2 session layer on 2026-05-30: the site (Cloudflare) and API
# (hc-server container) were deployed, but `provision_tenant.py` kept
# serving pre-0.2 code because nobody restarted hc-billing-webhook —
# /session/* 404'd and the account dashboard + magic-link key-hiding broke.
#
# Run as root from anywhere on the host:  /opt/hc-stark/deploy/hetzner/deploy.sh
set -euo pipefail

REPO="/opt/hc-stark"
COMPOSE="docker compose -f docker-compose.yml -f deploy/hetzner/docker-compose.prod.yml"
API_LOCAL="http://127.0.0.1:8080"
WEBHOOK_LOCAL="http://127.0.0.1:5001"
SHARED_DISPATCH=0

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: must run as root (needs systemctl + docker)." >&2
    exit 1
fi
cd "$REPO"

if [ "${HC_SERVER_PROVE_DISPATCH:-}" = "shared" ] \
    || { [ -f "$REPO/.env" ] && grep -Eq '^HC_SERVER_PROVE_DISPATCH=["'\'']?shared["'\'']?$' "$REPO/.env"; }; then
    SHARED_DISPATCH=1
    case ",${COMPOSE_PROFILES:-}," in
        *,shared-workers,*) ;;
        *)
            export COMPOSE_PROFILES="${COMPOSE_PROFILES:+$COMPOSE_PROFILES,}shared-workers"
            echo "==> HC_SERVER_PROVE_DISPATCH=shared detected; enabling compose profile: $COMPOSE_PROFILES"
            ;;
    esac
fi

sync_host_billing_services() {
    cat > /etc/cron.d/hc-billing <<'CRON'
0 * * * * root cd /opt/hc-stark && /opt/hc-stark/.venv/bin/python billing/sync_usage.py >> /var/log/hc-billing.log 2>&1
15 * * * * root cd /opt/hc-stark && /opt/hc-stark/.venv/bin/python billing/lifecycle_nudges.py >> /var/log/hc-lifecycle.log 2>&1
30 * * * * root cd /opt/hc-stark && /opt/hc-stark/.venv/bin/python billing/checkout_recovery.py >> /var/log/hc-checkout-recovery.log 2>&1
45 9 * * * root cd /opt/hc-stark && /opt/hc-stark/.venv/bin/python scripts/monitoring/gtm_growth_monitor.py --offline >> /var/log/hc-gtm-growth.log 2>&1
15 10 * * * root cd /opt/hc-stark && /opt/hc-stark/.venv/bin/python scripts/monitoring/daily_growth_decision.py >> /var/log/hc-daily-growth-decision.log 2>&1
CRON
    chmod 644 /etc/cron.d/hc-billing

    cat > /etc/systemd/system/hc-billing-webhook.service <<'UNIT'
[Unit]
Description=TinyZKP Stripe Webhook
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/hc-stark/billing
ExecStart=/opt/hc-stark/.venv/bin/gunicorn -w 2 -b 127.0.0.1:5001 provision_tenant:app
Restart=on-failure
RestartSec=5
EnvironmentFile=/opt/hc-stark/.env

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
}

echo "==> [1/10] Pull latest main"
git fetch --quiet origin main
git checkout --quiet main
git pull --ff-only origin main
RELEASE_SHA="$(git rev-parse HEAD)"
RELEASE_REF="$(git rev-parse --abbrev-ref HEAD)"
export HC_RELEASE_SHA="$RELEASE_SHA"
export HC_RELEASE_REF="$RELEASE_REF"
export HC_RELEASE_BUILD_URL="${HC_RELEASE_BUILD_URL:-}"
echo "    now at: $(git log -1 --pretty='%h %s')"
echo "    release identity: $HC_RELEASE_SHA ($HC_RELEASE_REF)"

echo "==> [2/10] Install/update host billing runtime"
deploy/hetzner/install_billing_runtime.sh

echo "==> [3/10] Sync host billing cron/systemd definitions"
sync_host_billing_services

echo "==> [4/10] Production deploy readiness"
python3 scripts/ci/deploy_readiness_check.py \
    --env-file "$REPO/.env" \
    --production \
    --check-host-python \
    --host-python "$REPO/.venv/bin/python"

echo "==> [5/10] Build containerized tiers"
$COMPOSE build

echo "==> [6/10] Shared worker config preflight"
if [ "$SHARED_DISPATCH" -eq 1 ]; then
    $COMPOSE run --rm --no-deps hc-job-worker --check-config
else
    echo "    HC_SERVER_PROVE_DISPATCH is not shared — skip hc-job-worker preflight"
fi

echo "==> [7/10] Restart containerized tiers (hc-server, hc-mcp, prometheus, grafana, alertmanager)"
$COMPOSE up -d

echo "==> [8/10] Sync Caddy reverse-proxy config (host systemd) if changed"
# Caddy runs as a HOST systemd unit reading /etc/caddy/Caddyfile — NOT a compose
# service and NOT the repo copy. A `git pull` updates deploy/hetzner/Caddyfile but
# Caddy keeps serving the old config until it is copied + reloaded. (That gap left
# wildcard CORS live after the 2026-06-04 deploy.) Sync safely: validate first,
# back up, graceful reload, and roll back on any failure.
REPO_CADDY="$REPO/deploy/hetzner/Caddyfile"
LIVE_CADDY="/etc/caddy/Caddyfile"
if systemctl is-active --quiet caddy && [ -f "$REPO_CADDY" ]; then
    if diff -q "$LIVE_CADDY" "$REPO_CADDY" >/dev/null 2>&1; then
        echo "    Caddyfile unchanged — skip"
    else
        BK="$LIVE_CADDY.bak.$(date -u +%Y%m%d_%H%M%S)"
        cp -a "$LIVE_CADDY" "$BK"
        cp "$REPO_CADDY" "$LIVE_CADDY"
        if caddy validate --config "$LIVE_CADDY" --adapter caddyfile >/dev/null 2>&1 \
            && systemctl reload caddy; then
            echo "    Caddy config synced + reloaded OK (backup: $BK)"
        else
            echo "    FAIL Caddy validate/reload — restoring $BK" >&2
            cp "$BK" "$LIVE_CADDY"
            systemctl reload caddy || true
            exit 1
        fi
    fi
else
    echo "    Caddy not a host systemd service (or repo Caddyfile missing) — skip"
fi

echo "==> [9/10] Restart host billing-webhook (systemd) so provision_tenant.py / tenant_store.py changes take effect"
systemctl restart hc-billing-webhook

echo "==> [10/10] Health checks"
sleep 5
fail=0
check() { # label url expected
    local code
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$2" 2>/dev/null || echo 000)
    if [ "$code" = "$3" ]; then
        echo "    OK   $1 ($code)"
    else
        echo "    FAIL $1 (got $code, want $3)"; fail=1
    fi
}
check "hc-server /healthz" "$API_LOCAL/healthz" 200
check "hc-server /version" "$API_LOCAL/version" 200
check "hc-mcp /version" "http://127.0.0.1:3001/version" 200
check "webhook /health"    "$WEBHOOK_LOCAL/health" 200
# A live, internal-secret-gated session route returns 403. A 404 here means
# the webhook is serving stale (pre-Phase-0.2) code — the bug this script prevents.
sr=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -X POST -H 'Content-Type: application/json' -d '{}' \
    "$WEBHOOK_LOCAL/session/resolve" 2>/dev/null || echo 000)
if [ "$sr" = "403" ]; then
    echo "    OK   webhook /session/resolve (403 — session layer live)"
else
    echo "    FAIL webhook /session/resolve (got $sr, want 403 — webhook may be stale)"; fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "==> Deploy complete — all three tiers healthy."
else
    echo "==> Deploy finished WITH FAILURES — investigate above." >&2
    exit 1
fi
