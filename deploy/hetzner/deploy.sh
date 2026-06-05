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

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: must run as root (needs systemctl + docker)." >&2
    exit 1
fi
cd "$REPO"

echo "==> [1/5] Pull latest main"
git fetch --quiet origin main
git checkout --quiet main
git pull --ff-only origin main
echo "    now at: $(git log -1 --pretty='%h %s')"

echo "==> [2/5] Rebuild + restart containerized tiers (hc-server, hc-mcp, prometheus, grafana, alertmanager)"
$COMPOSE up -d --build

echo "==> [3/5] Sync Caddy reverse-proxy config (host systemd) if changed"
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

echo "==> [4/5] Restart host billing-webhook (systemd) so provision_tenant.py / tenant_store.py changes take effect"
systemctl restart hc-billing-webhook

echo "==> [5/5] Health checks"
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
