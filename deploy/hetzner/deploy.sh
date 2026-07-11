#!/usr/bin/env -S -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LANG=C LC_ALL=C TZ=UTC TINYZKP_CLEAN_LAUNCH=1 /bin/bash --noprofile --norc
# TinyZKP — one-shot production deploy for the Hetzner host.
#
# Deploys the maintenance API/MCP plus the host-level billing/contact webhook
# in the correct order so the systemd service is never left
# running stale code after a `git pull`. That exact omission broke the
# Phase 0.2 session layer on 2026-05-30: the site (Cloudflare) and API
# (hc-server container) were deployed, but `provision_tenant.py` kept
# serving pre-0.2 code because nobody restarted hc-billing-webhook —
# /session/* 404'd and the account dashboard + magic-link key-hiding broke.
#
# Run as root from anywhere on the host:  /opt/hc-stark/deploy/hetzner/deploy.sh
[[ ${TINYZKP_CLEAN_LAUNCH:-} == 1 ]] || {
    /usr/bin/printf '%s\n' 'ERROR: invoke deploy.sh directly through its clean shebang' >&2
    exit 1
}
set -euo pipefail

PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
unset PYTHONPATH PYTHONHOME NODE_OPTIONS BASH_ENV ENV CDPATH GIT_DIR GIT_WORK_TREE \
    GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM LD_PRELOAD DYLD_INSERT_LIBRARIES || true

REPO="/opt/hc-stark"
COMPOSE=(/usr/bin/docker compose -f docker-compose.yml -f deploy/hetzner/docker-compose.prod.yml)
API_LOCAL="http://127.0.0.1:8080"
WEBHOOK_LOCAL="http://127.0.0.1:5001"
PREFLIGHT_EVIDENCE="/var/lib/tinyzkp-private/deploy/production-preflight.json"
PAGES_BINDINGS_FILE="/var/lib/tinyzkp-private/deploy/pages-bindings.env"
HOST_PYTHON="/var/lib/tinyzkp-runtime/billing-venv/bin/python"
NODE_EXECUTABLE="/var/lib/tinyzkp-runtime/node-v24.18.0-linux-x64/bin/node"
WRANGLER_ENTRYPOINT="/var/lib/tinyzkp-runtime/cloudflare-toolchain/node_modules/wrangler/bin/wrangler.js"
GIT_EXECUTABLE="/usr/bin/git"
DEPLOYMENT_ID="tinyzkp-production-primary"

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: must run as root (needs systemctl + docker)." >&2
    exit 1
fi
cd "$REPO"

RELEASE_SHA="$($GIT_EXECUTABLE rev-parse HEAD)"
RELEASE_REF="$($GIT_EXECUTABLE rev-parse --abbrev-ref HEAD)"

echo "==> [1/9] Verify and consume complete production preflight evidence"
# Update the checkout to the reviewed origin/main SHA before creating the
# aggregate evidence. deploy.sh intentionally performs no fetch, checkout, or
# pull afterward because any source change would invalidate that evidence.
scripts/ci/run_production_preflight.sh \
    --verify-evidence "$PREFLIGHT_EVIDENCE" \
    --consume-evidence \
    --production \
    --env-file "$REPO/.env" \
    --pages-bindings-file "$PAGES_BINDINGS_FILE" \
    --host-python "$HOST_PYTHON" \
    --node-executable "$NODE_EXECUTABLE" \
    --wrangler-entrypoint "$WRANGLER_ENTRYPOINT" \
    --git-executable "$GIT_EXECUTABLE" \
    --deployment-id "$DEPLOYMENT_ID" \
    --expected-release-sha "$RELEASE_SHA"
export HC_RELEASE_SHA="$RELEASE_SHA"
export HC_RELEASE_REF="$RELEASE_REF"
export HC_RELEASE_BUILD_URL="${HC_RELEASE_BUILD_URL:-}"
echo "    preflight binds: $HC_RELEASE_SHA ($HC_RELEASE_REF)"

sync_host_billing_services() {
    if ! getent group tinyzkp-billing >/dev/null; then
        groupadd --system tinyzkp-billing
    fi
    if ! id -u tinyzkp-billing >/dev/null 2>&1; then
        useradd --system --gid tinyzkp-billing --home-dir /nonexistent \
            --shell /usr/sbin/nologin tinyzkp-billing
    fi
    local service_uid service_gid
    service_uid="$(id -u tinyzkp-billing)"
    service_gid="$(id -g tinyzkp-billing)"
    "$HOST_PYTHON" "$REPO/billing/backup_env_exec.py" \
        ensure-service-data-root --path /opt/hc-stark/data \
        --uid "$service_uid" --gid "$service_gid"
    install -d -o root -g root -m 0700 \
        /var/lib/tinyzkp-private /var/lib/tinyzkp-private/billing \
        /var/lib/tinyzkp-private/backup
    install -d -o root -g tinyzkp-billing -m 0710 \
        /var/lib/tinyzkp-backup-staging
    install -d -o root -g root -m 0700 /opt/hc-stark/backups
    local loader_token=/var/lib/tinyzkp-private/backup/loader-token
    "$HOST_PYTHON" "$REPO/billing/backup_env_exec.py" \
        validate-loader-token --path "$loader_token"

    rm -f /etc/cron.d/hc-backup
    cat > /etc/cron.d/hc-billing <<'CRON'
# TinyZKP backend recovery: legacy usage meters, checkout recovery, lifecycle
# nudges, and growth automation are intentionally disabled. Contract invoices
# are operator-created through the reviewed Stripe Invoicing workflow.
0 2 * * * root /opt/hc-stark/billing/backup.sh >> /var/log/hc-backup.log 2>&1
17 3 * * * tinyzkp-billing /bin/sh -c 'umask 077; exec /var/lib/tinyzkp-runtime/billing-venv/bin/python /opt/hc-stark/billing/evaluation_intake.py --db /opt/hc-stark/data/evaluation_applications.sqlite purge-expired --apply >> /opt/hc-stark/data/evaluation-retention.log 2>&1'
CRON
    chmod 644 /etc/cron.d/hc-billing

    cat > /etc/systemd/system/hc-billing-webhook.service <<'UNIT'
[Unit]
Description=TinyZKP Stripe Webhook
After=network.target

[Service]
Type=simple
User=tinyzkp-billing
Group=tinyzkp-billing
WorkingDirectory=/opt/hc-stark/billing
ExecStart=/var/lib/tinyzkp-runtime/billing-venv/bin/gunicorn -w 2 -b 127.0.0.1:5001 provision_tenant:app
Restart=on-failure
RestartSec=5
UMask=0077
Environment=PYTHONDONTWRITEBYTECODE=1
EnvironmentFile=/opt/hc-stark/.env
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/opt/hc-stark/data

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
}

echo "==> [2/9] Sync host billing cron/systemd definitions"
sync_host_billing_services

echo "==> [3/9] Production deploy readiness"
"$HOST_PYTHON" scripts/ci/deploy_readiness_check.py \
    --env-file "$REPO/.env" \
    --production \
    --check-host-python \
    --host-python "$HOST_PYTHON"

echo "==> [4/9] Reuse identity-bound maintenance container images"
echo "    image was built and identity-bound by production preflight evidence"

echo "==> [5/9] Confirm production image has no proving workers"
# The project path is fixed at /opt/hc-stark, so Compose tags this freshly
# built service image as hc-stark-hc-server:latest. Do not resolve it through
# `compose images` or `compose run`: both inspect the currently running
# container first and fail when Docker has already pruned its old image ID.
if docker run --rm --entrypoint /bin/sh hc-stark-hc-server:latest -c \
    'test ! -e /app/hc-worker && test ! -e /app/hc-job-worker'; then
    echo "    production image is capability-only"
else
    echo "    FAIL production image contains a legacy proving worker" >&2
    exit 1
fi

echo "==> [6/9] Restart maintenance API and capability-only MCP"
"${COMPOSE[@]}" up -d --no-build

echo "==> [7/9] Sync Caddy reverse-proxy config (host systemd) if changed"
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

echo "==> [8/9] Restart host billing-webhook (systemd) so provision_tenant.py / tenant_store.py changes take effect"
systemctl restart hc-billing-webhook

echo "==> [9/9] Health checks"
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
# A live, internal-secret-gated contact route returns 403 without the secret.
sr=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -X POST -H 'Content-Type: application/json' -d '{}' \
    "$WEBHOOK_LOCAL/send-contact" 2>/dev/null || echo 000)
if [ "$sr" = "403" ]; then
    echo "    OK   webhook /send-contact (403 — internal-secret gate live)"
else
    echo "    FAIL webhook /send-contact (got $sr, want 403 — webhook may be stale)"; fail=1
fi
rr=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -X POST -H 'Content-Type: application/json' -d '{}' \
    "$WEBHOOK_LOCAL/contact-readiness" 2>/dev/null || echo 000)
if [ "$rr" = "403" ]; then
    echo "    OK   webhook /contact-readiness (403 — internal-secret gate live)"
else
    echo "    FAIL webhook /contact-readiness (got $rr, want 403)"; fail=1
fi

cap=$(curl -sf --max-time 10 "$API_LOCAL/v1/capabilities" 2>/dev/null || true)
if printf '%s' "$cap" | grep -q '"proving_available":false' \
    && printf '%s' "$cap" | grep -q '"checkout_enabled":false'; then
    echo "    OK   API capabilities are recovery-only"
else
    echo "    FAIL API capabilities do not fail closed"; fail=1
fi
prove_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X POST \
    -H 'Content-Type: application/json' -d '{}' "$API_LOCAL/prove" 2>/dev/null || echo 000)
legacy_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X POST \
    -H 'Content-Type: application/json' -d '{"proof":{"version":7}}' \
    "$API_LOCAL/verify" 2>/dev/null || echo 000)
if [ "$prove_code" = "503" ] && [ "$legacy_code" = "422" ]; then
    echo "    OK   prove=503 and legacy verify=422"
else
    echo "    FAIL maintenance errors (prove=$prove_code legacy_verify=$legacy_code)"; fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "==> Host deploy complete — maintenance surfaces healthy."
    echo "    Deploy Cloudflare Pages from the same $RELEASE_SHA, then run:"
    echo "    scripts/ci/run_production_preflight.sh --production --env-file /opt/hc-stark/.env --pages-bindings-file $PAGES_BINDINGS_FILE --host-python $HOST_PYTHON --node-executable $NODE_EXECUTABLE --wrangler-entrypoint $WRANGLER_ENTRYPOINT --git-executable $GIT_EXECUTABLE --deployment-id $DEPLOYMENT_ID --live --contact-readiness-secret-file /var/lib/tinyzkp-private/deploy/internal-secret --expected-release-sha $RELEASE_SHA"
else
    echo "==> Deploy finished WITH FAILURES — investigate above." >&2
    exit 1
fi
