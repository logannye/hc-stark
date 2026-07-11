#!/usr/bin/env -S -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LANG=C LC_ALL=C TZ=UTC TINYZKP_CLEAN_LAUNCH=1 /bin/bash --noprofile --norc
# TinyZKP transactional containment deploy for the reviewed production host.
#
# This script consumes release-bound production evidence, takes an exclusive
# deployment lock, records the complete mutable pre-state, and deploys only
# immutable release-SHA images. Any error, normal premature exit, or catchable
# signal rolls back to the transaction's recorded prior known-containment
# release. A first containment deploy with no authorized prior release stops
# every backend surface instead of restoring a legacy prover.
[[ ${TINYZKP_CLEAN_LAUNCH:-} == 1 ]] || {
    /usr/bin/printf '%s\n' 'ERROR: invoke deploy.sh directly through its clean shebang' >&2
    exit 1
}
set -Eeuo pipefail
umask 077

PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
unset PYTHONPATH PYTHONHOME NODE_OPTIONS BASH_ENV ENV CDPATH GIT_DIR GIT_WORK_TREE \
    GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM LD_PRELOAD DYLD_INSERT_LIBRARIES || true

REPO="/opt/hc-stark"
COMPOSE=(/usr/bin/docker compose -f docker-compose.yml -f deploy/hetzner/docker-compose.prod.yml)
API_LOCAL="http://127.0.0.1:8080"
MCP_LOCAL="http://127.0.0.1:3001"
WEBHOOK_LOCAL="http://127.0.0.1:5001"
DEPLOY_STATE="/var/lib/tinyzkp-private/deploy"
DEPLOY_LOCK="$DEPLOY_STATE/deployment.lock"
TRANSACTION_TOOL="$REPO/deploy/hetzner/deployment_transaction.py"
PREFLIGHT_EVIDENCE="$DEPLOY_STATE/production-preflight.json"
PAGES_BINDINGS_FILE="$DEPLOY_STATE/pages-bindings.env"
HOST_PYTHON="/var/lib/tinyzkp-runtime/billing-venv/bin/python"
NODE_EXECUTABLE="/var/lib/tinyzkp-runtime/node-v24.18.0-linux-x64/bin/node"
WRANGLER_ENTRYPOINT="/var/lib/tinyzkp-runtime/cloudflare-toolchain/node_modules/wrangler/bin/wrangler.js"
GIT_EXECUTABLE="/usr/bin/git"
DEPLOYMENT_ID="tinyzkp-production-primary"
TRANSACTION_ID=""
TRANSACTION_COMMITTED=0
DEPLOY_ERROR=0

if [ "$(/usr/bin/id -u)" -ne 0 ]; then
    echo "ERROR: deployment requires root" >&2
    exit 1
fi
if [ ! -x /usr/bin/flock ]; then
    echo "ERROR: /usr/bin/flock is required" >&2
    exit 1
fi
if [ ! -d "$DEPLOY_STATE" ] || [ -L "$DEPLOY_STATE" ] \
    || [ "$(/usr/bin/stat -Lc '%U:%G:%a' "$DEPLOY_STATE")" != "root:root:700" ]; then
    echo "ERROR: $DEPLOY_STATE must already be root:root mode 0700" >&2
    exit 1
fi

exec 8>"$DEPLOY_LOCK"
if ! /usr/bin/flock -n 8; then
    echo "ERROR: another deployment or rollback holds $DEPLOY_LOCK" >&2
    exit 1
fi

rollback_on_exit() {
    local exit_code=$?
    trap - ERR EXIT HUP INT TERM
    if [ -n "$TRANSACTION_ID" ] && [ "$TRANSACTION_COMMITTED" -ne 1 ]; then
        echo "==> Deployment did not commit; invoking recorded fail-closed rollback" >&2
        if ! /usr/bin/python3 "$TRANSACTION_TOOL" rollback \
            --automatic-recorded --transaction-id "$TRANSACTION_ID"; then
            echo "CRITICAL: automatic rollback failed; backend surfaces must remain stopped" >&2
            exit_code=1
        fi
    fi
    if [ "$DEPLOY_ERROR" -ne 0 ] && [ "$exit_code" -eq 0 ]; then
        exit_code=1
    fi
    exit "$exit_code"
}
trap 'DEPLOY_ERROR=1' ERR
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
trap rollback_on_exit EXIT

cd "$REPO"
RELEASE_SHA="$($GIT_EXECUTABLE rev-parse HEAD)"
RELEASE_REF="$($GIT_EXECUTABLE rev-parse --abbrev-ref HEAD)"

echo "==> [1/10] Verify and consume complete production preflight evidence"
# deploy.sh performs no fetch, checkout, pull, build, or package installation.
# The evidence binds the already-reviewed source, runtime, billing containment,
# operator drill, Cloudflare toolchain, and immutable candidate image IDs.
scripts/ci/run_production_preflight.sh \
    --verify-evidence "$PREFLIGHT_EVIDENCE" \
    --consume-evidence \
    --require-legacy \
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
export HC_IMAGE_TAG="$RELEASE_SHA"
echo "    evidence and immutable images bind $HC_RELEASE_SHA ($HC_RELEASE_REF)"

echo "==> [2/10] Begin owner-only deployment transaction"
TRANSACTION_ID="$(/usr/bin/python3 "$TRANSACTION_TOOL" begin \
    --candidate-release-sha "$RELEASE_SHA" \
    --deployment-id "$DEPLOYMENT_ID" \
    --id-only)"
case "$TRANSACTION_ID" in
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
    *) echo "ERROR: transaction helper returned an invalid ID" >&2; exit 1 ;;
esac
echo "    transaction: $TRANSACTION_ID"

validate_host_prerequisites() {
    /usr/bin/getent group tinyzkp-billing >/dev/null
    /usr/bin/id -u tinyzkp-billing >/dev/null
    /usr/bin/test -x "$HOST_PYTHON"
    /usr/bin/test ! -e /etc/cron.d/hc-backup
    /usr/bin/test -d /opt/hc-stark/data
    /usr/bin/test -d /opt/hc-stark/backups
    /usr/bin/test -d /var/lib/tinyzkp-private/billing
    /usr/bin/test -d /var/lib/tinyzkp-private/backup
    /usr/bin/test -d /var/lib/tinyzkp-backup-staging
    "$HOST_PYTHON" "$REPO/billing/backup_env_exec.py" \
        validate-loader-token --path /var/lib/tinyzkp-private/backup/loader-token
}

echo "==> [3/10] Validate pre-provisioned host and release readiness"
validate_host_prerequisites
"$HOST_PYTHON" scripts/ci/deploy_readiness_check.py \
    --env-file "$REPO/.env" \
    --production \
    --check-host-python \
    --host-python "$HOST_PYTHON"

echo "==> [4/10] Validate every staged config, then replace atomically"
/usr/bin/python3 "$TRANSACTION_TOOL" install-configs \
    --transaction-id "$TRANSACTION_ID" >/dev/null
/usr/bin/systemctl daemon-reload
# The legacy compose unit has no immutable release input and is never allowed
# to race this transaction or start an unbound image on reboot.
if /usr/bin/systemctl cat hc-stark.service >/dev/null 2>&1; then
    /usr/bin/systemctl disable --now hc-stark.service
fi
/usr/bin/systemctl enable caddy.service hc-billing-webhook.service
/usr/bin/systemctl restart caddy.service

echo "==> [5/10] Confirm immutable candidate image has no proving workers"
if /usr/bin/docker run --rm --entrypoint /bin/sh \
    "tinyzkp/hc-server:$RELEASE_SHA" -c \
    'test ! -e /app/hc-worker && test ! -e /app/hc-job-worker'; then
    echo "    production image is capability-only"
else
    echo "ERROR: production image contains a legacy proving worker" >&2
    exit 1
fi

echo "==> [6/10] Start immutable maintenance API and capability-only MCP"
"${COMPOSE[@]}" up -d --no-build hc-server hc-mcp

echo "==> [7/10] Restart host billing/contact webhook"
/usr/bin/systemctl restart hc-billing-webhook.service

echo "==> [8/10] Run local containment health checks"
/usr/bin/sleep 5
fail=0
check() { # label url expected
    local code
    code=$(/usr/bin/curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$2" 2>/dev/null || echo 000)
    if [ "$code" = "$3" ]; then
        echo "    OK   $1 ($code)"
    else
        echo "    FAIL $1 (got $code, want $3)" >&2
        fail=1
    fi
}
check "hc-server /healthz" "$API_LOCAL/healthz" 200
check "hc-server /version" "$API_LOCAL/version" 200
check "hc-mcp /version" "$MCP_LOCAL/version" 200
check "webhook /health" "$WEBHOOK_LOCAL/health" 200

# Internal-secret routes must reject an unauthenticated local request.
contact_code=$(/usr/bin/curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -X POST -H 'Content-Type: application/json' -d '{}' \
    "$WEBHOOK_LOCAL/send-contact" 2>/dev/null || echo 000)
readiness_code=$(/usr/bin/curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -X POST -H 'Content-Type: application/json' -d '{}' \
    "$WEBHOOK_LOCAL/contact-readiness" 2>/dev/null || echo 000)
if [ "$contact_code" = 403 ] && [ "$readiness_code" = 403 ]; then
    echo "    OK   internal-secret contact routes reject anonymous requests"
else
    echo "    FAIL contact gates (send=$contact_code readiness=$readiness_code)" >&2
    fail=1
fi

cap=$(/usr/bin/curl -sf --max-time 10 "$API_LOCAL/v1/capabilities" 2>/dev/null || true)
if printf '%s' "$cap" | /usr/bin/grep -q '"proving_available":false' \
    && printf '%s' "$cap" | /usr/bin/grep -q '"verification_available":false' \
    && printf '%s' "$cap" | /usr/bin/grep -q '"checkout_enabled":false' \
    && printf '%s' "$cap" | /usr/bin/grep -q '"account_creation_enabled":false'; then
    echo "    OK   API capabilities are recovery-only"
else
    echo "    FAIL API capabilities do not fail closed" >&2
    fail=1
fi
prove_code=$(/usr/bin/curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X POST \
    -H 'Content-Type: application/json' -d '{}' "$API_LOCAL/prove" 2>/dev/null || echo 000)
legacy_code=$(/usr/bin/curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X POST \
    -H 'Content-Type: application/json' -d '{"proof":{"version":7}}' \
    "$API_LOCAL/verify" 2>/dev/null || echo 000)
if [ "$prove_code" = 503 ] && [ "$legacy_code" = 422 ]; then
    echo "    OK   prove=503 and legacy verify=422"
else
    echo "    FAIL maintenance errors (prove=$prove_code legacy=$legacy_code)" >&2
    fail=1
fi
if [ "$fail" -ne 0 ]; then
    echo "ERROR: candidate containment checks failed" >&2
    exit 1
fi

echo "==> [9/10] Commit candidate as the only known-containment release"
/usr/bin/python3 "$TRANSACTION_TOOL" commit \
    --transaction-id "$TRANSACTION_ID" >/dev/null
TRANSACTION_COMMITTED=1

echo "==> [10/10] Host containment committed"
echo "    Deploy Cloudflare Pages from the same $RELEASE_SHA, then run:"
echo "    scripts/ci/run_production_preflight.sh --require-legacy --production --env-file /opt/hc-stark/.env --pages-bindings-file $PAGES_BINDINGS_FILE --host-python $HOST_PYTHON --node-executable $NODE_EXECUTABLE --wrangler-entrypoint $WRANGLER_ENTRYPOINT --git-executable $GIT_EXECUTABLE --deployment-id $DEPLOYMENT_ID --live --contact-readiness-secret-file $DEPLOY_STATE/internal-secret --expected-release-sha $RELEASE_SHA"
