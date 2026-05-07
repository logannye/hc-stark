#!/bin/bash
# ── TinyZKP Production Health Audit ───────────────────────────────
# Runs daily via launchd. Tests every production endpoint across all
# three services (API, website, billing webhook) and sends a macOS
# notification + optional Slack/Discord webhook on any failures.
#
# Usage: ./api_health_audit.sh
# Env:   TINYZKP_AUDIT_API_KEY  (optional — enables prove/verify/usage tests)
#        TINYZKP_AUDIT_WEBHOOK  (optional — Slack/Discord webhook URL)

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────
API="https://api.tinyzkp.com"
SITE="https://tinyzkp.com"
WEBHOOK_SVC="https://webhook.tinyzkp.com"
API_KEY="${TINYZKP_AUDIT_API_KEY:-}"
LOG_DIR="$HOME/hc-stark/logs/audit"
LOG_FILE="$LOG_DIR/api_audit_$(date +%Y-%m-%d).log"
WEBHOOK="${TINYZKP_AUDIT_WEBHOOK:-}"

mkdir -p "$LOG_DIR"

PASS=0
FAIL=0
FAILURES=""
TOTAL=0

log() { echo "[$(date '+%H:%M:%S')] $*" >> "$LOG_FILE"; echo "[$(date '+%H:%M:%S')] $*" >&2; }

# ── Pre-flight: wait for API ──────────────────────────────────────
WARMUP_TIMEOUT=120
WARMUP_INTERVAL=10
WARMUP_ELAPSED=0

while [ "$WARMUP_ELAPSED" -lt "$WARMUP_TIMEOUT" ]; do
    warmup_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$API/healthz" 2>/dev/null) || warmup_code="000"
    if [ "$warmup_code" = "200" ]; then
        break
    fi
    log "  WAIT  API not ready (healthz=$warmup_code, elapsed=${WARMUP_ELAPSED}s), retrying in ${WARMUP_INTERVAL}s..."
    sleep "$WARMUP_INTERVAL"
    WARMUP_ELAPSED=$((WARMUP_ELAPSED + WARMUP_INTERVAL))
done

if [ "$WARMUP_ELAPSED" -ge "$WARMUP_TIMEOUT" ]; then
    log "  ERROR  API did not become ready within ${WARMUP_TIMEOUT}s — aborting audit"
    osascript -e "display notification \"API not ready after ${WARMUP_TIMEOUT}s — audit aborted\" with title \"TinyZKP Audit\" subtitle \"Server unreachable\"" 2>/dev/null || true
    exit 1
fi

# ── Test helpers ──────────────────────────────────────────────────
# test_api METHOD PATH [BODY] [EXPECTED_STATUS] [TIMEOUT] [EXTRA_HEADERS]
test_api() {
    local method="$1"
    local path="$2"
    local body="${3:-}"
    local expected="${4:-200}"
    local timeout="${5:-30}"
    local extra_headers="${6:-}"
    local label="$method $path"

    TOTAL=$((TOTAL + 1))

    local curl_args=(-s -w "\n%{http_code}" --max-time "$timeout")

    if [ -n "$extra_headers" ]; then
        IFS='|' read -ra HDRS <<< "$extra_headers"
        for h in "${HDRS[@]}"; do
            curl_args+=(-H "$h")
        done
    fi

    if [ "$method" = "POST" ] && [ -n "$body" ]; then
        curl_args+=(-X POST -H "Content-Type: application/json" -d "$body")
    elif [ "$method" = "POST" ]; then
        curl_args+=(-X POST)
    fi

    local raw code response
    raw=$(curl "${curl_args[@]}" "$API$path" 2>/dev/null) || raw=$'\n000'
    code=$(echo "$raw" | tail -n1)
    response=$(echo "$raw" | sed '$d')

    if [ "$code" = "$expected" ]; then
        log "  PASS  $code  $label"
        PASS=$((PASS + 1))
    else
        log "  FAIL  $code  $label  (expected $expected)"
        FAIL=$((FAIL + 1))
        FAILURES="$FAILURES\n  $code $label (expected $expected)"
    fi

    echo "$response"
    sleep 0.5
}

# test_url URL [EXPECTED_STATUS]
test_url() {
    local url="$1"
    local expected="${2:-200}"
    TOTAL=$((TOTAL + 1))
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 30 -L "$url" 2>/dev/null) || code="000"
    if [ "$code" = "$expected" ]; then
        log "  PASS  $code  $url"
        PASS=$((PASS + 1))
    else
        log "  FAIL  $code  $url (expected $expected)"
        FAIL=$((FAIL + 1))
        FAILURES="$FAILURES\n  $code $url (expected $expected)"
    fi
    sleep 0.5
}

# ── Begin Audit ───────────────────────────────────────────────────
log "============================================"
log "  TinyZKP Production Health Audit"
log "  $(date '+%Y-%m-%d %H:%M')"
log "  API:     $API"
log "  Site:    $SITE"
log "  Webhook: $WEBHOOK_SVC"
if [ -n "$API_KEY" ]; then
    log "  API Key: set (${API_KEY:0:8}...)"
else
    log "  API Key: not set (skipping auth tests)"
fi
log "============================================"

# ══════════════════════════════════════════════════════════════════
# 1. API SERVER — Health & Monitoring (3 tests)
# ══════════════════════════════════════════════════════════════════
log ""
log "── API: Health & Monitoring ──"
test_api GET "/healthz"
test_api GET "/readyz"

# Metrics — verify Prometheus text format
metrics_resp=$(test_api GET "/metrics")
if ! echo "$metrics_resp" | grep -q "hc_prove_submitted_total"; then
    log "  WARN  /metrics missing expected counter hc_prove_submitted_total"
fi

# ══════════════════════════════════════════════════════════════════
# 2. API SERVER — Public Endpoints (4 tests)
# ══════════════════════════════════════════════════════════════════
log ""
log "── API: Public Endpoints ──"

# OpenAPI spec
test_api GET "/api-doc/openapi.json" > /dev/null

# Templates list — verify JSON array
templates_resp=$(test_api GET "/templates")
if ! echo "$templates_resp" | grep -q '"templates"'; then
    log "  WARN  /templates response missing 'templates' array"
fi

# Estimate — lightweight cost estimation
estimate_resp=$(test_api POST "/estimate" '{"program_length":1024}')
if ! echo "$estimate_resp" | grep -q '"estimated_cost_cents"'; then
    log "  WARN  /estimate response missing 'estimated_cost_cents'"
fi

# Template detail
test_api GET "/templates/range_proof" > /dev/null

# ══════════════════════════════════════════════════════════════════
# 3. API SERVER — Auth Rejection (3 tests)
# ══════════════════════════════════════════════════════════════════
log ""
log "── API: Auth Rejection ──"
test_api POST "/prove" \
    '{"initial_acc":0,"final_acc":10,"block_size":8,"fri_final_poly_size":4}' \
    "401" > /dev/null
test_api GET  "/usage" "" "401" > /dev/null
test_api POST "/prove/batch" \
    '{"requests":[{"initial_acc":0,"final_acc":10,"block_size":8,"fri_final_poly_size":4}]}' \
    "401" > /dev/null
# Send a structurally-valid body so the Json extractor succeeds and the
# auth check runs (matches how /prove and /prove/batch are tested above).
test_api POST "/aggregate" \
    '{"job_ids":["00000000-0000-0000-0000-000000000000"]}' \
    "401" > /dev/null
test_api GET  "/prove" "" "401" > /dev/null

# ══════════════════════════════════════════════════════════════════
# 4. API SERVER — Authenticated Endpoints (if API key provided)
# ══════════════════════════════════════════════════════════════════
if [ -n "$API_KEY" ]; then
    AUTH_HDR="Authorization: Bearer $API_KEY"

    log ""
    log "── API: Authenticated — Usage & Listing ──"
    usage_resp=$(test_api GET "/usage" "" "200" "15" "$AUTH_HDR")
    if ! echo "$usage_resp" | grep -q '"total_proofs"'; then
        log "  WARN  /usage response missing 'total_proofs'"
    fi

    # List jobs — should return JSON (possibly empty list)
    test_api GET "/prove" "" "200" "15" "$AUTH_HDR" > /dev/null

    # Authed batch happy path — single tiny job
    test_api POST "/prove/batch" \
        '{"requests":[{"workload_id":"toy_add_1_2","initial_acc":0,"final_acc":3,"block_size":8,"fri_final_poly_size":4}]}' \
        "200" "60" "$AUTH_HDR" > /dev/null

    # Aggregate — exists and rejects empty body with structural error.
    # Accept 400 or 422; either confirms the route is mounted and auth passed.
    TOTAL=$((TOTAL + 1))
    agg_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
        -X POST -H "$AUTH_HDR" -H "Content-Type: application/json" \
        -d '{}' "$API/aggregate" 2>/dev/null) || agg_code="000"
    if [ "$agg_code" = "400" ] || [ "$agg_code" = "422" ]; then
        log "  PASS  $agg_code  POST /aggregate (route live, rejects empty)"
        PASS=$((PASS + 1))
    else
        log "  FAIL  $agg_code  POST /aggregate (expected 400|422)"
        FAIL=$((FAIL + 1))
        FAILURES="$FAILURES\n  $agg_code POST /aggregate (expected 400|422)"
    fi
    sleep 0.5

    log ""
    log "── API: Authenticated — Prove + Verify ──"

    # Submit a minimal proof using the built-in toy workload
    prove_resp=$(test_api POST "/prove" \
        '{"workload_id":"toy_add_1_2","initial_acc":0,"final_acc":3,"block_size":8,"fri_final_poly_size":4}' \
        "200" "60" "$AUTH_HDR")

    JOB_ID=$(echo "$prove_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('job_id',''))" 2>/dev/null || echo "")

    if [ -n "$JOB_ID" ]; then
        # Poll for job completion (up to 90s)
        log "  INFO  Proof job submitted: $JOB_ID — polling..."
        POLL_ELAPSED=0
        POLL_TIMEOUT=90
        JOB_STATUS="pending"
        JOB_RESP=""

        while [ "$POLL_ELAPSED" -lt "$POLL_TIMEOUT" ]; do
            sleep 5
            POLL_ELAPSED=$((POLL_ELAPSED + 5))
            JOB_RESP=$(curl -s --max-time 10 -H "$AUTH_HDR" "$API/prove/$JOB_ID" 2>/dev/null || echo "")
            JOB_STATUS=$(echo "$JOB_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status',''))" 2>/dev/null || echo "")
            if [ "$JOB_STATUS" = "succeeded" ] || [ "$JOB_STATUS" = "failed" ]; then
                break
            fi
        done

        # Prove job result
        TOTAL=$((TOTAL + 1))
        if [ "$JOB_STATUS" = "succeeded" ]; then
            log "  PASS  200  GET /prove/$JOB_ID (status=succeeded, ${POLL_ELAPSED}s)"
            PASS=$((PASS + 1))
        else
            log "  FAIL  ---  GET /prove/$JOB_ID (status=$JOB_STATUS after ${POLL_ELAPSED}s)"
            FAIL=$((FAIL + 1))
            FAILURES="$FAILURES\n  --- prove job $JOB_ID status=$JOB_STATUS"
        fi

        # Inspect the proof
        if [ "$JOB_STATUS" = "succeeded" ]; then
            inspect_resp=$(test_api GET "/prove/$JOB_ID/inspect" "" "200" "15" "$AUTH_HDR")
            if ! echo "$inspect_resp" | grep -q '"trace_commitment_digest"'; then
                log "  WARN  /prove/$JOB_ID/inspect missing trace_commitment_digest"
            fi

            # Verify the proof
            PROOF_JSON=$(echo "$JOB_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(d.get('proof',{})))" 2>/dev/null || echo "{}")
            if [ "$PROOF_JSON" != "{}" ]; then
                verify_resp=$(test_api POST "/verify" \
                    "{\"proof\":$PROOF_JSON,\"allow_legacy_v2\":true}" \
                    "200" "30" "$AUTH_HDR")
                if ! echo "$verify_resp" | grep -q '"ok":true'; then
                    log "  WARN  /verify did not return ok:true"
                fi
            else
                log "  SKIP  /verify — no proof payload in job response"
                TOTAL=$((TOTAL + 1))
            fi

            # Calldata generation
            test_api GET "/proof/$JOB_ID/calldata" "" "200" "15" "$AUTH_HDR" > /dev/null
        else
            log "  SKIP  /inspect, /verify, /calldata — proof did not succeed"
            TOTAL=$((TOTAL + 3))
        fi

        # Cleanup — delete the test job
        curl -s -X DELETE -H "$AUTH_HDR" "$API/prove/$JOB_ID" --max-time 10 >/dev/null 2>&1 || true
    else
        log "  WARN  prove returned no job_id — skipping verify chain"
        TOTAL=$((TOTAL + 4))
        FAIL=$((FAIL + 4))
        FAILURES="$FAILURES\n  --- prove returned no job_id"
    fi

    log ""
    log "── API: Authenticated — Cancel + Template ──"
    # Cancel flow: submit a job, immediately cancel. The toy workload
    # finishes in <1s, so 409 ("already in a terminal state") is also a
    # healthy result — both prove the route is mounted and auth passed.
    cancel_submit=$(test_api POST "/prove" \
        '{"workload_id":"toy_add_1_2","initial_acc":0,"final_acc":3,"block_size":8,"fri_final_poly_size":4}' \
        "200" "30" "$AUTH_HDR")
    CANCEL_JOB=$(echo "$cancel_submit" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('job_id',''))" 2>/dev/null || echo "")
    if [ -n "$CANCEL_JOB" ]; then
        TOTAL=$((TOTAL + 1))
        cancel_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
            -X POST -H "$AUTH_HDR" \
            "$API/prove/$CANCEL_JOB/cancel" 2>/dev/null) || cancel_code="000"
        if [ "$cancel_code" = "200" ] || [ "$cancel_code" = "409" ]; then
            log "  PASS  $cancel_code  POST /prove/$CANCEL_JOB/cancel (route live)"
            PASS=$((PASS + 1))
        else
            log "  FAIL  $cancel_code  POST /prove/$CANCEL_JOB/cancel (expected 200|409)"
            FAIL=$((FAIL + 1))
            FAILURES="$FAILURES\n  $cancel_code POST /prove/$CANCEL_JOB/cancel (expected 200|409)"
        fi
        sleep 0.5
        curl -s -X DELETE -H "$AUTH_HDR" "$API/prove/$CANCEL_JOB" --max-time 10 >/dev/null 2>&1 || true
    else
        log "  WARN  prove for cancel test returned no job_id"
        TOTAL=$((TOTAL + 1))
        FAIL=$((FAIL + 1))
        FAILURES="$FAILURES\n  --- prove (cancel test) returned no job_id"
    fi

    # Template proof — range_proof template using minimal valid params.
    # Schema requires the parameters wrapped in a "params" object.
    template_resp=$(test_api POST "/prove/template/range_proof" \
        '{"params":{"min":0,"max":100,"witness_steps":[42]}}' \
        "200" "60" "$AUTH_HDR")
    TEMPLATE_JOB=$(echo "$template_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('job_id',''))" 2>/dev/null || echo "")
    if [ -n "$TEMPLATE_JOB" ]; then
        # Best-effort cleanup; ignore failure.
        curl -s -X DELETE -H "$AUTH_HDR" "$API/prove/$TEMPLATE_JOB" --max-time 10 >/dev/null 2>&1 || true
    fi
else
    log ""
    log "── API: Authenticated — SKIPPED (no TINYZKP_AUDIT_API_KEY) ──"
fi

# ══════════════════════════════════════════════════════════════════
# 5. BILLING WEBHOOK SERVICE (7 tests)
# ══════════════════════════════════════════════════════════════════
log ""
log "── Billing Webhook Service ──"

# Health check
test_url "$WEBHOOK_SVC/health"

# Stripe webhook route — bad signature should be rejected (400), not 404
TOTAL=$((TOTAL + 1))
stripe_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
    -X POST \
    -H "Content-Type: application/json" \
    -H "Stripe-Signature: t=0,v1=bad" \
    -d '{}' \
    "$WEBHOOK_SVC/webhook" 2>/dev/null) || stripe_code="000"
if [ "$stripe_code" = "400" ] || [ "$stripe_code" = "401" ]; then
    log "  PASS  $stripe_code  POST $WEBHOOK_SVC/webhook (rejects bad sig)"
    PASS=$((PASS + 1))
elif [ "$stripe_code" = "404" ]; then
    log "  FAIL  $stripe_code  POST $WEBHOOK_SVC/webhook (route missing)"
    FAIL=$((FAIL + 1))
    FAILURES="$FAILURES\n  $stripe_code POST $WEBHOOK_SVC/webhook (route missing)"
else
    log "  FAIL  $stripe_code  POST $WEBHOOK_SVC/webhook (expected 400|401)"
    FAIL=$((FAIL + 1))
    FAILURES="$FAILURES\n  $stripe_code POST $WEBHOOK_SVC/webhook (expected 400|401)"
fi
sleep 0.5

# Internal-only routes — require X-Internal-Secret. Hitting without the
# header should return 403 (route exists, auth-rejected). 404 = route gone.
for path in /provision-free /rotate /send-magic-link /send-contact /verify-magic-link; do
    TOTAL=$((TOTAL + 1))
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
        -X POST -H "Content-Type: application/json" -d '{}' \
        "$WEBHOOK_SVC$path" 2>/dev/null) || code="000"
    if [ "$code" = "403" ]; then
        log "  PASS  $code  POST $WEBHOOK_SVC$path (route live, internal-secret-gated)"
        PASS=$((PASS + 1))
    else
        log "  FAIL  $code  POST $WEBHOOK_SVC$path (expected 403)"
        FAIL=$((FAIL + 1))
        FAILURES="$FAILURES\n  $code POST $WEBHOOK_SVC$path (expected 403)"
    fi
    sleep 0.5
done

# ══════════════════════════════════════════════════════════════════
# 6. CLOUDFLARE FUNCTIONS — Signup, Billing, Auth, Demo (9 tests)
# ══════════════════════════════════════════════════════════════════
log ""
log "── Cloudflare Functions ──"

# Helper for CF Function structural tests — empty body should yield 400
# (validation error, route mounted), 429 (rate limited, route mounted),
# or 405 (wrong method, also route mounted). Anything else is a failure.
test_cf_function() {
    local method="$1"
    local path="$2"
    local label="$3"
    TOTAL=$((TOTAL + 1))
    local code
    if [ "$method" = "POST" ]; then
        code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
            -X POST -H "Content-Type: application/json" \
            -H "Origin: https://tinyzkp.com" \
            -d '{}' "$SITE$path" 2>/dev/null) || code="000"
    else
        code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
            -H "Origin: https://tinyzkp.com" \
            "$SITE$path" 2>/dev/null) || code="000"
    fi
    if [ "$code" = "400" ] || [ "$code" = "429" ]; then
        log "  PASS  $code  $method $path ($label)"
        PASS=$((PASS + 1))
    else
        log "  FAIL  $code  $method $path (expected 400|429)"
        FAIL=$((FAIL + 1))
        FAILURES="$FAILURES\n  $code $method $path (expected 400|429)"
    fi
    sleep 0.5
}

# Signup / billing
test_cf_function POST /api/create-free-account "free-signup route"
test_cf_function POST /api/create-checkout     "checkout route"
test_cf_function POST /api/create-portal-session "Stripe billing portal"
test_cf_function POST /api/contact             "contact form"

# Auth (magic-link)
test_cf_function POST /api/send-magic-link     "magic-link send"
test_cf_function POST /api/verify-magic-link   "magic-link verify"

# Homepage demo flow (powers /try)
test_cf_function POST /api/demo-prove          "demo prove proxy"
test_cf_function GET  /api/demo-poll           "demo poll proxy"
test_cf_function POST /api/demo-verify         "demo verify proxy"

# ══════════════════════════════════════════════════════════════════
# 7. WEBSITE — All Pages (11 tests)
# ══════════════════════════════════════════════════════════════════
log ""
log "── Website Pages ──"
for path in / /docs /signup /welcome /contact /terms /privacy /account /compute /try /status; do
    test_url "$SITE$path"
done

# ══════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════
log ""
log "============================================"
log "  RESULTS: $PASS/$TOTAL passed, $FAIL failed"
log "============================================"

if [ "$FAIL" -gt 0 ]; then
    log ""
    log "FAILURES:"
    echo -e "$FAILURES" | tee -a "$LOG_FILE"
fi

# ── Notification ──────────────────────────────────────────────────
if [ "$FAIL" -gt 0 ]; then
    SUBJECT="TinyZKP Audit: $FAIL/$TOTAL endpoints failed"

    osascript -e "display notification \"$FAIL endpoints failed — check $LOG_FILE\" with title \"TinyZKP Audit\" subtitle \"$PASS/$TOTAL passed\"" 2>/dev/null || true

    if [ -n "$WEBHOOK" ]; then
        curl -s -X POST "$WEBHOOK" \
            -H "Content-Type: application/json" \
            -d "{\"text\": \"$SUBJECT\n\n\`\`\`$(echo -e "$FAILURES")\`\`\`\"}" \
            >/dev/null 2>&1 || true
    fi

    exit 1
else
    log "All endpoints healthy."
    osascript -e "display notification \"All $TOTAL endpoints healthy\" with title \"TinyZKP Audit\" subtitle \"Daily check passed\"" 2>/dev/null || true
    exit 0
fi
