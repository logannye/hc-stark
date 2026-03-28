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
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 -L "$url" 2>/dev/null) || code="000"
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

# ══════════════════════════════════════════════════════════════════
# 4. API SERVER — Authenticated Endpoints (if API key provided)
# ══════════════════════════════════════════════════════════════════
if [ -n "$API_KEY" ]; then
    AUTH_HDR="Authorization: Bearer $API_KEY"

    log ""
    log "── API: Authenticated — Usage ──"
    usage_resp=$(test_api GET "/usage" "" "200" "15" "$AUTH_HDR")
    if ! echo "$usage_resp" | grep -q '"total_proofs"'; then
        log "  WARN  /usage response missing 'total_proofs'"
    fi

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
        log "  WARN  prove/template returned no job_id — skipping verify chain"
        TOTAL=$((TOTAL + 4))
        FAIL=$((FAIL + 4))
        FAILURES="$FAILURES\n  --- prove/template/range_proof returned no job_id"
    fi
else
    log ""
    log "── API: Authenticated — SKIPPED (no TINYZKP_AUDIT_API_KEY) ──"
fi

# ══════════════════════════════════════════════════════════════════
# 5. BILLING WEBHOOK SERVICE (2 tests)
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

# ══════════════════════════════════════════════════════════════════
# 6. CLOUDFLARE FUNCTIONS — Signup & Billing Routes (3 tests)
# ══════════════════════════════════════════════════════════════════
log ""
log "── Cloudflare Functions ──"

# Free account creation — missing email should get 400
TOTAL=$((TOTAL + 1))
free_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
    -X POST \
    -H "Content-Type: application/json" \
    -H "Origin: https://tinyzkp.com" \
    -d '{}' \
    "$SITE/api/create-free-account" 2>/dev/null) || free_code="000"
if [ "$free_code" = "400" ] || [ "$free_code" = "429" ]; then
    log "  PASS  $free_code  POST /api/create-free-account (route live)"
    PASS=$((PASS + 1))
else
    log "  FAIL  $free_code  POST /api/create-free-account (expected 400)"
    FAIL=$((FAIL + 1))
    FAILURES="$FAILURES\n  $free_code POST /api/create-free-account (expected 400)"
fi
sleep 0.5

# Checkout — missing email should get 400
TOTAL=$((TOTAL + 1))
checkout_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
    -X POST \
    -H "Content-Type: application/json" \
    -H "Origin: https://tinyzkp.com" \
    -d '{}' \
    "$SITE/api/create-checkout" 2>/dev/null) || checkout_code="000"
if [ "$checkout_code" = "400" ] || [ "$checkout_code" = "429" ]; then
    log "  PASS  $checkout_code  POST /api/create-checkout (route live)"
    PASS=$((PASS + 1))
else
    log "  FAIL  $checkout_code  POST /api/create-checkout (expected 400)"
    FAIL=$((FAIL + 1))
    FAILURES="$FAILURES\n  $checkout_code POST /api/create-checkout (expected 400)"
fi
sleep 0.5

# Contact form — missing fields should get 400
TOTAL=$((TOTAL + 1))
contact_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
    -X POST \
    -H "Content-Type: application/json" \
    -H "Origin: https://tinyzkp.com" \
    -d '{}' \
    "$SITE/api/contact" 2>/dev/null) || contact_code="000"
if [ "$contact_code" = "400" ] || [ "$contact_code" = "429" ]; then
    log "  PASS  $contact_code  POST /api/contact (route live)"
    PASS=$((PASS + 1))
else
    log "  FAIL  $contact_code  POST /api/contact (expected 400)"
    FAIL=$((FAIL + 1))
    FAILURES="$FAILURES\n  $contact_code POST /api/contact (expected 400)"
fi
sleep 0.5

# ══════════════════════════════════════════════════════════════════
# 7. WEBSITE — All Pages (7 tests)
# ══════════════════════════════════════════════════════════════════
log ""
log "── Website Pages ──"
for path in / /docs /signup /welcome /contact /terms /privacy; do
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
