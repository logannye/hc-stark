#!/bin/bash
# ── TinyZKP Production Health Audit ───────────────────────────────
# Runs daily via launchd. Tests every production endpoint across all
# production services (API, MCP, website, billing webhook) and sends a macOS
# notification + optional Slack/Discord webhook on any failures.
#
# Usage: ./api_health_audit.sh
# Env:   TINYZKP_AUDIT_API_KEY  (optional — enables prove/verify/usage tests)
#        TINYZKP_AUDIT_MCP_E2E  (optional — set to 1 for MCP prove/verify E2E)
#        TINYZKP_AUDIT_WEBHOOK  (optional — Slack/Discord webhook URL)

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────
API="https://api.tinyzkp.com"
SITE="https://tinyzkp.com"
WEBHOOK_SVC="https://webhook.tinyzkp.com"
MCP="https://mcp.tinyzkp.com"
API_KEY="${TINYZKP_AUDIT_API_KEY:-}"
MCP_E2E="${TINYZKP_AUDIT_MCP_E2E:-}"
LOG_DIR="$HOME/hc-stark/logs/audit"
LOG_FILE="$LOG_DIR/api_audit_$(date +%Y-%m-%d).log"
WEBHOOK="${TINYZKP_AUDIT_WEBHOOK:-}"

mkdir -p "$LOG_DIR"

# Scratch files. test_api writes its response body to RESP_FILE (instead of
# stdout) so callers never wrap it in $(...) — command substitution runs the
# function in a SUBSHELL, which silently discards the PASS/FAIL/TOTAL/FAILURES
# mutations. POST bodies go through BODY_FILE via `curl --data @file`, which
# avoids the ARG_MAX limit (a multi-MB proof passed as a `-d` argv aborts curl
# with "argument list too long" → recorded as a phantom 000 failure).
RESP_FILE="$(mktemp)"
BODY_FILE="$(mktemp)"
trap 'rm -f "$RESP_FILE" "$BODY_FILE"' EXIT

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
        # Stream the body from a file — a multi-MB proof passed as a `-d` argv
        # exceeds ARG_MAX and aborts curl before it runs (phantom 000 failure).
        printf '%s' "$body" > "$BODY_FILE"
        curl_args+=(-X POST -H "Content-Type: application/json" --data @"$BODY_FILE")
    elif [ "$method" = "POST" ]; then
        curl_args+=(-X POST)
    fi

    local raw code response attempt
    # Retry once on a connection-level failure (000) to absorb transient
    # cold-start/TLS blips. Real HTTP errors (4xx/5xx) return a code and are
    # never retried, so genuine outages are still reported.
    for attempt in 1 2; do
        raw=$(curl "${curl_args[@]}" "$API$path" 2>/dev/null) || raw=$'\n000'
        code=$(echo "$raw" | tail -n1)
        response=$(echo "$raw" | sed '$d')
        [ "$code" != "000" ] && break
        [ "$attempt" -eq 1 ] && sleep 2
    done

    if [ "$code" = "$expected" ]; then
        log "  PASS  $code  $label"
        PASS=$((PASS + 1))
    else
        log "  FAIL  $code  $label  (expected $expected)"
        FAIL=$((FAIL + 1))
        FAILURES="$FAILURES\n  $code $label (expected $expected)"
    fi

    # Hand the body back via RESP_FILE (NOT stdout) so callers can read it with
    # `cat "$RESP_FILE"` instead of `$(test_api …)`, which would run this whole
    # function — counters included — in a subshell and discard the tally.
    printf '%s' "$response" > "$RESP_FILE"
    sleep 0.5
}

# test_url URL [EXPECTED_STATUS]
test_url() {
    local url="$1"
    local expected="${2:-200}"
    TOTAL=$((TOTAL + 1))
    local code attempt
    for attempt in 1 2; do
        code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 30 -L "$url" 2>/dev/null) || code="000"
        [ "$code" != "000" ] && break
        [ "$attempt" -eq 1 ] && sleep 2
    done
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

# test_url_contains URL EXPECTED_STATUS MARKER LABEL
test_url_contains() {
    local url="$1"
    local expected="${2:-200}"
    local marker="$3"
    local label="$4"
    TOTAL=$((TOTAL + 1))

    local raw code response attempt
    for attempt in 1 2; do
        raw=$(curl -s -L -w "\n%{http_code}" --max-time 30 "$url" 2>/dev/null) || raw=$'\n000'
        code=$(echo "$raw" | tail -n1)
        response=$(echo "$raw" | sed '$d')
        [ "$code" != "000" ] && break
        [ "$attempt" -eq 1 ] && sleep 2
    done

    if [ "$code" != "$expected" ]; then
        log "  FAIL  $code  $label content marker (expected $expected)"
        FAIL=$((FAIL + 1))
        FAILURES="$FAILURES\n  $code $url content marker '$marker' (expected $expected)"
    elif printf '%s' "$response" | grep -Fq "$marker"; then
        log "  PASS  $code  $label content marker"
        PASS=$((PASS + 1))
    else
        log "  FAIL  $code  $label missing content marker '$marker'"
        FAIL=$((FAIL + 1))
        FAILURES="$FAILURES\n  $code $url missing content marker '$marker'"
    fi
    sleep 0.5
}

mcp_initialize() {
    local headers_file
    headers_file="$(mktemp)"
    local init_body code session
    init_body='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"tinyzkp-audit","version":"0.1.0"}}}'
    code=$(curl -s -D "$headers_file" -o "$RESP_FILE" -w "%{http_code}" --max-time 15 \
        -X POST -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -d "$init_body" "$MCP/mcp" 2>/dev/null) || code="000"
    session=$(grep -i '^mcp-session-id:' "$headers_file" | head -n1 | awk '{print $2}' | tr -d '\r')
    rm -f "$headers_file"
    printf '%s\n%s' "$code" "$session"
}

mcp_post() {
    local session="$1"
    local body="$2"
    local timeout="${3:-20}"
    curl -s -o "$RESP_FILE" -w "%{http_code}" --max-time "$timeout" \
        -X POST -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -H "Mcp-Session-Id: $session" \
        -d "$body" "$MCP/mcp" 2>/dev/null || printf '000'
}

mcp_result_text() {
    python3 - "$RESP_FILE" <<'PY'
import json, sys
path = sys.argv[1]
last = None
with open(path, "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        if not line.startswith("data:"):
            continue
        data = line[len("data:"):].strip()
        if not data or not data.startswith("{"):
            continue
        try:
            last = json.loads(data)
        except json.JSONDecodeError:
            pass
if not last:
    sys.exit(1)
result = last.get("result", {})
content = result.get("content") or []
if content and isinstance(content[0], dict) and "text" in content[0]:
    print(content[0]["text"])
else:
    print(json.dumps(result))
PY
}

# ── Begin Audit ───────────────────────────────────────────────────
log "============================================"
log "  TinyZKP Production Health Audit"
log "  $(date '+%Y-%m-%d %H:%M')"
log "  API:     $API"
log "  Site:    $SITE"
log "  Webhook: $WEBHOOK_SVC"
log "  MCP:     $MCP"
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

# Metrics — G10: /metrics is now gated by HC_METRICS_TOKEN. An unauthenticated
# request must be rejected (401); Prometheus scrapes it with the token. The
# audit confirms the gate is live, and — if HC_METRICS_TOKEN is exported —
# additionally verifies the counter is exposed to an authorized scraper.
test_api GET "/metrics" "" "401" > /dev/null
if [ -n "${HC_METRICS_TOKEN:-}" ]; then
    test_api GET "/metrics" "" "200" "15" "Authorization: Bearer $HC_METRICS_TOKEN"
    metrics_resp=$(cat "$RESP_FILE")
    if ! echo "$metrics_resp" | grep -q "hc_prove_submitted_total"; then
        log "  WARN  /metrics missing expected counter hc_prove_submitted_total"
    fi
fi

# ══════════════════════════════════════════════════════════════════
# 2. API SERVER — Public Endpoints (4 tests)
# ══════════════════════════════════════════════════════════════════
log ""
log "── API: Public Endpoints ──"

# OpenAPI spec
test_api GET "/api-doc/openapi.json" > /dev/null

# Templates list — verify JSON array
test_api GET "/templates"
templates_resp=$(cat "$RESP_FILE")
if ! echo "$templates_resp" | grep -q '"templates"'; then
    log "  WARN  /templates response missing 'templates' array"
fi

# Estimate — lightweight cost estimation
test_api POST "/estimate" '{"program_length":1024}'
estimate_resp=$(cat "$RESP_FILE")
if ! echo "$estimate_resp" | grep -q '"estimated_cost_cents"'; then
    log "  WARN  /estimate response missing 'estimated_cost_cents'"
fi

# Template detail — accumulator_step is the current built-in template
# (range_proof was retired in the v5 sound-FRI cutover, Phase 1A).
test_api GET "/templates/accumulator_step" > /dev/null

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
# /aggregate (recursive aggregation) is gated OFF pending the G2 soundness
# fix: it returns 410 Gone for any structurally-valid request, before the
# auth check. Restore this to a 401 auth-rejection test when Phase 1B
# re-enables the endpoint.
test_api POST "/aggregate" \
    '{"job_ids":["00000000-0000-0000-0000-000000000000"]}' \
    "410" > /dev/null
test_api GET  "/prove" "" "401" > /dev/null

# ══════════════════════════════════════════════════════════════════
# 4. API SERVER — Authenticated Endpoints (if API key provided)
# ══════════════════════════════════════════════════════════════════
if [ -n "$API_KEY" ]; then
    AUTH_HDR="Authorization: Bearer $API_KEY"

    log ""
    log "── API: Authenticated — Usage & Listing ──"
    test_api GET "/usage" "" "200" "15" "$AUTH_HDR"
    usage_resp=$(cat "$RESP_FILE")
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
    test_api POST "/prove" \
        '{"workload_id":"toy_add_1_2","initial_acc":0,"final_acc":3,"block_size":8,"fri_final_poly_size":4}' \
        "200" "60" "$AUTH_HDR"
    prove_resp=$(cat "$RESP_FILE")

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
            test_api GET "/prove/$JOB_ID/inspect" "" "200" "15" "$AUTH_HDR"
            inspect_resp=$(cat "$RESP_FILE")
            if ! echo "$inspect_resp" | grep -q '"trace_commitment_digest"'; then
                log "  WARN  /prove/$JOB_ID/inspect missing trace_commitment_digest"
            fi

            # Verify the proof
            PROOF_JSON=$(echo "$JOB_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(d.get('proof',{})))" 2>/dev/null || echo "{}")
            if [ "$PROOF_JSON" != "{}" ]; then
                test_api POST "/verify" \
                    "{\"proof\":$PROOF_JSON,\"allow_legacy_v2\":true}" \
                    "200" "30" "$AUTH_HDR"
                verify_resp=$(cat "$RESP_FILE")
                if ! echo "$verify_resp" | grep -q '"ok":true'; then
                    log "  WARN  /verify did not return ok:true"
                fi
            else
                log "  SKIP  /verify — no proof payload in job response"
                TOTAL=$((TOTAL + 1))
            fi

            # Calldata generation — the production prover emits sound v5/v7 proofs,
            # for which EVM calldata is intentionally unavailable (no on-chain
            # verifier has shipped for the sound proof system; the EVM path only
            # handles the legacy pre-v5 format). The endpoint returns a documented
            # 409, not a 200. Restore to 200 if/when a v5/v7 EVM verifier ships.
            test_api GET "/proof/$JOB_ID/calldata" "" "409" "15" "$AUTH_HDR"
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
    test_api POST "/prove" \
        '{"workload_id":"toy_add_1_2","initial_acc":0,"final_acc":3,"block_size":8,"fri_final_poly_size":4}' \
        "200" "30" "$AUTH_HDR"
    cancel_submit=$(cat "$RESP_FILE")
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

    # Template proof — accumulator_step template using minimal valid params
    # (range_proof was retired in the v5 cutover). Schema requires the
    # parameters wrapped in a "params" object.
    test_api POST "/prove/template/accumulator_step" \
        '{"params":{"initial":0,"final":15,"deltas":[5,3,7]}}' \
        "200" "60" "$AUTH_HDR"
    template_resp=$(cat "$RESP_FILE")
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
# 5. CRITICAL FLOWS — Stripe Checkout (positive)
# ══════════════════════════════════════════════════════════════════
# Verify the checkout endpoint can actually create a Stripe Session and
# return a real checkout.stripe.com URL. Catches Stripe key + Price ID
# misconfiguration that the structural empty-body test (which only
# checks for 400) cannot detect.
log ""
log "── Critical Flows — Stripe Checkout ──"
TOTAL=$((TOTAL + 1))
checkout_email="audit+stripe-$(date +%s)@tinyzkp.com"
checkout_resp=$(curl -s --max-time 20 \
    -X POST -H "Content-Type: application/json" \
    -H "Origin: https://tinyzkp.com" \
    -d "{\"email\":\"$checkout_email\",\"plan\":\"developer\",\"cadence\":\"monthly\",\"source\":\"api_health_audit\",\"medium\":\"monitoring\",\"intent\":\"checkout_canary\"}" \
    "$SITE/api/create-checkout" 2>/dev/null) || checkout_resp=""
checkout_url=$(echo "$checkout_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('url',''))" 2>/dev/null || echo "")
if [[ "$checkout_url" == https://checkout.stripe.com/* ]]; then
    log "  PASS  200  POST /api/create-checkout (returned valid Stripe session URL)"
    PASS=$((PASS + 1))
else
    log "  FAIL  ---  POST /api/create-checkout (no checkout.stripe.com URL in response: ${checkout_resp:0:120})"
    FAIL=$((FAIL + 1))
    FAILURES="$FAILURES\n  POST /api/create-checkout did not return a valid Stripe session URL"
fi
sleep 0.5

pilot_capability_resp=$(curl -s --max-time 10 \
    -H "Origin: https://tinyzkp.com" \
    "$SITE/api/create-pilot-checkout" 2>/dev/null) || pilot_capability_resp=""
pilot_capability_available=$(echo "$pilot_capability_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print('true' if d.get('available') is True else 'false')" 2>/dev/null || echo "false")
if [[ "$pilot_capability_available" == "true" ]]; then
    TOTAL=$((TOTAL + 1))
    pilot_checkout_email="audit+pilot-$(date +%s)@tinyzkp.com"
    pilot_checkout_resp=$(curl -s --max-time 20 \
        -X POST -H "Content-Type: application/json" \
        -H "Origin: https://tinyzkp.com" \
        -d "{\"email\":\"$pilot_checkout_email\",\"pilot_workflow\":\"Production pilot checkout canary\",\"source\":\"api_health_audit\",\"medium\":\"monitoring\",\"intent\":\"paid_pilot_checkout_canary\"}" \
        "$SITE/api/create-pilot-checkout" 2>/dev/null) || pilot_checkout_resp=""
    pilot_checkout_url=$(echo "$pilot_checkout_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('url',''))" 2>/dev/null || echo "")
    if [[ "$pilot_checkout_url" == https://checkout.stripe.com/* ]]; then
        log "  PASS  200  POST /api/create-pilot-checkout (returned valid Stripe session URL)"
        PASS=$((PASS + 1))
    else
        log "  FAIL  ---  POST /api/create-pilot-checkout (no checkout.stripe.com URL in response: ${pilot_checkout_resp:0:120})"
        FAIL=$((FAIL + 1))
        FAILURES="$FAILURES\n  POST /api/create-pilot-checkout did not return a valid Stripe session URL"
    fi
else
    log "  WARN  ---  POST /api/create-pilot-checkout skipped (capability unavailable: STRIPE_SECRET_KEY not configured)"
fi
sleep 0.5

# ══════════════════════════════════════════════════════════════════
# 6. CRITICAL FLOWS — Free Signup → Magic-Link → Session Cookie → /usage
# ══════════════════════════════════════════════════════════════════
# End-to-end exercise of the full free-tier signup pipeline:
#   CF Function → webhook → tenant DB → magic-link issuance →
#   verify-magic-link (sets tz_session cookie, no raw api_key) →
#   session-resolve → /api/usage (cookie-gated).
# Cleans up by purging the test tenant via the webhook's
# /tenant-purge admin endpoint (gated by INTERNAL_SECRET, refuses any
# tenant whose plan != "free" or whose email doesn't start with "audit+").
#
# Skipped when TINYZKP_INTERNAL_SECRET is unset — the purge step would
# leave dead tenants in the DB, so we'd rather skip the section entirely.
INTERNAL_SECRET="${TINYZKP_INTERNAL_SECRET:-}"
if [ -n "$INTERNAL_SECRET" ]; then
    log ""
    log "── Critical Flows — Free Signup E2E ──"

    # Cookie jar — mirrors a real browser session; cleaned up below.
    JAR=$(mktemp)

    audit_email="audit+autotest-$(date +%s)@tinyzkp.com"
    # Capture the HTTP status (not just the body) so a failure tells us WHICH
    # layer broke: a function-level 502 carries `upstream_status` in its JSON
    # body (the webhook's real code), whereas a bare "error code: 502" is a
    # Cloudflare platform/edge 502 for the Pages function request itself.
    : > "$RESP_FILE"   # curl -o does NOT truncate on connection failure; clear stale body first
    signup_code=$(curl -s -o "$RESP_FILE" -w "%{http_code}" --max-time 20 \
        -X POST -H "Content-Type: application/json" \
        -H "Origin: https://tinyzkp.com" \
        -d "{\"email\":\"$audit_email\"}" \
        "$SITE/api/create-free-account" 2>/dev/null) || signup_code="000"
    signup_resp=$(cat "$RESP_FILE")
    DASHBOARD_TOKEN=$(echo "$signup_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('dashboard_token','') or '')" 2>/dev/null || echo "")

    TOTAL=$((TOTAL + 1))
    if [ -n "$DASHBOARD_TOKEN" ]; then
        log "  PASS  $signup_code  POST /api/create-free-account (tenant + magic-link issued)"
        PASS=$((PASS + 1))
    else
        log "  FAIL  $signup_code  POST /api/create-free-account (no dashboard_token: ${signup_resp:0:120})"
        FAIL=$((FAIL + 1))
        FAILURES="$FAILURES\n  $signup_code POST /api/create-free-account did not return a dashboard_token"
    fi
    sleep 0.5

    NEW_TENANT_ID=""
    VERIFY_OK=""
    if [ -n "$DASHBOARD_TOKEN" ]; then
        # POST verify-magic-link with cookie jar so the HttpOnly tz_session
        # cookie is stored for all subsequent cookie-gated calls.
        verify_resp=$(curl -s --max-time 15 \
            -c "$JAR" -b "$JAR" \
            -X POST -H "Content-Type: application/json" \
            -H "Origin: https://tinyzkp.com" \
            -d "{\"token\":\"$DASHBOARD_TOKEN\"}" \
            "$SITE/api/verify-magic-link" 2>/dev/null) || verify_resp=""
        NEW_TENANT_ID=$(echo "$verify_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('tenant_id','') or '')" 2>/dev/null || echo "")

        # Assert: response must NOT contain api_key (raw key must never be returned).
        TOTAL=$((TOTAL + 1))
        has_raw_key=$(echo "$verify_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if 'api_key' in d and d['api_key'] else '')" 2>/dev/null || echo "")
        if [ -n "$has_raw_key" ]; then
            log "  FAIL  ---  POST /api/verify-magic-link leaked the raw API key (api_key present in response)"
            FAIL=$((FAIL + 1))
            FAILURES="$FAILURES\n  POST /api/verify-magic-link leaked the raw API key"
        else
            log "  PASS  ---  POST /api/verify-magic-link did not return api_key (key not exposed)"
            PASS=$((PASS + 1))
        fi

        # Assert: response must contain api_key_prefix and the session cookie must be set.
        TOTAL=$((TOTAL + 1))
        has_prefix=$(echo "$verify_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if d.get('api_key_prefix') else '')" 2>/dev/null || echo "")
        has_cookie=$(grep -q "tz_session" "$JAR" 2>/dev/null && echo "yes" || echo "")
        if [ -n "$has_prefix" ] && [ -n "$has_cookie" ]; then
            log "  PASS  200  POST /api/verify-magic-link (api_key_prefix present; tz_session cookie set)"
            PASS=$((PASS + 1))
            VERIFY_OK="yes"
        elif [ -z "$has_prefix" ]; then
            log "  FAIL  ---  POST /api/verify-magic-link (missing api_key_prefix: ${verify_resp:0:120})"
            FAIL=$((FAIL + 1))
            FAILURES="$FAILURES\n  POST /api/verify-magic-link did not return api_key_prefix"
        else
            log "  FAIL  ---  POST /api/verify-magic-link (tz_session cookie not set in jar)"
            FAIL=$((FAIL + 1))
            FAILURES="$FAILURES\n  POST /api/verify-magic-link did not set tz_session cookie"
        fi
        sleep 0.5
    fi

    if [ -n "$VERIFY_OK" ]; then
        # session-resolve positive path — cookie authenticates.
        TOTAL=$((TOTAL + 1))
        sresolve_resp=$(curl -s --max-time 15 \
            -b "$JAR" \
            -X POST -H "Content-Type: application/json" \
            -H "Origin: https://tinyzkp.com" \
            -d '{}' \
            "$SITE/api/session-resolve" 2>/dev/null) || sresolve_resp=""
        sr_prefix=$(echo "$sresolve_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('api_key_prefix','') or '')" 2>/dev/null || echo "")
        if [ -n "$sr_prefix" ]; then
            log "  PASS  200  POST /api/session-resolve (session cookie authenticates; api_key_prefix present)"
            PASS=$((PASS + 1))
        else
            log "  FAIL  ---  POST /api/session-resolve (missing api_key_prefix: ${sresolve_resp:0:120})"
            FAIL=$((FAIL + 1))
            FAILURES="$FAILURES\n  POST /api/session-resolve did not return api_key_prefix"
        fi
        sleep 0.5

        # /api/usage positive path — cookie-gated, replaces old Bearer /usage.
        TOTAL=$((TOTAL + 1))
        usage_resp=$(curl -s --max-time 15 \
            -b "$JAR" \
            -X POST -H "Content-Type: application/json" \
            -H "Origin: https://tinyzkp.com" \
            -d '{}' \
            "$SITE/api/usage" 2>/dev/null) || usage_resp=""
        usage_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
            -b "$JAR" \
            -X POST -H "Content-Type: application/json" \
            -H "Origin: https://tinyzkp.com" \
            -d '{}' \
            "$SITE/api/usage" 2>/dev/null) || usage_code="000"
        has_proofs=$(echo "$usage_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if 'total_proofs' in d else '')" 2>/dev/null || echo "")
        if [ "$usage_code" = "200" ]; then
            if [ -n "$has_proofs" ]; then
                log "  PASS  200  POST /api/usage (session cookie authenticates; total_proofs present)"
            else
                log "  PASS  200  POST /api/usage (session cookie authenticates)"
            fi
            PASS=$((PASS + 1))
        else
            log "  FAIL  $usage_code  POST /api/usage (expected 200, got $usage_code)"
            FAIL=$((FAIL + 1))
            FAILURES="$FAILURES\n  $usage_code POST /api/usage with session cookie"
        fi
        sleep 0.5

        # session-resolve negative path — no cookie should return 401.
        TOTAL=$((TOTAL + 1))
        sr_noauth_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
            -X POST -H "Content-Type: application/json" \
            -H "Origin: https://tinyzkp.com" \
            -d '{}' \
            "$SITE/api/session-resolve" 2>/dev/null) || sr_noauth_code="000"
        if [ "$sr_noauth_code" = "401" ]; then
            log "  PASS  401  POST /api/session-resolve (correctly rejects unauthenticated request)"
            PASS=$((PASS + 1))
        else
            log "  FAIL  $sr_noauth_code  POST /api/session-resolve (expected 401 without cookie)"
            FAIL=$((FAIL + 1))
            FAILURES="$FAILURES\n  $sr_noauth_code POST /api/session-resolve without cookie (expected 401)"
        fi
        sleep 0.5

        # Magic-link positive path against the just-created tenant. The
        # public route returns 200 even for unknown emails (anti-enumeration),
        # so this only catches outright route/email-service breakage —
        # delivery verification would require inbox access.
        TOTAL=$((TOTAL + 1))
        mlink_resp=$(curl -s --max-time 15 \
            -X POST -H "Content-Type: application/json" \
            -H "Origin: https://tinyzkp.com" \
            -d "{\"email\":\"$audit_email\"}" \
            "$SITE/api/send-magic-link" 2>/dev/null) || mlink_resp=""
        mlink_ok=$(echo "$mlink_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if d.get('ok') else '')" 2>/dev/null || echo "")
        if [ -n "$mlink_ok" ]; then
            log "  PASS  200  POST /api/send-magic-link (route accepted send for known tenant)"
            PASS=$((PASS + 1))
        else
            log "  FAIL  ---  POST /api/send-magic-link (no ok:true in response: ${mlink_resp:0:120})"
            FAIL=$((FAIL + 1))
            FAILURES="$FAILURES\n  POST /api/send-magic-link did not return ok:true"
        fi
        sleep 0.5
    fi

    # Cleanup — purge the test tenant and remove the cookie jar. Failure
    # here is logged but does not fail the audit (the safety guards on
    # /tenant-purge make orphan rows benign).
    rm -f "$JAR"
    if [ -n "$NEW_TENANT_ID" ]; then
        purge_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
            -X POST -H "Content-Type: application/json" \
            -H "X-Internal-Secret: $INTERNAL_SECRET" \
            -d "{\"tenant_id\":\"$NEW_TENANT_ID\"}" \
            "$WEBHOOK_SVC/tenant-purge" 2>/dev/null) || purge_code="000"
        if [ "$purge_code" = "200" ]; then
            log "  INFO  Purged audit tenant $NEW_TENANT_ID"
        else
            log "  WARN  Failed to purge audit tenant $NEW_TENANT_ID (HTTP $purge_code) — leaves orphan row"
        fi
    fi
else
    log ""
    log "── Critical Flows — Free Signup E2E — SKIPPED (no TINYZKP_INTERNAL_SECRET) ──"
fi

# ══════════════════════════════════════════════════════════════════
# 7. BILLING WEBHOOK SERVICE (7 tests)
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
for path in /provision-free /rotate /send-magic-link /send-contact /verify-magic-link /session/resolve /logout; do
    TOTAL=$((TOTAL + 1))
    # The webhook origin (Caddy → Flask systemd unit) can cold-start slowly
    # (~7s observed on /health), so use a 15s budget and retry once on a
    # connection-level 000 — otherwise a transient blip flaps the audit.
    for attempt in 1 2; do
        code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
            -X POST -H "Content-Type: application/json" -d '{}' \
            "$WEBHOOK_SVC$path" 2>/dev/null) || code="000"
        [ "$code" != "000" ] && break
        [ "$attempt" -eq 1 ] && sleep 2
    done
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
# 8. CLOUDFLARE FUNCTIONS — Signup, Billing, Auth, Demo (9 tests)
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
# create-portal-session is session-gated (G3): an unauthenticated request
# returns 401 ("no session"), not a 400 body-validation error. Confirm the
# route is mounted and refuses portal access without a session.
TOTAL=$((TOTAL + 1))
portal_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
    -X POST -H "Content-Type: application/json" -H "Origin: https://tinyzkp.com" \
    -d '{}' "$SITE/api/create-portal-session" 2>/dev/null) || portal_code="000"
if [ "$portal_code" = "401" ] || [ "$portal_code" = "429" ]; then
    log "  PASS  $portal_code  POST /api/create-portal-session (session-gated)"
    PASS=$((PASS + 1))
else
    log "  FAIL  $portal_code  POST /api/create-portal-session (expected 401|429)"
    FAIL=$((FAIL + 1))
    FAILURES="$FAILURES\n  $portal_code POST /api/create-portal-session (expected 401|429)"
fi
sleep 0.5
test_cf_function POST /api/contact             "contact form"

# Auth (magic-link)
test_cf_function POST /api/send-magic-link     "magic-link send"
test_cf_function POST /api/verify-magic-link   "magic-link verify"

# Homepage demo flow (powers /try)
test_cf_function POST /api/demo-prove          "demo prove proxy"
test_cf_function GET  /api/demo-poll           "demo poll proxy"
test_cf_function POST /api/demo-verify         "demo verify proxy"

# ══════════════════════════════════════════════════════════════════
# 9. MCP HTTP TRANSPORT — Handshake + discovery (+ optional proof E2E)
# ══════════════════════════════════════════════════════════════════
log ""
log "── MCP HTTP Transport ──"

TOTAL=$((TOTAL + 1))
mcp_init="$(mcp_initialize)"
mcp_code="$(printf '%s\n' "$mcp_init" | sed -n '1p')"
mcp_session="$(printf '%s\n' "$mcp_init" | sed -n '2p')"
mcp_init_resp="$(cat "$RESP_FILE")"
if [ "$mcp_code" = "200" ] && [ -n "$mcp_session" ] && echo "$mcp_init_resp" | grep -q '"serverInfo"'; then
    log "  PASS  $mcp_code  POST $MCP/mcp initialize (session issued)"
    PASS=$((PASS + 1))
else
    log "  FAIL  $mcp_code  POST $MCP/mcp initialize (missing session/serverInfo)"
    FAIL=$((FAIL + 1))
    FAILURES="$FAILURES\n  $mcp_code POST $MCP/mcp initialize (missing session/serverInfo)"
fi
sleep 0.5

if [ -n "$mcp_session" ]; then
    TOTAL=$((TOTAL + 1))
    init_notify_code=$(mcp_post "$mcp_session" '{"jsonrpc":"2.0","method":"notifications/initialized"}' 10)
    if [ "$init_notify_code" = "202" ]; then
        log "  PASS  $init_notify_code  POST $MCP/mcp notifications/initialized"
        PASS=$((PASS + 1))
    else
        log "  FAIL  $init_notify_code  POST $MCP/mcp notifications/initialized (expected 202)"
        FAIL=$((FAIL + 1))
        FAILURES="$FAILURES\n  $init_notify_code POST $MCP/mcp notifications/initialized (expected 202)"
    fi
    sleep 0.5

    TOTAL=$((TOTAL + 1))
    tools_code=$(mcp_post "$mcp_session" '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' 20)
    tools_resp=$(cat "$RESP_FILE")
    if [ "$tools_code" = "200" ] && echo "$tools_resp" | grep -q '"name":"list_templates"' && echo "$tools_resp" | grep -q '"name":"verify_proof"'; then
        log "  PASS  $tools_code  POST $MCP/mcp tools/list (template + verify tools present)"
        PASS=$((PASS + 1))
    else
        log "  FAIL  $tools_code  POST $MCP/mcp tools/list (missing expected tools)"
        FAIL=$((FAIL + 1))
        FAILURES="$FAILURES\n  $tools_code POST $MCP/mcp tools/list (missing list_templates/verify_proof)"
    fi
    sleep 0.5

    TOTAL=$((TOTAL + 1))
    list_templates_code=$(mcp_post "$mcp_session" '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_templates","arguments":{}}}' 20)
    list_templates_text=$(mcp_result_text 2>/dev/null || echo "")
    if [ "$list_templates_code" = "200" ] && echo "$list_templates_text" | grep -q '"id":"accumulator_step"' && echo "$list_templates_text" | grep -q '"lifecycle":"live"'; then
        log "  PASS  $list_templates_code  MCP list_templates (accumulator_step lifecycle=live)"
        PASS=$((PASS + 1))
    else
        log "  FAIL  $list_templates_code  MCP list_templates (expected accumulator_step lifecycle=live)"
        FAIL=$((FAIL + 1))
        FAILURES="$FAILURES\n  $list_templates_code MCP list_templates missing accumulator_step lifecycle=live"
    fi
    sleep 0.5

    if [ "$MCP_E2E" = "1" ]; then
        log "  INFO  TINYZKP_AUDIT_MCP_E2E=1 — running MCP prove/poll/get/verify lifecycle"

        TOTAL=$((TOTAL + 1))
        mcp_prove_body='{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"prove_template","arguments":{"template_id":"accumulator_step","parameters":{"initial":0,"final":36,"deltas":[1,2,3,4,5,6,7,8]},"zk":false}}}'
        mcp_prove_code=$(mcp_post "$mcp_session" "$mcp_prove_body" 60)
        mcp_prove_text=$(mcp_result_text 2>/dev/null || echo "")
        mcp_job_id=$(echo "$mcp_prove_text" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('job_id',''))" 2>/dev/null || echo "")
        if [ "$mcp_prove_code" = "200" ] && [ -n "$mcp_job_id" ]; then
            log "  PASS  $mcp_prove_code  MCP prove_template submitted job $mcp_job_id"
            PASS=$((PASS + 1))
        else
            log "  FAIL  $mcp_prove_code  MCP prove_template (no job_id)"
            FAIL=$((FAIL + 1))
            FAILURES="$FAILURES\n  $mcp_prove_code MCP prove_template did not return job_id"
        fi

        if [ -n "$mcp_job_id" ]; then
            mcp_poll_elapsed=0
            mcp_poll_timeout=90
            mcp_status="pending"
            while [ "$mcp_poll_elapsed" -lt "$mcp_poll_timeout" ]; do
                sleep 5
                mcp_poll_elapsed=$((mcp_poll_elapsed + 5))
                poll_body="{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"poll_job\",\"arguments\":{\"job_id\":\"$mcp_job_id\"}}}"
                mcp_poll_code=$(mcp_post "$mcp_session" "$poll_body" 20)
                mcp_poll_text=$(mcp_result_text 2>/dev/null || echo "")
                mcp_status=$(echo "$mcp_poll_text" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status',''))" 2>/dev/null || echo "")
                if [ "$mcp_status" = "succeeded" ] || [ "$mcp_status" = "failed" ]; then
                    break
                fi
            done

            TOTAL=$((TOTAL + 1))
            if [ "$mcp_status" = "succeeded" ]; then
                log "  PASS  $mcp_poll_code  MCP poll_job (status=succeeded, ${mcp_poll_elapsed}s)"
                PASS=$((PASS + 1))
            else
                log "  FAIL  $mcp_poll_code  MCP poll_job (status=$mcp_status after ${mcp_poll_elapsed}s)"
                FAIL=$((FAIL + 1))
                FAILURES="$FAILURES\n  $mcp_poll_code MCP poll_job status=$mcp_status"
            fi

            TOTAL=$((TOTAL + 1))
            proof_body="{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{\"name\":\"get_proof\",\"arguments\":{\"job_id\":\"$mcp_job_id\"}}}"
            mcp_proof_code=$(mcp_post "$mcp_session" "$proof_body" 30)
            mcp_proof_text=$(mcp_result_text 2>/dev/null || echo "")
            mcp_proof_b64=$(echo "$mcp_proof_text" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('proof_b64',''))" 2>/dev/null || echo "")
            mcp_verifier_url=$(echo "$mcp_proof_text" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('verifier_url') or '')" 2>/dev/null || echo "")
            mcp_receipt_url=$(echo "$mcp_proof_text" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('receipt_url') or '')" 2>/dev/null || echo "")
            mcp_receipt_status=$(echo "$mcp_proof_text" | python3 -c "import sys,json; d=json.load(sys.stdin); print((d.get('receipt_share') or {}).get('status',''))" 2>/dev/null || echo "")
            if [ "$mcp_proof_code" = "200" ] && [ -n "$mcp_proof_b64" ] && [[ "$mcp_verifier_url" == https://tinyzkp.com/verify\?source=receipt_share*medium=mcp* ]] && { [[ "$mcp_receipt_url" == https://tinyzkp.com/verify\?source=receipt_share*medium=mcp*"#proof="* ]] || [ "$mcp_receipt_status" = "proof_too_large" ]; }; then
                log "  PASS  $mcp_proof_code  MCP get_proof (proof_b64 + tracked verifier URL returned)"
                PASS=$((PASS + 1))
            else
                log "  FAIL  $mcp_proof_code  MCP get_proof (missing proof_b64, tracked verifier_url, or receipt status)"
                FAIL=$((FAIL + 1))
                FAILURES="$FAILURES\n  $mcp_proof_code MCP get_proof missing proof_b64, tracked verifier_url, or receipt status"
            fi

            TOTAL=$((TOTAL + 1))
            verify_body="{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"verify_proof\",\"arguments\":{\"proof_b64\":\"$mcp_proof_b64\"}}}"
            mcp_verify_code=$(mcp_post "$mcp_session" "$verify_body" 30)
            mcp_verify_text=$(mcp_result_text 2>/dev/null || echo "")
            mcp_valid=$(echo "$mcp_verify_text" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if d.get('valid') is True else '')" 2>/dev/null || echo "")
            if [ "$mcp_verify_code" = "200" ] && [ -n "$mcp_valid" ]; then
                log "  PASS  $mcp_verify_code  MCP verify_proof (valid=true)"
                PASS=$((PASS + 1))
            else
                log "  FAIL  $mcp_verify_code  MCP verify_proof (expected valid=true)"
                FAIL=$((FAIL + 1))
                FAILURES="$FAILURES\n  $mcp_verify_code MCP verify_proof expected valid=true"
            fi
        fi
    else
        log "  SKIP  MCP prove/poll/get/verify lifecycle (set TINYZKP_AUDIT_MCP_E2E=1 to enable)"
    fi
else
    log "  SKIP  MCP tools/list + list_templates — no session from initialize"
    TOTAL=$((TOTAL + 3))
    FAIL=$((FAIL + 3))
    FAILURES="$FAILURES\n  --- MCP initialize returned no session; skipped tools/list/list_templates"
fi

# ══════════════════════════════════════════════════════════════════
# 10. WEBSITE — Pages + content markers (13 status tests + markers)
# ══════════════════════════════════════════════════════════════════
log ""
log "── Website Pages ──"
for path in / /docs /signup /welcome /contact /terms /privacy /account /compute /try /status /research /security; do
    test_url "$SITE$path"
done
test_url_contains "$SITE/research" 200 "One company, one thesis: space-efficient proving." "GET /research"
test_url_contains "$SITE/security" 200 "Responsible disclosure" "GET /security"
test_url_contains "$SITE/docs"     200 "Template Lifecycle" "GET /docs"

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
