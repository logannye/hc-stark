#!/usr/bin/env bash
# TinyZKP shared-dispatch cutover smoke test.
#
# This is a focused release/staging gate for the Postgres + hc-job-worker path.
# It intentionally checks fewer things than api_health_audit.sh, but it proves
# the cutover-critical flow end to end: public lifecycle metadata, site markers,
# authenticated prove submission, poll/download, inspect, verify, cancel route,
# and usage access.
#
# Required for authenticated E2E:
#   TINYZKP_SMOKE_API_KEY or TINYZKP_AUDIT_API_KEY
#
# Useful overrides:
#   TINYZKP_SMOKE_API=https://api.tinyzkp.com
#   TINYZKP_SMOKE_SITE=https://tinyzkp.com
#   TINYZKP_SMOKE_MCP=https://mcp.tinyzkp.com
#   TINYZKP_SMOKE_PUBLIC_ONLY=1
#   TINYZKP_SMOKE_POLL_TIMEOUT=120
#   TINYZKP_SMOKE_EXPECT_ONLY_ACCUMULATOR=1

set -euo pipefail

API="${TINYZKP_SMOKE_API:-https://api.tinyzkp.com}"
SITE="${TINYZKP_SMOKE_SITE:-https://tinyzkp.com}"
MCP="${TINYZKP_SMOKE_MCP:-https://mcp.tinyzkp.com}"
API_KEY="${TINYZKP_SMOKE_API_KEY:-${TINYZKP_AUDIT_API_KEY:-}}"
PUBLIC_ONLY="${TINYZKP_SMOKE_PUBLIC_ONLY:-0}"
POLL_TIMEOUT="${TINYZKP_SMOKE_POLL_TIMEOUT:-120}"
POLL_INTERVAL="${TINYZKP_SMOKE_POLL_INTERVAL:-5}"
EXPECT_ONLY_ACCUMULATOR="${TINYZKP_SMOKE_EXPECT_ONLY_ACCUMULATOR:-1}"

TMP_DIR="$(mktemp -d)"
RESP_FILE="$TMP_DIR/response.json"
BODY_FILE="$TMP_DIR/body.json"
ERR_FILE="$TMP_DIR/curl.err"
JOB_FILE="$TMP_DIR/job.json"
VERIFY_FILE="$TMP_DIR/verify.json"
trap 'rm -rf "$TMP_DIR"' EXIT

PASS=0
FAIL=0
TOTAL=0

pass() {
  TOTAL=$((TOTAL + 1))
  PASS=$((PASS + 1))
  printf 'PASS  %s\n' "$*"
}

fail() {
  TOTAL=$((TOTAL + 1))
  FAIL=$((FAIL + 1))
  printf 'FAIL  %s\n' "$*" >&2
}

body_excerpt() {
  python3 - "$RESP_FILE" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
text = " ".join(text.split())
print(text[:240])
PY
}

request_api_file() {
  local method="$1"
  local path="$2"
  local body_path="$3"
  local expected_regex="$4"
  local timeout="${5:-30}"
  local header="${6:-}"
  local label="$method $path"

  local args=(-sS -o "$RESP_FILE" -w "%{http_code}" --max-time "$timeout")
  if [ -n "$header" ]; then
    args+=(-H "$header")
  fi
  if [ "$method" = "POST" ]; then
    args+=(-X POST -H "Content-Type: application/json")
    if [ -n "$body_path" ]; then
      args+=(--data @"$body_path")
    fi
  elif [ "$method" != "GET" ]; then
    args+=(-X "$method")
  fi

  : > "$ERR_FILE"
  local code
  code=$(curl "${args[@]}" "$API$path" 2>"$ERR_FILE") || code="000"
  if [[ "$code" =~ ^($expected_regex)$ ]]; then
    pass "$code  $label"
  else
    fail "$code  $label expected $expected_regex; body=$(body_excerpt); err=$(tr '\n' ' ' < "$ERR_FILE" | cut -c1-160)"
  fi
}

request_api_json() {
  local method="$1"
  local path="$2"
  local body="$3"
  local expected_regex="$4"
  local timeout="${5:-30}"
  local header="${6:-}"

  if [ -n "$body" ]; then
    printf '%s' "$body" > "$BODY_FILE"
    request_api_file "$method" "$path" "$BODY_FILE" "$expected_regex" "$timeout" "$header"
  else
    request_api_file "$method" "$path" "" "$expected_regex" "$timeout" "$header"
  fi
}

request_site_contains() {
  local path="$1"
  local marker="$2"
  local label="$3"
  local code

  : > "$RESP_FILE"
  : > "$ERR_FILE"
  code=$(curl -sS -L -o "$RESP_FILE" -w "%{http_code}" --max-time 30 "$SITE$path" 2>"$ERR_FILE") || code="000"
  if [ "$code" != "200" ]; then
    fail "$code  $label expected 200; err=$(tr '\n' ' ' < "$ERR_FILE" | cut -c1-160)"
    return
  fi
  if grep -Fq "$marker" "$RESP_FILE"; then
    pass "200  $label"
  else
    fail "200  $label missing marker: $marker"
  fi
}

request_mcp_json() {
  local path="$1"
  local expected_regex="$2"
  local timeout="${3:-30}"
  local code

  : > "$RESP_FILE"
  : > "$ERR_FILE"
  code=$(curl -sS -o "$RESP_FILE" -w "%{http_code}" --max-time "$timeout" "$MCP$path" 2>"$ERR_FILE") || code="000"
  if [[ "$code" =~ ^($expected_regex)$ ]]; then
    pass "$code  MCP GET $path"
  else
    fail "$code  MCP GET $path expected $expected_regex; body=$(body_excerpt); err=$(tr '\n' ' ' < "$ERR_FILE" | cut -c1-160)"
  fi
}

python_assert() {
  local label="$1"
  shift
  if python3 "$@"; then
    pass "$label"
  else
    fail "$label"
  fi
}

printf 'TinyZKP shared-dispatch smoke\n'
printf '  API:  %s\n' "$API"
printf '  SITE: %s\n' "$SITE"
printf '  MCP:  %s\n' "$MCP"
if [ -n "$API_KEY" ]; then
  printf '  Auth: set (%s...)\n' "${API_KEY:0:8}"
else
  printf '  Auth: not set\n'
fi
printf '\n'

request_api_json GET "/healthz" "" "200" 15
request_api_json GET "/readyz" "" "200" 15
request_api_json GET "/templates" "" "200" 30
python_assert "/templates exposes accumulator_step lifecycle=live" - "$RESP_FILE" "$EXPECT_ONLY_ACCUMULATOR" <<'PY'
import json, sys
path, expect_only = sys.argv[1], sys.argv[2] == "1"
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)
templates = data.get("templates")
if not isinstance(templates, list) or not templates:
    raise SystemExit("templates must be a non-empty list")
missing = [t.get("id", "<missing id>") for t in templates if not t.get("lifecycle")]
if missing:
    raise SystemExit(f"templates missing lifecycle: {missing}")
by_id = {t.get("id"): t for t in templates}
acc = by_id.get("accumulator_step")
if not acc:
    raise SystemExit("accumulator_step missing")
if acc.get("lifecycle") != "live":
    raise SystemExit(f"accumulator_step lifecycle is {acc.get('lifecycle')!r}, not 'live'")
if expect_only and sorted(by_id) != ["accumulator_step"]:
    raise SystemExit(f"unexpected default template ids: {sorted(by_id)}")
PY

if [ -n "$SITE" ]; then
  request_site_contains "/research" "One company, one thesis: space-efficient proving." "site /research reconciliation marker"
  request_site_contains "/security" "Responsible disclosure" "site /security disclosure marker"
  request_site_contains "/docs" "Template Lifecycle" "site /docs lifecycle marker"
fi

if [ -n "$MCP" ]; then
  request_mcp_json "/.well-known/mcp/server-card.json" "200" 30
  python_assert "MCP server-card advertises current public tool catalog" - "$RESP_FILE" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    card = json.load(f)
tools = {tool.get("name") for tool in card.get("tools", []) if isinstance(tool, dict)}
required = {"list_templates", "prove_template", "poll_job", "get_proof", "verify_proof"}
missing = sorted(required - tools)
if missing:
    raise SystemExit(f"missing tools: {missing}")
description = card.get("metadata", {}).get("description", "")
if "accumulator_step available now" not in description:
    raise SystemExit("missing accumulator_step available-now marker")
auth_description = card.get("authentication", {}).get("description", "")
auth_description_lower = auth_description.lower()
if "optional bearer token" not in auth_description_lower or "public lane" not in auth_description_lower:
    raise SystemExit("missing optional auth/public lane marker")
serialized = json.dumps(card).lower()
for forbidden in ["range_proof", "zkml_matmul", "spartan_r1cs"]:
    if forbidden in serialized:
        raise SystemExit(f"gated template leaked: {forbidden}")
PY
fi

if [ "$PUBLIC_ONLY" = "1" ]; then
  printf '\nPublic-only mode enabled; skipping authenticated prove flow.\n'
elif [ -z "$API_KEY" ]; then
  fail "authenticated smoke requires TINYZKP_SMOKE_API_KEY or TINYZKP_AUDIT_API_KEY"
else
  AUTH_HDR="Authorization: Bearer $API_KEY"

  request_api_json GET "/usage" "" "200" 30 "$AUTH_HDR"
  python_assert "/usage returns total_proofs" - "$RESP_FILE" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)
if "total_proofs" not in data:
    raise SystemExit("missing total_proofs")
PY

  request_api_json POST "/prove/template/accumulator_step" \
    '{"params":{"initial":0,"final":15,"deltas":[5,3,7]}}' \
    "200" 60 "$AUTH_HDR"
  JOB_ID=$(python3 - "$RESP_FILE" <<'PY'
import json, sys
try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        print(json.load(f).get("job_id", ""))
except Exception:
    print("")
PY
)
  if [ -z "$JOB_ID" ]; then
    fail "template prove returned no job_id"
  else
    printf 'INFO  submitted template job %s\n' "$JOB_ID"
    elapsed=0
    status="pending"
    poll_code="000"
    while [ "$elapsed" -lt "$POLL_TIMEOUT" ]; do
      sleep "$POLL_INTERVAL"
      elapsed=$((elapsed + POLL_INTERVAL))
      poll_code=$(curl -sS -o "$RESP_FILE" -w "%{http_code}" --max-time 20 \
        -H "$AUTH_HDR" "$API/prove/$JOB_ID" 2>"$ERR_FILE") || poll_code="000"
      status=$(python3 - "$RESP_FILE" <<'PY'
import json, sys
try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        print(json.load(f).get("status", ""))
except Exception:
    print("")
PY
)
      if [ "$status" = "succeeded" ] || [ "$status" = "failed" ]; then
        break
      fi
    done

    if [ "$poll_code" = "200" ] && [ "$status" = "succeeded" ]; then
      cp "$RESP_FILE" "$JOB_FILE"
      pass "200  GET /prove/$JOB_ID status=succeeded after ${elapsed}s"
    else
      fail "$poll_code  GET /prove/$JOB_ID status=$status after ${elapsed}s; body=$(body_excerpt)"
    fi

    if [ "$status" = "succeeded" ]; then
      request_api_json GET "/prove/$JOB_ID/inspect" "" "200" 30 "$AUTH_HDR"
      python_assert "/prove/$JOB_ID/inspect returns trace_commitment_digest" - "$RESP_FILE" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)
if not data.get("trace_commitment_digest"):
    raise SystemExit("missing trace_commitment_digest")
PY

      if python3 - "$JOB_FILE" "$VERIFY_FILE" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)
proof = data.get("proof")
if not proof:
    raise SystemExit("job response missing proof")
with open(sys.argv[2], "w", encoding="utf-8") as f:
    json.dump({"proof": proof, "allow_legacy_v2": True}, f)
PY
      then
        request_api_file POST "/verify" "$VERIFY_FILE" "200" 60 "$AUTH_HDR"
        python_assert "/verify returns ok=true" - "$RESP_FILE" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)
if data.get("ok") is not True:
    raise SystemExit(f"verify ok is {data.get('ok')!r}")
PY
      else
        fail "job response missing proof payload for /verify"
      fi

      curl -sS -X DELETE -H "$AUTH_HDR" "$API/prove/$JOB_ID" --max-time 20 >/dev/null 2>&1 || true
    fi
  fi

  request_api_json POST "/prove/template/accumulator_step" \
    '{"params":{"initial":0,"final":6,"deltas":[1,2,3]}}' \
    "200" 60 "$AUTH_HDR"
  CANCEL_JOB=$(python3 - "$RESP_FILE" <<'PY'
import json, sys
try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        print(json.load(f).get("job_id", ""))
except Exception:
    print("")
PY
)
  if [ -z "$CANCEL_JOB" ]; then
    fail "cancel smoke prove returned no job_id"
  else
    request_api_json POST "/prove/$CANCEL_JOB/cancel" "" "200|409" 20 "$AUTH_HDR"
    curl -sS -X DELETE -H "$AUTH_HDR" "$API/prove/$CANCEL_JOB" --max-time 20 >/dev/null 2>&1 || true
  fi
fi

printf '\nTinyZKP shared-dispatch smoke: %d passed, %d failed, %d total\n' "$PASS" "$FAIL" "$TOTAL"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
