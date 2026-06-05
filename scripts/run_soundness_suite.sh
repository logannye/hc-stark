#!/usr/bin/env bash
# TinyZKP soundness suite — the runnable demonstrations behind the deployed
# v5/v7 soundness claims, grouped by claim. Intended for the Phase-4 external
# auditor (and CI): one command to confirm the forgery boundary, the verifier
# security floor, the K-extension composition, FRI honesty, malleability
# rejection, the wire round-trip, and the AIR constraint soundness.
#
# Usage:  ./scripts/run_soundness_suite.sh
# See docs/security/auditor_guide.md for what each group demonstrates.
set -uo pipefail
cd "$(dirname "$0")/.."

pass=0
fail=0
declare -a failed

run() { # label  cargo-args...
    local label="$1"; shift
    printf '\n\033[1m== %s ==\033[0m\n' "$label"
    local out rc
    out=$(cargo test "$@" 2>&1); rc=$?
    echo "$out" | grep -E 'test result:|FAILED|error\[' | sed 's/^/  /'
    # A filter that matched no tests (all "0 passed; 0 failed") is a suite bug.
    if [ "$rc" -eq 0 ] && echo "$out" | grep -qE 'test result: ok\. [1-9]'; then
        echo "  PASS"; pass=$((pass + 1))
    else
        echo "  FAIL"; fail=$((fail + 1)); failed+=("$label")
    fi
}

echo "Building (release-agnostic test build)…"
cargo build --workspace --tests >/dev/null 2>&1 || true

run "G2 — forge-PoC: high-degree codeword REJECTED by v5"      -p hc-verifier forge_poc_g2
run "G7 — verifier security floor rejects relaxed parameters"  -p hc-verifier floor
run "1A.2 — composition challenge alpha lives in K (~2^128)"   -p hc-prover alpha
run "Transcript — extension-field challenge binds c1 (not 64-bit)" -p hc-hash nonzero_c1
run "FRI — honest low-degree final-coeffs round-trip"          -p hc-prover honest_low_degree
run "Grinding — PoW nonce satisfies the bound"                 -p hc-prover grinding
run "Determinism — v5 prove is byte-reproducible"              -p hc-prover deterministic
run "Malleability — bit-flip/truncation/extension/version proptests" -p hc-verifier --test proptest_soundness
run "Wire — production v7 round-trips through verify_proof_bytes" -p hc-sdk v7_range
run "AIR — accumulator/range/sorted constraint soundness + tamper" -p hc-air

printf '\n\033[1m== Soundness suite: %d/%d groups passed ==\033[0m\n' "$pass" "$((pass + fail))"
if [ "$fail" -ne 0 ]; then
    printf 'FAILED groups: %s\n' "${failed[*]}" >&2
    exit 1
fi
echo "All soundness demonstrations green."
