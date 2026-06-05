#!/usr/bin/env bash
# Reproducible O(√T) memory-scaling sweep for the streaming Stark commitment.
#
# For each trace length T we set block_size = round(√T) and measure the streaming
# (height-compressed) commit vs the full O(T) commit: peak-RSS delta, wall time,
# and the EXACT streaming working set (blocks × block_size). The streaming peak
# working set is block_size = √T elements by construction, independent of RSS
# noise; the RSS deltas corroborate the divergence at large T. One fresh process
# per size so getrusage peak-RSS isn't cross-contaminated.
#
# Usage:  ./scripts/bench/run_sqrt_sweep.sh [samples] [max_exp]
#   samples : samples per size (default 3)
#   max_exp : largest size is 4^max_exp (default 7 => 16,384; use 12 => 16,777,216)
#
# Writes the CSV to benchmarks/sqrt_sweep_latest.csv (a local, gitignored output
# dir). The committed reference run is docs/benchmarks/sqrt_memory_scaling.csv.
set -euo pipefail
cd "$(dirname "$0")/../.."

BIN=./target/release/hc-cli
if [ ! -x "$BIN" ]; then
  echo "building hc-cli (release)…" >&2
  cargo build --release -p hc-cli >&2
fi

SAMPLES="${1:-3}"
MAX_EXP="${2:-7}"
FMT=scripts/bench/_sqrt_sweep_fmt.py
mkdir -p benchmarks
OUT=benchmarks/sqrt_sweep_latest.csv
echo "leaves,block_size,stream_blocks,stream_working_set_elems,full_working_set_elems,reduction_factor,merkle_stream_peak_mb,merkle_full_peak_mb,merkle_stream_ms,merkle_full_ms,roots_match" > "$OUT"

for EXP in $(seq 3 "$MAX_EXP"); do
  T=$((4 ** EXP))                       # powers of 4 => √T is a power of 2
  BLK=$(python3 -c "import math; print(math.isqrt($T))")
  echo "  T=$T  block=$BLK  samples=$SAMPLES" >&2
  JSON=$("$BIN" bench --scenario height --leaves "$T" --block-size "$BLK" --samples "$SAMPLES" 2>/dev/null | tail -1)
  echo "$JSON" | python3 "$FMT" "$T" "$BLK" >> "$OUT"
done

echo "" >&2
echo "wrote $OUT:" >&2
column -t -s, "$OUT"
