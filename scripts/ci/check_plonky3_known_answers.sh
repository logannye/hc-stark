#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cd "$root"
export HC_RELEASE_SHA=tinyzkp-kat-v1

cargo run -q -p hc-cli --locked --release -- plonky3 prove \
  --manifest test-vectors/plonky3/fibonacci-16.manifest.json \
  --output "$tmp/fibonacci.bundle.json"
cargo run -q -p hc-cli --locked --release -- plonky3 prove \
  --manifest test-vectors/plonky3/poseidon2-8.manifest.json \
  --output "$tmp/poseidon2.bundle.json"

cmp test-vectors/plonky3/fibonacci-16.bundle.json "$tmp/fibonacci.bundle.json"
cmp test-vectors/plonky3/poseidon2-8.bundle.json "$tmp/poseidon2.bundle.json"

cargo run -q -p hc-cli --locked --release -- plonky3 verify \
  --bundle test-vectors/plonky3/fibonacci-16.bundle.json
cargo run -q -p hc-cli --locked --release -- plonky3 verify \
  --bundle test-vectors/plonky3/poseidon2-8.bundle.json
