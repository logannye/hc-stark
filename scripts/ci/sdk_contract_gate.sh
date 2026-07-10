#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
schemas=$(mktemp -d)
trap 'rm -rf "$schemas"' EXIT

cd "$root"
cmp LICENSE crates/hc-wasm/LICENSE
cargo run -q -p hc-cli --locked -- schema --output-dir "$schemas"
diff -ru site/schemas "$schemas"
python3 scripts/ci/generate_sdk_schema_models.py \
  --schema-dir "$schemas" \
  --python-output clients/python/tinyzkp/schema_models.py \
  --typescript-output clients/typescript/src/schema-models.ts \
  --check

# The candidate-evidence command must be reproducible on a clean runner. Do
# not rely on an earlier CI job having installed the SDK runtime or test extra,
# and do not mutate an externally managed system Python.
python3 -m venv "$schemas/python-venv"
"$schemas/python-venv/bin/python" -m pip install -e 'clients/python[test]'
"$schemas/python-venv/bin/python" -m pytest clients/python/tests -q
npm --prefix clients/typescript ci
npm --prefix clients/typescript test
cargo test --manifest-path clients/rust/Cargo.toml --locked
cargo check -p hc-wasm --target wasm32-unknown-unknown --locked

if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "wasm-pack 0.14.0 is required for the runtime contract gate" >&2
  exit 2
fi
crates/hc-wasm/build.sh
node crates/hc-wasm/test-package.mjs
