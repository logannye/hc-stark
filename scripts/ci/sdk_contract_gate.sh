#!/usr/bin/env bash
set -euo pipefail

if [[ "${TINYZKP_HASH_LOCKED_PYTHON_WHEELHOUSE:-}" != "1" ]]; then
  echo "replacement SDK evidence requires a committed hash-locked Python wheelhouse" >&2
  exit 2
fi

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
python_bin=${TINYZKP_PYTHON:-python3}
npm_bin=${TINYZKP_NPM:-npm}
node_bin=${TINYZKP_NODE:-node}
cargo_bin=${TINYZKP_CARGO:-cargo}
schemas="${TINYZKP_EVIDENCE_WORK_DIR:-$(mktemp -d)}"
mkdir -p "$schemas"
trap 'rm -rf "$schemas"' EXIT

cd "$root"
cmp LICENSE crates/hc-wasm/LICENSE
"$cargo_bin" run -q -p hc-cli --locked -- schema --output-dir "$schemas"
diff -ru site/schemas "$schemas"
"$python_bin" scripts/ci/generate_sdk_schema_models.py \
  --schema-dir "$schemas" \
  --python-output clients/python/tinyzkp/schema_models.py \
  --typescript-output clients/typescript/src/schema-models.ts \
  --check

# The candidate-evidence command must be reproducible on a clean runner. Do
# not rely on an earlier CI job having installed the SDK runtime or test extra,
# and do not mutate an externally managed system Python.
"$python_bin" -m venv --copies "$schemas/python-venv"
"$schemas/python-venv/bin/python" -m pip install 'clients/python[test]'
"$schemas/python-venv/bin/python" -m pytest clients/python/tests -q
cp -R clients/typescript "$schemas/typescript"
"$npm_bin" --prefix "$schemas/typescript" ci
"$npm_bin" --prefix "$schemas/typescript" test
"$cargo_bin" test --manifest-path clients/rust/Cargo.toml --locked
"$cargo_bin" check -p hc-wasm --target wasm32-unknown-unknown --locked

if [[ ! -x "${TINYZKP_WASM_PACK:-}" ]] && ! command -v wasm-pack >/dev/null 2>&1; then
  echo "wasm-pack 0.14.0 is required for the runtime contract gate" >&2
  exit 2
fi
export TINYZKP_WASM_OUT_DIR="$schemas/wasm-package"
crates/hc-wasm/build.sh
"$node_bin" crates/hc-wasm/test-package.mjs

echo "PASS TinyZKP replacement SDK contracts"
