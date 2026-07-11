#!/usr/bin/env bash
set -euo pipefail

for required in \
  TINYZKP_BASH TINYZKP_CARGO TINYZKP_EVIDENCE_WORK_DIR TINYZKP_NODE \
  TINYZKP_PYTHON TINYZKP_SDK_PYTHON_WHEELHOUSE TINYZKP_SDK_NPM_TARBALLS \
  TINYZKP_SEALED_NPM_TARBALLS TINYZKP_SEALED_PYTHON_WHEELS TINYZKP_WASM_PACK \
  CARGO RUSTC
do
  if [[ -z "${!required:-}" ]]; then
    echo "replacement SDK evidence lacks required descriptor/path: $required" >&2
    exit 2
  fi
done

root=$PWD
python_bin=$TINYZKP_PYTHON
node_bin=$TINYZKP_NODE
cargo_bin=$TINYZKP_CARGO
schemas=$TINYZKP_EVIDENCE_WORK_DIR
typescript_root=$schemas/workspace/clients/typescript

cd "$root"
"$python_bin" -I -c '
from pathlib import Path
if Path("LICENSE").read_bytes() != Path("crates/hc-wasm/LICENSE").read_bytes():
    raise ValueError("license skew")
'
"$cargo_bin" run -q -p hc-cli --locked -- schema --output-dir "$schemas"
"$python_bin" -I -c '
from pathlib import Path
expected = Path("site/schemas")
actual = Path(__import__("sys").argv[1])
names = sorted(path.name for path in expected.glob("*.json"))
actual_names = sorted(path.name for path in actual.glob("*.json"))
if not names or names != actual_names:
    raise ValueError("schema inventory skew")
if not all((expected / name).read_bytes() == (actual / name).read_bytes() for name in names):
    raise ValueError("schema content skew")
' "$schemas"
"$python_bin" -I scripts/ci/generate_sdk_schema_models.py \
  --schema-dir "$schemas" \
  --python-output clients/python/tinyzkp/schema_models.py \
  --typescript-output clients/typescript/src/schema-models.ts \
  --check

# The explicit preparation step has materialized this exact wheelhouse from
# the committed URL/size/SHA/METADATA lock.  Reverify it inside the write-denied
# evidence boundary, then build and test an installed SDK wheel fully offline.
"$python_bin" -I scripts/ci/materialize_sdk_python_env.py \
  --wheelhouse "$TINYZKP_SDK_PYTHON_WHEELHOUSE" \
  --work-dir "$schemas/python-sdk"
"$python_bin" -I -c \
  'import shutil,sys; shutil.copytree("clients/typescript", sys.argv[1]); shutil.copytree("test-vectors", sys.argv[2])' \
  "$typescript_root" "$schemas/workspace/test-vectors"
"$python_bin" -I scripts/ci/verify_sdk_npm_tarballs.py \
  --extract-sealed "$typescript_root/node_modules"

# Invoke the FD-held Node interpreter directly. No npm executable, registry
# client, lifecycle script, user config, or ambient package cache participates.
"$node_bin" "$typescript_root/node_modules/typescript/bin/tsc" \
  -p "$typescript_root/tsconfig.json"
"$node_bin" "$typescript_root/node_modules/typescript/bin/tsc" \
  -p "$typescript_root/tsconfig.cjs.json"
"$node_bin" -e \
  'require("fs").writeFileSync(process.argv[1], JSON.stringify({type:"commonjs"}, null, 2))' \
  "$typescript_root/dist/cjs/package.json"
"$node_bin" --test \
  "$typescript_root"/tests/*.test.mjs \
  "$typescript_root"/tests/*.test.cjs
"$cargo_bin" test --manifest-path clients/rust/Cargo.toml --locked
"$cargo_bin" check -p hc-wasm --target wasm32-unknown-unknown --locked

if [[ ! -x "$TINYZKP_WASM_PACK" ]]; then
  echo "the FD-bound wasm-pack 0.14.0 executable is unavailable" >&2
  exit 2
fi
export TINYZKP_WASM_OUT_DIR="$schemas/wasm-package"
"$TINYZKP_BASH" crates/hc-wasm/build.sh
"$node_bin" crates/hc-wasm/test-package.mjs

echo "PASS TinyZKP replacement SDK contracts"
