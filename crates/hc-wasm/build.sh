#!/usr/bin/env bash
# Build the WASM verifier package for npm.
#
# Prerequisites:
#   cargo install wasm-pack
#
# Usage:
#   ./build.sh          # Build the browser/ESM package

set -euo pipefail

TARGET="${1:-web}"
SCRIPT_DIR=${BASH_SOURCE[0]%/*}
cd "$SCRIPT_DIR"
SCRIPT_DIR=$PWD
PACKAGE_VERSION="${TINYZKP_SDK_VERSION:-}"
OUT_DIR="${TINYZKP_WASM_OUT_DIR:-pkg}"
cargo_bin=${TINYZKP_CARGO:-cargo}
python_bin=${TINYZKP_PYTHON:-python3}
wasm_pack_bin=${TINYZKP_WASM_PACK:-wasm-pack}

if [[ "${TINYZKP_IMMUTABLE_SOURCE:-}" == "1" ]]; then
  for required in TINYZKP_CARGO TINYZKP_PYTHON TINYZKP_WASM_PACK; do
    if [[ -z "${!required:-}" ]]; then
      echo "evidenced WASM build lacks required descriptor: $required" >&2
      exit 2
    fi
  done
fi

if [[ -z "$PACKAGE_VERSION" ]]; then
  PACKAGE_VERSION="$({
    "$cargo_bin" metadata --no-deps --format-version 1 |
      "$python_bin" -c 'import json,sys; data=json.load(sys.stdin); print(next(package["version"] for package in data["packages"] if package["name"] == "hc-wasm"))'
  })"
fi
PACKAGE_VERSION="${PACKAGE_VERSION#v}"
if [[ ! "$PACKAGE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$ ]]; then
  echo "invalid TINYZKP_SDK_VERSION: $PACKAGE_VERSION" >&2
  exit 2
fi
if [[ "$TARGET" != "web" ]]; then
  echo "unsupported package target: $TARGET (expected web)" >&2
  exit 2
fi

echo "Building @tinyzkp/verify ${PACKAGE_VERSION} for target: ${TARGET}"

# Clear RUSTFLAGS to avoid host-target flags (e.g. -Ctarget-cpu) leaking into wasm build.
RUSTFLAGS='' "$wasm_pack_bin" build \
  --target "$TARGET" \
  --out-dir "$OUT_DIR" \
  --out-name tinyzkp-verify \
  -- --no-default-features --locked

# Override package.json with our npm metadata.
IFS= read -r -d '' PACKAGE_JSON <<PKGJSON || true
{
  "name": "@tinyzkp/verify",
  "version": "${PACKAGE_VERSION}",
  "description": "Client-side verifier for official Plonky3 ProofBundleV1 artifacts",
  "type": "module",
  "main": "tinyzkp-verify.js",
  "module": "tinyzkp-verify.js",
  "types": "tinyzkp-verify.d.ts",
  "exports": {
    ".": {
      "types": "./tinyzkp-verify.d.ts",
      "import": "./tinyzkp-verify.js"
    }
  },
  "files": [
    "LICENSE",
    "tinyzkp-verify_bg.wasm",
    "tinyzkp-verify_bg.wasm.d.ts",
    "tinyzkp-verify.js",
    "tinyzkp-verify.d.ts"
  ],
  "keywords": ["plonky3", "stark", "verifiable-computation", "wasm", "verifier", "tinyzkp"],
  "license": "MIT",
  "repository": {
    "type": "git",
    "url": "https://github.com/logannye/hc-stark"
  },
  "homepage": "https://tinyzkp.com"
}
PKGJSON
printf '%s\n' "$PACKAGE_JSON" > "$OUT_DIR/package.json"

"$python_bin" -I -c \
  'import os,shutil,sys; shutil.copyfile(sys.argv[1], sys.argv[2]); os.chmod(sys.argv[2], 0o644)' \
  LICENSE "$OUT_DIR/LICENSE"

echo "Build complete: ${OUT_DIR}/"
