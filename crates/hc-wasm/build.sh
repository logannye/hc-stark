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
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PACKAGE_VERSION="${TINYZKP_SDK_VERSION:-}"

if [[ -z "$PACKAGE_VERSION" ]]; then
  PACKAGE_VERSION="$({
    cargo metadata --no-deps --format-version 1 |
      python3 -c 'import json,sys; data=json.load(sys.stdin); print(next(package["version"] for package in data["packages"] if package["name"] == "hc-wasm"))'
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

cd "$SCRIPT_DIR"

# Clear RUSTFLAGS to avoid host-target flags (e.g. -Ctarget-cpu) leaking into wasm build.
RUSTFLAGS='' wasm-pack build \
  --target "$TARGET" \
  --out-dir pkg \
  --out-name tinyzkp-verify \
  -- --no-default-features --locked

# Override package.json with our npm metadata.
cat > pkg/package.json <<PKGJSON
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

install -m 0644 LICENSE pkg/LICENSE

echo "Build complete: pkg/"
echo "  To publish: cd pkg && npm publish --provenance --access public"
