#!/usr/bin/env bash
# Build the WASM verifier package for npm.
#
# Prerequisites:
#   cargo install wasm-pack
#
# Usage:
#   ./build.sh          # Build for web (browsers)
#   ./build.sh nodejs   # Build for Node.js

set -euo pipefail

TARGET="${1:-web}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Building @tinyzkp/verify for target: ${TARGET}"

cd "$SCRIPT_DIR"

# Clear RUSTFLAGS to avoid host-target flags (e.g. -Ctarget-cpu) leaking into wasm build.
RUSTFLAGS='' wasm-pack build \
  --target "$TARGET" \
  --out-dir pkg \
  --out-name tinyzkp-verify \
  -- --no-default-features

# Override package.json with our npm metadata.
cat > pkg/package.json <<'PKGJSON'
{
  "name": "@tinyzkp/verify",
  "version": "0.1.1",
  "description": "Client-side WASM verifier for TinyZKP ZK-STARK proofs",
  "main": "tinyzkp-verify.js",
  "types": "tinyzkp-verify.d.ts",
  "files": [
    "tinyzkp-verify_bg.wasm",
    "tinyzkp-verify_bg.wasm.d.ts",
    "tinyzkp-verify.js",
    "tinyzkp-verify.d.ts"
  ],
  "keywords": ["zkp", "stark", "zero-knowledge", "wasm", "verifier", "tinyzkp"],
  "license": "MIT",
  "repository": {
    "type": "git",
    "url": "https://github.com/logannye/hc-stark"
  },
  "homepage": "https://tinyzkp.com"
}
PKGJSON

echo "Build complete: pkg/"
echo "  To publish: cd pkg && npm publish --access public"
