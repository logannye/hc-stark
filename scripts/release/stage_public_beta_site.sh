#!/usr/bin/env bash
set -euo pipefail

RELEASE_SHA="${1:-}"
OUTPUT="${2:-}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
[[ "$RELEASE_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "usage: $0 RELEASE_SHA OUTPUT_DIRECTORY" >&2; exit 2; }
[[ -n "$OUTPUT" && ! -e "$OUTPUT" ]] || { echo "output must not already exist" >&2; exit 2; }
mkdir -m 0700 "$OUTPUT"
for asset in shared.css recovery.css favicon.svg wrangler.toml; do
  cp "$ROOT/site/$asset" "$OUTPUT/$asset"
done
cp -R "$ROOT/deploy/cloudflare/public-beta-site"/. "$OUTPUT"/

# public-beta-site/_worker.js is a dedicated policy and overwrites the
# containment worker through the overlay copy above. Never transform the
# containment policy in place.
cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -p hc-beta-api \
  --bin hc-beta-openapi -- "$RELEASE_SHA" "$OUTPUT/openapi.json"

while IFS= read -r -d '' file; do
  if grep -q '__TINYZKP_RELEASE_SHA__' "$file" 2>/dev/null; then
    sed -i.bak "s/__TINYZKP_RELEASE_SHA__/$RELEASE_SHA/g" "$file"
    rm -f "$file.bak"
  fi
done < <(find "$OUTPUT" -type f -print0)

jq -e --arg sha "$RELEASE_SHA" '.service_status=="public_beta" and .release_sha==$sha' "$OUTPUT/discovery.json" >/dev/null
jq -e --arg sha "$RELEASE_SHA" '.service_status=="public_beta" and .release_sha==$sha and .automatic_overages==false' "$OUTPUT/pricing.json" >/dev/null
grep -q 'not independently audited' "$OUTPUT/status.html"
grep -q '/v1/billing/checkout-sessions' "$OUTPUT/dashboard.js"
if rg -ni 'backend recovery|implementation preview|public checkout is disabled|contact sales|custom engineering|certified|fleet/oem|evaluation application' "$OUTPUT"/*.html "$OUTPUT"/*.json; then
  echo "staged public-beta site contains containment copy" >&2
  exit 3
fi
if rg -n 'innerHTML' "$OUTPUT/dashboard.js"; then
  echo "dashboard may not render API or tenant values with innerHTML" >&2
  exit 3
fi
grep -q "Content-Security-Policy" "$OUTPUT/_worker.js"
grep -q 'automatic tax' "$OUTPUT/openapi.json"
find "$OUTPUT" -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 shasum -a 256 >"$OUTPUT/SHA256SUMS"
echo "PASS staged exact-release public-beta site: $OUTPUT"
