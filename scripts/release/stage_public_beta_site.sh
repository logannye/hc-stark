#!/usr/bin/env bash
set -euo pipefail

RELEASE_SHA="${1:-}"
OUTPUT="${2:-}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
[[ "$RELEASE_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "usage: $0 RELEASE_SHA OUTPUT_DIRECTORY" >&2; exit 2; }
[[ -n "$OUTPUT" && ! -e "$OUTPUT" ]] || { echo "output must not already exist" >&2; exit 2; }
mkdir -m 0700 "$OUTPUT"
cp -R "$ROOT/site"/. "$OUTPUT"/
cp -R "$ROOT/deploy/cloudflare/public-beta-site"/. "$OUTPUT"/

# The containment worker must not claim beta-only assets before activation.
# Add them only inside the exact-release staged Pages directory.
python3 - "$OUTPUT/_worker.js" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")
route_needle = '  "/pricing", "/status", "/contact", "/privacy", "/terms", "/requests",\n'
asset_needle = '  "/status.html",\n'
if source.count(route_needle) != 1 or source.count(asset_needle) != 1:
    raise SystemExit("public-beta worker staging anchors changed")
source = source.replace(
    route_needle,
    route_needle.rstrip("\n") + ' "/dashboard",\n',
)
source = source.replace(
    asset_needle,
    asset_needle + '  "/dashboard.html",\n  "/dashboard.js",\n',
)
path.write_text(source, encoding="utf-8")
PY

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
if rg -n 'Backend recovery in progress|Public checkout is disabled' "$OUTPUT/index.html" "$OUTPUT/status.html" "$OUTPUT/pricing.html"; then
  echo "staged public-beta site contains containment copy" >&2
  exit 3
fi
find "$OUTPUT" -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 shasum -a 256 >"$OUTPUT/SHA256SUMS"
echo "PASS staged exact-release public-beta site: $OUTPUT"
