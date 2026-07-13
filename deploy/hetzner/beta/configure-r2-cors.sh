#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
MODE="${1:-check}"
BUCKET="${TINYZKP_R2_ARTIFACT_BUCKET:-}"
POLICY="$ROOT/deploy/hetzner/beta/r2-artifacts-cors.json"

if [ -z "$BUCKET" ]; then
    echo "TINYZKP_R2_ARTIFACT_BUCKET is required" >&2
    exit 2
fi
if [ "$BUCKET" = "${TINYZKP_R2_BACKUP_BUCKET:-}" ]; then
    echo "artifact and backup buckets must be distinct" >&2
    exit 2
fi

case "$MODE" in
    apply)
        if [ "${TINYZKP_ALLOW_R2_CORS_WRITE:-}" != 1 ]; then
            echo "refusing R2 CORS write without TINYZKP_ALLOW_R2_CORS_WRITE=1" >&2
            exit 2
        fi
        wrangler r2 bucket cors set "$BUCKET" --file "$POLICY" --force
        ;;
    check)
        ;;
    *)
        echo "mode must be apply or check" >&2
        exit 2
        ;;
esac

CURRENT="$(wrangler r2 bucket cors list "$BUCKET")"
for required in \
    https://tinyzkp.com \
    https://www.tinyzkp.com \
    x-amz-meta-tinyzkp-blake3
do
    if ! grep -Fq "$required" <<<"$CURRENT"; then
        echo "missing required R2 CORS contract $required on $BUCKET" >&2
        exit 1
    fi
done
if grep -Fq '*' <<<"$CURRENT"; then
    echo "wildcard R2 CORS is forbidden on $BUCKET" >&2
    exit 1
fi
printf '%s\n' "$CURRENT"
