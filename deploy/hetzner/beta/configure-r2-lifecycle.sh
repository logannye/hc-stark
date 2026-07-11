#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
MODE="${1:-check}"
TARGET="${2:-artifacts}"

case "$TARGET" in
    artifacts)
        BUCKET="${TINYZKP_R2_ARTIFACT_BUCKET:-}"
        POLICY="$ROOT/deploy/hetzner/beta/r2-artifacts-lifecycle.json"
        REQUIRED_IDS="tinyzkp-beta-uploads-24h tinyzkp-beta-bundles-90d-maximum tinyzkp-beta-abort-incomplete-24h"
        ;;
    backups)
        BUCKET="${TINYZKP_R2_BACKUP_BUCKET:-}"
        POLICY="$ROOT/deploy/hetzner/beta/r2-backups-lifecycle.json"
        REQUIRED_IDS="tinyzkp-backups-abort-incomplete-24h"
        ;;
    *)
        echo "target must be artifacts or backups" >&2
        exit 2
        ;;
esac

if [ -z "$BUCKET" ]; then
    echo "the selected TINYZKP_R2_*_BUCKET variable is required" >&2
    exit 2
fi
if [ "$TARGET" = artifacts ] && [ "$BUCKET" = "${TINYZKP_R2_BACKUP_BUCKET:-}" ]; then
    echo "artifact and backup buckets must be distinct" >&2
    exit 2
fi

case "$MODE" in
    apply)
        if [ "${TINYZKP_ALLOW_R2_LIFECYCLE_WRITE:-}" != 1 ]; then
            echo "refusing R2 lifecycle write without TINYZKP_ALLOW_R2_LIFECYCLE_WRITE=1" >&2
            exit 2
        fi
        wrangler r2 bucket lifecycle set "$BUCKET" --file "$POLICY" --force
        ;;
    check)
        ;;
    *)
        echo "mode must be apply or check" >&2
        exit 2
        ;;
esac

CURRENT="$(wrangler r2 bucket lifecycle list "$BUCKET")"
for rule_id in $REQUIRED_IDS; do
    if ! grep -Fq "$rule_id" <<<"$CURRENT"; then
        echo "missing R2 lifecycle rule $rule_id on $BUCKET" >&2
        exit 1
    fi
done
printf '%s\n' "$CURRENT"
