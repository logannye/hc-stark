#!/usr/bin/env bash
# Daily SQLite backup for tenant_store, usage, and evaluation application
# databases, plus api_keys.txt and private contract evidence/documents.
# Uses SQLite .backup command (safe with WAL concurrent reads).
# Retains 30 days of local backups.
# Off-box push (G13): configure either rclone or the authenticated HTTP ingest.
set -euo pipefail
umask 077   # backup artifacts (api_keys.txt, sqlite) must not be group/world-readable
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source .env so HC_BACKUP_REMOTE is available when run from cron.
# shellcheck source=/dev/null
[ -f "${HC_BACKUP_ENV_FILE:-/opt/hc-stark/.env}" ] && . "${HC_BACKUP_ENV_FILE:-/opt/hc-stark/.env}"

BACKUP_DIR="${HC_BACKUP_DIR:-/opt/hc-stark/backups}"
DATA_DIR="${HC_BACKUP_DATA_DIR:-/opt/hc-stark/data}"
DATE="${HC_BACKUP_DATE:-$(date -u +%Y%m%d_%H%M%S)}"
REMOTE_DATE="${HC_BACKUP_REMOTE_DATE:-$(date -u +%Y-%m-%d)}"
RETENTION_DAYS="${HC_BACKUP_RETENTION_DAYS:-30}"
CONTRACT_DIR="${HC_CONTRACT_DATA_DIR:-/var/lib/tinyzkp-private/contracts}"

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

# --- SQLite snapshots ---
for db in tenant_store.sqlite usage.sqlite evaluation_applications.sqlite; do
  src="$DATA_DIR/$db"
  if [ -f "$src" ]; then
    dest="$BACKUP_DIR/${db%.sqlite}_${DATE}.sqlite"
    sqlite3 "$src" ".backup '$dest'"
    chmod 600 "$dest"
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) Backed up $db -> $dest"
  else
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) SKIP $db (not found)"
  fi
done

# --- api_keys.txt snapshot ---
if [ -f "$DATA_DIR/api_keys.txt" ]; then
  install -m 600 "$DATA_DIR/api_keys.txt" "$BACKUP_DIR/api_keys_${DATE}.txt"
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) Backed up api_keys.txt -> $BACKUP_DIR/api_keys_${DATE}.txt"
else
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) SKIP api_keys.txt (not found)"
fi

# --- Signed contract evidence/documents snapshot ---
if [ -d "$CONTRACT_DIR" ]; then
  "${HC_BACKUP_PYTHON:-python3}" "$SCRIPT_DIR/validate_private_contract_dir.py" "$CONTRACT_DIR"
  if find "$CONTRACT_DIR" -type f -print -quit | grep -q .; then
    contract_archive="$BACKUP_DIR/contracts_${DATE}.tar.gz"
    tar -C "$CONTRACT_DIR" -czf "$contract_archive" .
    chmod 600 "$contract_archive"
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) Backed up private contracts -> $contract_archive"
  else
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) SKIP private contracts (empty)"
  fi
else
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) SKIP private contracts (not found)"
fi

# --- Off-box copy (G13) ---
# NOTE: HC_BACKUP_REMOTE must point at a PRIVATE bucket with server-side
# encryption + no public/anonymous read — these artifacts are credential material.
# Push today's snapshot to a configured rclone remote or private HTTP ingest.
# Operator setup:
#   1. apt-get install rclone
#   2. rclone config  (add a remote: Backblaze B2, S3, Hetzner Storage Box, etc.)
#   3. Set HC_BACKUP_REMOTE="<remote>:<bucket>" in /opt/hc-stark/.env
#      e.g. HC_BACKUP_REMOTE="b2:hc-stark-backups"
OFFBOX_FAILED=0
if [ -n "${HC_BACKUP_REMOTE:-}" ] && command -v rclone >/dev/null 2>&1; then
  if rclone copy "$BACKUP_DIR" "${HC_BACKUP_REMOTE%/}/${REMOTE_DATE}" --max-age 25h; then
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) Off-box backup pushed to ${HC_BACKUP_REMOTE}"
  else
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) ERROR: rclone off-box push FAILED" >&2
    OFFBOX_FAILED=1
  fi
elif [ -n "${HC_BACKUP_HTTP_URL:-}" ] && [ -n "${HC_BACKUP_HTTP_TOKEN_FILE:-}" ]; then
  if [ ! -f "$HC_BACKUP_HTTP_TOKEN_FILE" ]; then
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) ERROR: backup ingest token file missing" >&2
    OFFBOX_FAILED=1
  else
    BACKUP_TOKEN="$(tr -d '\r\n' < "$HC_BACKUP_HTTP_TOKEN_FILE")"
    case "$BACKUP_TOKEN" in
      *[!A-Za-z0-9._~-]*|'')
        echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) ERROR: backup ingest token has invalid characters" >&2
        OFFBOX_FAILED=1
        ;;
      *)
        for artifact in "$BACKUP_DIR"/*_"$DATE".*; do
          [ -f "$artifact" ] || continue
          if command -v sha256sum >/dev/null 2>&1; then
            digest="$(sha256sum "$artifact" | awk '{print $1}')"
          else
            digest="$(shasum -a 256 "$artifact" | awk '{print $1}')"
          fi
          target="${HC_BACKUP_HTTP_URL%/}/${REMOTE_DATE}/$(basename "$artifact")"
          if ! printf 'header = "Authorization: Bearer %s"\nheader = "X-Content-SHA256: %s"\nupload-file = "%s"\nurl = "%s"\n' \
              "$BACKUP_TOKEN" "$digest" "$artifact" "$target" \
              | curl --config - --fail --silent --show-error --retry 3 --retry-all-errors >/dev/null; then
            echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) ERROR: HTTP off-box push FAILED for $(basename "$artifact")" >&2
            OFFBOX_FAILED=1
            break
          fi
        done
        if [ "$OFFBOX_FAILED" -eq 0 ]; then
          echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) Off-box backup pushed through authenticated HTTP ingest"
        fi
        ;;
    esac
  fi
else
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) WARNING: no usable off-box backup transport — on-disk backup ONLY (G13 off-box requirement NOT satisfied)" >&2
fi

# --- Prune local backups older than retention period ---
find "$BACKUP_DIR" -name "*.sqlite" -mtime +${RETENTION_DAYS} -delete
find "$BACKUP_DIR" -name "api_keys_*.txt" -mtime +${RETENTION_DAYS} -delete
find "$BACKUP_DIR" -name "contracts_*.tar.gz" -mtime +${RETENTION_DAYS} -delete
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) Pruned backups older than ${RETENTION_DAYS} days"
if [ "$OFFBOX_FAILED" -ne 0 ]; then
  exit 1
fi
