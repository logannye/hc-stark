#!/usr/bin/env bash
# Daily SQLite backup for tenant_store and usage databases, plus api_keys.txt.
# Uses SQLite .backup command (safe with WAL concurrent reads).
# Retains 30 days of local backups.
# Off-box push (G13): set HC_BACKUP_REMOTE in /opt/hc-stark/.env and install rclone.
set -euo pipefail
umask 077   # backup artifacts (api_keys.txt, sqlite) must not be group/world-readable

# Source .env so HC_BACKUP_REMOTE is available when run from cron.
# shellcheck source=/dev/null
[ -f /opt/hc-stark/.env ] && . /opt/hc-stark/.env

BACKUP_DIR="/opt/hc-stark/backups"
DATA_DIR="/opt/hc-stark/data"
DATE=$(date -u +%Y%m%d_%H%M%S)
RETENTION_DAYS=30

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

# --- SQLite snapshots ---
for db in tenant_store.sqlite usage.sqlite; do
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

# --- Off-box copy (G13) ---
# NOTE: HC_BACKUP_REMOTE must point at a PRIVATE bucket with server-side
# encryption + no public/anonymous read — these artifacts are credential material.
# Push today's snapshot to a configured rclone remote.
# Operator setup:
#   1. apt-get install rclone
#   2. rclone config  (add a remote: Backblaze B2, S3, Hetzner Storage Box, etc.)
#   3. Set HC_BACKUP_REMOTE="<remote>:<bucket>" in /opt/hc-stark/.env
#      e.g. HC_BACKUP_REMOTE="b2:hc-stark-backups"
if [ -n "${HC_BACKUP_REMOTE:-}" ] && command -v rclone >/dev/null 2>&1; then
  if rclone copy "$BACKUP_DIR" "${HC_BACKUP_REMOTE%/}/$(date -u +%Y-%m-%d)" --max-age 25h; then
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) Off-box backup pushed to ${HC_BACKUP_REMOTE}"
  else
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) ERROR: rclone off-box push FAILED" >&2
  fi
else
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) WARNING: HC_BACKUP_REMOTE unset or rclone missing — on-disk backup ONLY (G13 off-box requirement NOT satisfied)" >&2
fi

# --- Prune local backups older than retention period ---
find "$BACKUP_DIR" -name "*.sqlite" -mtime +${RETENTION_DAYS} -delete
find "$BACKUP_DIR" -name "api_keys_*.txt" -mtime +${RETENTION_DAYS} -delete
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) Pruned backups older than ${RETENTION_DAYS} days"
