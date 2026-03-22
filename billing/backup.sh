#!/usr/bin/env bash
# Daily SQLite backup for tenant_store and usage databases.
# Uses SQLite .backup command (safe with WAL concurrent reads).
# Retains 30 days of backups.
set -euo pipefail

BACKUP_DIR="/opt/hc-stark/backups"
DATA_DIR="/opt/hc-stark/data"
DATE=$(date -u +%Y%m%d_%H%M%S)
RETENTION_DAYS=30

mkdir -p "$BACKUP_DIR"

for db in tenant_store.sqlite usage.sqlite; do
  src="$DATA_DIR/$db"
  if [ -f "$src" ]; then
    dest="$BACKUP_DIR/${db%.sqlite}_${DATE}.sqlite"
    sqlite3 "$src" ".backup '$dest'"
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) Backed up $db -> $dest"
  else
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) SKIP $db (not found)"
  fi
done

# Prune backups older than retention period.
find "$BACKUP_DIR" -name "*.sqlite" -mtime +${RETENTION_DAYS} -delete
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) Pruned backups older than ${RETENTION_DAYS} days"
