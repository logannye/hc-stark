#!/bin/sh
# Daily SQLite backup for tenant_store, usage, evaluation application, and
# contract billing reservation databases, plus api_keys.txt and private
# contract evidence/documents.
# Uses SQLite .backup command (safe with WAL concurrent reads).
# Retains 30 days of local backups.
# Off-box push (G13): configure either rclone or the authenticated HTTP ingest.
set -eu
umask 077   # backup artifacts (api_keys.txt, sqlite) must not be group/world-readable
PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
export PATH
unset BASH_ENV ENV CDPATH GLOBIGNORE PYTHONHOME PYTHONPATH || true
SCRIPT_DIR="$(CDPATH= cd -- "$(/usr/bin/dirname -- "$0")" && pwd -P)"
PYTHON_BIN=/usr/bin/python3
RCLONE_BIN=/usr/bin/rclone
CURL_BIN=/usr/bin/curl
TAR_BIN=/usr/bin/tar
SYSTEMCTL_BIN=/usr/bin/systemctl
RUNUSER_BIN=/usr/sbin/runuser

# The cron runs as root. Never shell-source the deployment env. A private,
# data-only parser exports only backup settings and re-execs this script.
if [ "$(/usr/bin/id -u)" -eq 0 ]; then
  ROOT_MODE=1
  BACKUP_ENV_FILE=/opt/hc-stark/.env
  LOADER_TOKEN_FILE=/var/lib/tinyzkp-private/backup/loader-token
  TEST_TIMESTAMP=''
  TEST_REMOTE_DATE=''
else
  ROOT_MODE=0
  BACKUP_ENV_FILE="${TINYZKP_BACKUP_TEST_ENV_FILE:-/opt/hc-stark/.env}"
  LOADER_TOKEN_FILE="${TINYZKP_BACKUP_TEST_TOKEN_FILE:-/var/lib/tinyzkp-private/backup/loader-token}"
  TEST_TIMESTAMP="${TINYZKP_BACKUP_TEST_DATE:-}"
  TEST_REMOTE_DATE="${TINYZKP_BACKUP_TEST_REMOTE_DATE:-}"
fi
LOADED_ARGUMENT='--tinyzkp-data-env-loaded'
if [ "${1:-}" = "$LOADED_ARGUMENT" ]; then
  shift
  REEXEC_TOKEN_FILE="${1:-}"
  [ -n "$REEXEC_TOKEN_FILE" ] || {
    echo "ERROR: internal loader token path is missing" >&2
    exit 1
  }
  shift
  if [ "$ROOT_MODE" -eq 1 ] && \
      [ "$REEXEC_TOKEN_FILE" != /var/lib/tinyzkp-private/backup/loader-token ]; then
    echo "ERROR: production loader token path is invalid" >&2
    exit 1
  fi
  LOADER_TOKEN_FILE="$REEXEC_TOKEN_FILE"
  "$PYTHON_BIN" "$SCRIPT_DIR/backup_env_exec.py" verify-capability \
    --loader-token-file "$LOADER_TOKEN_FILE"
  if [ "${TINYZKP_BACKUP_ENV_LOADED:-}" != "data-only-v1" ]; then
    echo "ERROR: internal data-only environment marker is missing" >&2
    exit 1
  fi
  if [ "$ROOT_MODE" -eq 1 ] && \
      [ "${TINYZKP_BACKUP_LOCK_HELD:-}" != "exclusive-v1" ]; then
    echo "ERROR: production backup process lock is not held" >&2
    exit 1
  fi
else
  if [ -n "$TEST_TIMESTAMP" ] || [ -n "$TEST_REMOTE_DATE" ]; then
    exec "$PYTHON_BIN" "$SCRIPT_DIR/backup_env_exec.py" exec \
      --env-file "$BACKUP_ENV_FILE" \
      --loader-token-file "$LOADER_TOKEN_FILE" \
      --test-timestamp "$TEST_TIMESTAMP" \
      --test-remote-date "$TEST_REMOTE_DATE" \
      -- "$0" "$LOADED_ARGUMENT" "$LOADER_TOKEN_FILE" "$@"
  fi
  exec "$PYTHON_BIN" "$SCRIPT_DIR/backup_env_exec.py" exec \
    --env-file "$BACKUP_ENV_FILE" \
    --loader-token-file "$LOADER_TOKEN_FILE" \
    -- "$0" "$LOADED_ARGUMENT" "$LOADER_TOKEN_FILE" "$@"
fi
unset TINYZKP_BACKUP_ENV_LOADED TINYZKP_BACKUP_CAPABILITY \
  TINYZKP_BACKUP_LOCK_HELD

BACKUP_DIR="${HC_BACKUP_DIR:-/opt/hc-stark/backups}"
DATA_DIR="${HC_BACKUP_DATA_DIR:-/opt/hc-stark/data}"
DATE="${HC_BACKUP_DATE:-$(/bin/date -u +%Y%m%d_%H%M%S)}"
REMOTE_DATE="${HC_BACKUP_REMOTE_DATE:-$(/bin/date -u +%Y-%m-%d)}"
RETENTION_DAYS="${HC_BACKUP_RETENTION_DAYS:-30}"
CONTRACT_DIR="${HC_CONTRACT_DATA_DIR:-/var/lib/tinyzkp-private/contracts}"
BILLING_LEDGER_PATH="${TINYZKP_CONTRACT_BILLING_LEDGER_PATH:-/var/lib/tinyzkp-private/billing/contract_billing.sqlite}"

case "$RETENTION_DAYS" in
  ''|*[!0-9]*)
    echo "ERROR: HC_BACKUP_RETENTION_DAYS must be an integer from 1 through 3650" >&2
    exit 1
    ;;
esac
if [ "$RETENTION_DAYS" -lt 1 ] || [ "$RETENTION_DAYS" -gt 3650 ]; then
  echo "ERROR: HC_BACKUP_RETENTION_DAYS must be an integer from 1 through 3650" >&2
  exit 1
fi

"$PYTHON_BIN" "$SCRIPT_DIR/backup_env_exec.py" validate-dates \
  --timestamp "$DATE" --remote-date "$REMOTE_DATE"
"$PYTHON_BIN" "$SCRIPT_DIR/backup_env_exec.py" validate-layout \
  --backup-dir "$BACKUP_DIR" \
  --data-dir "$DATA_DIR" \
  --contract-dir "$CONTRACT_DIR" \
  --billing-ledger-path "$BILLING_LEDGER_PATH" \
  --script-dir "$SCRIPT_DIR" \
  --timestamp "$DATE"
unset HC_BACKUP_DATE HC_BACKUP_REMOTE_DATE

# Production snapshots run at a quiesced point. Service-owned SQLite files are
# opened by the unprivileged service UID into a private staging directory, then
# root copies the self-contained snapshot through held O_NOFOLLOW descriptors.
# The SQLite parser can therefore never be redirected to a root-only file.
QUIESCED=0
HC_STARK_WAS_ACTIVE=0
WEBHOOK_WAS_ACTIVE=0
STAGING_DIR=''
resume_quiesced_services() {
  if [ "$QUIESCED" -eq 1 ]; then
    if [ -n "$STAGING_DIR" ] && [ -d "$STAGING_DIR" ]; then
      "$PYTHON_BIN" "$SCRIPT_DIR/backup_env_exec.py" remove-staging \
        --path "$STAGING_DIR"
    fi
    if [ "$WEBHOOK_WAS_ACTIVE" -eq 1 ]; then
      "$SYSTEMCTL_BIN" start hc-billing-webhook.service
    fi
    if [ "$HC_STARK_WAS_ACTIVE" -eq 1 ]; then
      "$SYSTEMCTL_BIN" start hc-stark.service
    fi
    QUIESCED=0
  fi
}
if [ "$ROOT_MODE" -eq 1 ]; then
  "$SYSTEMCTL_BIN" is-active --quiet hc-stark.service && HC_STARK_WAS_ACTIVE=1 || true
  "$SYSTEMCTL_BIN" is-active --quiet hc-billing-webhook.service && WEBHOOK_WAS_ACTIVE=1 || true
  QUIESCED=1
  trap 'resume_quiesced_services' EXIT
  trap 'resume_quiesced_services; exit 129' HUP
  trap 'resume_quiesced_services; exit 130' INT
  trap 'resume_quiesced_services; exit 143' TERM
  [ "$HC_STARK_WAS_ACTIVE" -eq 0 ] || "$SYSTEMCTL_BIN" stop hc-stark.service
  [ "$WEBHOOK_WAS_ACTIVE" -eq 0 ] || "$SYSTEMCTL_BIN" stop hc-billing-webhook.service
  if "$SYSTEMCTL_BIN" is-active --quiet hc-stark.service \
      || "$SYSTEMCTL_BIN" is-active --quiet hc-billing-webhook.service; then
    echo "ERROR: a production writer remained active during backup quiescence" >&2
    exit 1
  fi
  STAGING_DIR="/var/lib/tinyzkp-backup-staging/run_$DATE"
  SERVICE_UID="$(/usr/bin/id -u tinyzkp-billing)"
  SERVICE_GID="$(/usr/bin/id -g tinyzkp-billing)"
  "$PYTHON_BIN" "$SCRIPT_DIR/backup_env_exec.py" create-staging \
    --path "$STAGING_DIR" --uid "$SERVICE_UID" --gid "$SERVICE_GID"
fi

# --- SQLite snapshots ---
for db in tenant_store.sqlite usage.sqlite evaluation_applications.sqlite; do
  src="$DATA_DIR/$db"
  if [ -f "$src" ]; then
    dest="$BACKUP_DIR/${db%.sqlite}_${DATE}.sqlite"
    if [ "$ROOT_MODE" -eq 1 ]; then
      staged="$STAGING_DIR/$db"
      "$RUNUSER_BIN" --user tinyzkp-billing -- \
        /usr/bin/env -i PATH="$PATH" LANG=C LC_ALL=C TZ=UTC \
        "$PYTHON_BIN" "$SCRIPT_DIR/backup_env_exec.py" snapshot \
          --source "$src" --destination "$staged" --kind sqlite
      "$PYTHON_BIN" "$SCRIPT_DIR/backup_env_exec.py" snapshot \
        --source "$staged" --destination "$dest" --kind copy
    else
      "$PYTHON_BIN" "$SCRIPT_DIR/backup_env_exec.py" snapshot \
        --source "$src" --destination "$dest" --kind sqlite
    fi
    echo "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ) Backed up $db -> $dest"
  else
    echo "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ) SKIP $db (not found)"
  fi
done

# The contract billing reservation ledger is operator-owned and deliberately
# separated from the service-owned application data directory.
if [ -f "$BILLING_LEDGER_PATH" ]; then
  billing_dest="$BACKUP_DIR/contract_billing_${DATE}.sqlite"
  "$PYTHON_BIN" "$SCRIPT_DIR/backup_env_exec.py" snapshot \
    --source "$BILLING_LEDGER_PATH" --destination "$billing_dest" --kind sqlite
  echo "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ) Backed up contract billing ledger -> $billing_dest"
else
  echo "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ) SKIP contract billing ledger (not found)"
fi

# --- api_keys.txt snapshot ---
if [ -f "$DATA_DIR/api_keys.txt" ]; then
  "$PYTHON_BIN" "$SCRIPT_DIR/backup_env_exec.py" snapshot \
    --source "$DATA_DIR/api_keys.txt" \
    --destination "$BACKUP_DIR/api_keys_${DATE}.txt" --kind copy
  echo "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ) Backed up api_keys.txt -> $BACKUP_DIR/api_keys_${DATE}.txt"
else
  echo "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ) SKIP api_keys.txt (not found)"
fi

# --- Signed contract evidence/documents snapshot ---
if [ -d "$CONTRACT_DIR" ]; then
  "$PYTHON_BIN" "$SCRIPT_DIR/validate_private_contract_dir.py" "$CONTRACT_DIR"
  if [ -n "$(/usr/bin/find "$CONTRACT_DIR" -type f -print -quit)" ]; then
    contract_archive="$BACKUP_DIR/contracts_${DATE}.tar.gz"
    "$TAR_BIN" -C "$CONTRACT_DIR" -czf "$contract_archive" .
    /bin/chmod 600 "$contract_archive"
    echo "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ) Backed up private contracts -> $contract_archive"
  else
    echo "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ) SKIP private contracts (empty)"
  fi
else
  echo "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ) SKIP private contracts (not found)"
fi

# Freeze the exact current-run artifact set before any off-box copy. The
# manifest requires the evaluation and contract-billing ledgers, records every
# artifact digest, and makes an empty/partial run fail closed.
MANIFEST_PATH="$BACKUP_DIR/manifest_${DATE}.json"
"$PYTHON_BIN" "$SCRIPT_DIR/backup_env_exec.py" create-manifest \
  --backup-dir "$BACKUP_DIR" --timestamp "$DATE" >/dev/null
"$PYTHON_BIN" "$SCRIPT_DIR/backup_env_exec.py" verify-manifest \
  --path "$MANIFEST_PATH"
resume_quiesced_services
trap - EXIT HUP INT TERM

# --- Off-box copy (G13) ---
# NOTE: HC_BACKUP_REMOTE must point at a PRIVATE bucket with server-side
# encryption + no public/anonymous read — these artifacts are credential material.
# Push today's snapshot to a configured rclone remote or private HTTP ingest.
# Operator setup:
#   1. apt-get install rclone
#   2. rclone config --config /var/lib/tinyzkp-private/backup/rclone.conf
#      (add a remote: Backblaze B2, S3, Hetzner Storage Box, etc.)
#   3. Set HC_BACKUP_REMOTE="<remote>:<bucket>" in /opt/hc-stark/.env
#      e.g. HC_BACKUP_REMOTE="b2:hc-stark-backups"
OFFBOX_FAILED=0
if [ -n "${HC_BACKUP_REMOTE:-}" ] && [ -x "$RCLONE_BIN" ]; then
  RCLONE_COPY_FAILED=0
  RCLONE_ARTIFACT_COUNT=0
  for artifact in \
    "$BACKUP_DIR/tenant_store_${DATE}.sqlite" \
    "$BACKUP_DIR/usage_${DATE}.sqlite" \
    "$BACKUP_DIR/evaluation_applications_${DATE}.sqlite" \
    "$BACKUP_DIR/contract_billing_${DATE}.sqlite" \
    "$BACKUP_DIR/api_keys_${DATE}.txt" \
    "$BACKUP_DIR/contracts_${DATE}.tar.gz" \
    "$MANIFEST_PATH"; do
    [ -f "$artifact" ] || continue
    RCLONE_ARTIFACT_COUNT=$((RCLONE_ARTIFACT_COUNT + 1))
    if ! "$RCLONE_BIN" copyto "$artifact" \
        "${HC_BACKUP_REMOTE%/}/${REMOTE_DATE}/$(/usr/bin/basename "$artifact")"; then
      RCLONE_COPY_FAILED=1
      break
    fi
  done
  if [ "$RCLONE_COPY_FAILED" -eq 0 ] && [ "$RCLONE_ARTIFACT_COUNT" -ge 3 ]; then
    echo "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ) Off-box backup pushed to ${HC_BACKUP_REMOTE}"
    if "$RCLONE_BIN" delete "${HC_BACKUP_REMOTE%/}" \
        --min-age "${RETENTION_DAYS}d" \
        --include '**/tenant_store_[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]_[0-9][0-9][0-9][0-9][0-9][0-9].sqlite' \
        --include '**/usage_[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]_[0-9][0-9][0-9][0-9][0-9][0-9].sqlite' \
        --include '**/evaluation_applications_[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]_[0-9][0-9][0-9][0-9][0-9][0-9].sqlite' \
        --include '**/contract_billing_[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]_[0-9][0-9][0-9][0-9][0-9][0-9].sqlite' \
        --include '**/api_keys_[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]_[0-9][0-9][0-9][0-9][0-9][0-9].txt' \
        --include '**/contracts_[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]_[0-9][0-9][0-9][0-9][0-9][0-9].tar.gz' \
        --include '**/manifest_[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]_[0-9][0-9][0-9][0-9][0-9][0-9].json' \
        --exclude '**'; then
      echo "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ) Pruned exact off-box backup artifacts older than ${RETENTION_DAYS} days"
    else
      echo "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ) ERROR: rclone off-box retention prune FAILED" >&2
      OFFBOX_FAILED=1
    fi
  else
    echo "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ) ERROR: rclone off-box push FAILED" >&2
    OFFBOX_FAILED=1
  fi
elif [ -n "${HC_BACKUP_HTTP_URL:-}" ] && [ -n "${HC_BACKUP_HTTP_TOKEN_FILE:-}" ]; then
  if [ ! -f "$HC_BACKUP_HTTP_TOKEN_FILE" ]; then
    echo "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ) ERROR: backup ingest token file missing" >&2
    OFFBOX_FAILED=1
  else
    if BACKUP_TOKEN="$($PYTHON_BIN "$SCRIPT_DIR/backup_env_exec.py" read-http-token \
        --token-file "$HC_BACKUP_HTTP_TOKEN_FILE")"; then
      HTTP_ARTIFACT_COUNT=0
        for artifact in \
          "$BACKUP_DIR/tenant_store_${DATE}.sqlite" \
          "$BACKUP_DIR/usage_${DATE}.sqlite" \
          "$BACKUP_DIR/evaluation_applications_${DATE}.sqlite" \
          "$BACKUP_DIR/contract_billing_${DATE}.sqlite" \
          "$BACKUP_DIR/api_keys_${DATE}.txt" \
          "$BACKUP_DIR/contracts_${DATE}.tar.gz" \
          "$MANIFEST_PATH"; do
          [ -f "$artifact" ] || continue
          HTTP_ARTIFACT_COUNT=$((HTTP_ARTIFACT_COUNT + 1))
          if [ -x /usr/bin/sha256sum ]; then
            digest="$(/usr/bin/sha256sum "$artifact" | /usr/bin/awk '{print $1}')"
          else
            digest="$(/usr/bin/shasum -a 256 "$artifact" | /usr/bin/awk '{print $1}')"
          fi
          target="${HC_BACKUP_HTTP_URL%/}/${REMOTE_DATE}/$(/usr/bin/basename "$artifact")"
          HTTP_STATUS="$(printf 'header = "Authorization: Bearer %s"\nheader = "X-Content-SHA256: %s"\nupload-file = "%s"\nurl = "%s"\n' \
              "$BACKUP_TOKEN" "$digest" "$artifact" "$target" \
              | "$CURL_BIN" --disable --config - --silent --show-error \
                  --retry 3 --retry-all-errors --max-redirs 0 \
                  --proto '=https' --proto-redir '=https' \
                  --output /dev/null --write-out '%{http_code}')" || HTTP_STATUS='000'
          case "$HTTP_STATUS" in
            2??) ;;
            *)
            echo "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ) ERROR: HTTP off-box push FAILED for $(/usr/bin/basename "$artifact")" >&2
            OFFBOX_FAILED=1
            break
            ;;
          esac
        done
        if [ "$OFFBOX_FAILED" -eq 0 ] && [ "$HTTP_ARTIFACT_COUNT" -ge 3 ]; then
          echo "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ) Off-box backup pushed through authenticated HTTP ingest"
          if [ "${HC_BACKUP_HTTP_RETENTION_CONFIRMED:-0}" != "1" ]; then
            echo "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ) ERROR: HTTP backup destination retention is not confirmed" >&2
            OFFBOX_FAILED=1
          fi
        elif [ "$OFFBOX_FAILED" -eq 0 ]; then
          echo "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ) ERROR: current HTTP backup set is incomplete" >&2
          OFFBOX_FAILED=1
        fi
    else
      OFFBOX_FAILED=1
    fi
  fi
else
  if [ -n "${HC_BACKUP_REMOTE:-}" ]; then
    echo "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ) ERROR: HC_BACKUP_REMOTE is configured but rclone is unavailable and no usable HTTP transport exists" >&2
  else
    echo "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ) ERROR: no usable off-box backup transport — on-disk backup ONLY (G13 off-box requirement NOT satisfied)" >&2
  fi
  OFFBOX_FAILED=1
fi

# --- Prune exact local TinyZKP artifacts older than retention period ---
"$PYTHON_BIN" "$SCRIPT_DIR/backup_env_exec.py" prune \
  --backup-dir "$BACKUP_DIR" --retention-days "$RETENTION_DAYS"
echo "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ) Pruned exact TinyZKP backups older than ${RETENTION_DAYS} days"
if [ "$OFFBOX_FAILED" -ne 0 ]; then
  exit 1
fi
