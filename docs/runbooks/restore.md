# Restore Runbook — hc-stark state (G13)

Covers restoring `tenant_store.sqlite`, `usage.sqlite`,
`evaluation_applications.sqlite`, `contract_billing.sqlite`, `api_keys.txt`,
and the private contract archive from an off-box rclone backup. Restore only an
artifact set whose same-timestamp manifest verifies. Each SQLite online backup
is internally consistent; because stores are captured sequentially, a timestamp
is not a cross-database transaction boundary unless writers were quiesced first.

---

## Prerequisites

- `HC_BACKUP_REMOTE` set in `/opt/hc-stark/.env` (e.g. `b2:hc-stark-backups`) — **must be a private, server-side-encrypted bucket with no public/anonymous read; backups contain plaintext API keys and key hashes**
- `rclone` installed with the reviewed root-only configuration at
  `/var/lib/tinyzkp-private/backup/rclone.conf`
- Root access to the Hetzner box

---

## 1. List available backup dates

```bash
BACKUP_REMOTE="$(/var/lib/tinyzkp-runtime/billing-venv/bin/python \
  /opt/hc-stark/billing/backup_env_exec.py read-remote \
  --env-file /opt/hc-stark/.env)"
/usr/bin/rclone --config /var/lib/tinyzkp-private/backup/rclone.conf \
  lsd "${BACKUP_REMOTE}"
```

Each directory is named `YYYY-MM-DD` (one per calendar day UTC).

---

## 2. Pull the chosen day's snapshot

Replace `<YYYY-MM-DD>` with the date you want to restore from:

```bash
BACKUP_REMOTE="$(/var/lib/tinyzkp-runtime/billing-venv/bin/python \
  /opt/hc-stark/billing/backup_env_exec.py read-remote \
  --env-file /opt/hc-stark/.env)"
TARGET_DATE="<YYYY-MM-DD>"
umask 077
if [ -e /opt/hc-stark/restore ]; then
  test ! -L /opt/hc-stark/restore
  test "$(/usr/bin/stat -c '%u:%g:%a' /opt/hc-stark/restore)" = "0:0:700"
  test -z "$(/usr/bin/find /opt/hc-stark/restore -mindepth 1 -print -quit)"
else
  /usr/bin/install -d -o root -g root -m 0700 /opt/hc-stark/restore
fi
/usr/bin/rclone --config /var/lib/tinyzkp-private/backup/rclone.conf \
  copy "${BACKUP_REMOTE}/${TARGET_DATE}" /opt/hc-stark/restore
ls -lh /opt/hc-stark/restore
```

You will see files named `tenant_store_<YYYYMMDD_HHMMSS>.sqlite`,
`usage_<YYYYMMDD_HHMMSS>.sqlite`,
`evaluation_applications_<YYYYMMDD_HHMMSS>.sqlite`,
`contract_billing_<YYYYMMDD_HHMMSS>.sqlite`,
`api_keys_<YYYYMMDD_HHMMSS>.txt`, and (after the first signed evaluation)
`contracts_<YYYYMMDD_HHMMSS>.tar.gz`, plus
`manifest_<YYYYMMDD_HHMMSS>.json`.
Pick the timestamp set you want (usually the latest within the day).

Verify it before stopping services or copying any data:

```bash
/var/lib/tinyzkp-runtime/billing-venv/bin/python \
  /opt/hc-stark/billing/backup_env_exec.py verify-manifest \
  --path /opt/hc-stark/restore/manifest_<YYYYMMDD_HHMMSS>.json
```

---

## 3. Stop the stack

```bash
systemctl stop hc-stark
systemctl stop hc-billing-webhook
```

Confirm nothing is writing to the databases:

```bash
lsof /opt/hc-stark/data/*.sqlite \
  /var/lib/tinyzkp-private/billing/contract_billing.sqlite \
  2>/dev/null || echo "No open handles — safe to proceed"
```

---

## 4. Restore the files

Set `TS` to the exact timestamp of the snapshot set (e.g. `20260529_020001`):

```bash
TS="<YYYYMMDD_HHMMSS>"
RESTORE_DIR="/opt/hc-stark/restore"
DATA_DIR="/opt/hc-stark/data"
CONTRACT_DIR="/var/lib/tinyzkp-private/contracts"
BILLING_DIR="/var/lib/tinyzkp-private/billing"
SERVICE_UID="$(/usr/bin/id -u tinyzkp-billing)"
SERVICE_GID="$(/usr/bin/id -g tinyzkp-billing)"
RESTORE_HELPER=/opt/hc-stark/billing/backup_env_exec.py
PYTHON=/var/lib/tinyzkp-runtime/billing-venv/bin/python

"$PYTHON" "$RESTORE_HELPER" restore-artifact \
  --source "${RESTORE_DIR}/tenant_store_${TS}.sqlite" \
  --destination "${DATA_DIR}/tenant_store.sqlite" \
  --uid "$SERVICE_UID" --gid "$SERVICE_GID"
"$PYTHON" "$RESTORE_HELPER" restore-artifact \
  --source "${RESTORE_DIR}/usage_${TS}.sqlite" \
  --destination "${DATA_DIR}/usage.sqlite" \
  --uid "$SERVICE_UID" --gid "$SERVICE_GID"
"$PYTHON" "$RESTORE_HELPER" restore-artifact \
  --source "${RESTORE_DIR}/evaluation_applications_${TS}.sqlite" \
  --destination "${DATA_DIR}/evaluation_applications.sqlite" \
  --uid "$SERVICE_UID" --gid "$SERVICE_GID"
"$PYTHON" "$RESTORE_HELPER" restore-artifact \
  --source "${RESTORE_DIR}/api_keys_${TS}.txt" \
  --destination "${DATA_DIR}/api_keys.txt" \
  --uid "$SERVICE_UID" --gid "$SERVICE_GID"
"$PYTHON" "$RESTORE_HELPER" restore-artifact \
  --source "${RESTORE_DIR}/contract_billing_${TS}.sqlite" \
  --destination "${BILLING_DIR}/contract_billing.sqlite" \
  --uid 0 --gid 0

if [ -f "${RESTORE_DIR}/contracts_${TS}.tar.gz" ]; then
  mv "${CONTRACT_DIR}" "${CONTRACT_DIR}.pre-restore-${TS}" 2>/dev/null || true
  install -d -m 700 "${CONTRACT_DIR}"
  tar -xzf "${RESTORE_DIR}/contracts_${TS}.tar.gz" \
    --no-same-owner --no-same-permissions -C "${CONTRACT_DIR}"
  find "${CONTRACT_DIR}" -type d -exec chmod 700 {} +
  find "${CONTRACT_DIR}" -type f -exec chmod 600 {} +
fi
```

> **WAL note:** The `.backup` command used by `backup.sh` produces a self-contained
> snapshot with no external WAL or SHM files.  Simply placing the `.sqlite` file is
> sufficient — no WAL replay is required.

---

## 5. Restart the stack

```bash
systemctl start hc-stark
systemctl start hc-billing-webhook
```

---

## 6. Verify

Run the health audit script:

```bash
/opt/hc-stark/scripts/monitoring/api_health_audit.sh
```

Or check manually:

```bash
# Basic liveness
curl -sf https://api.tinyzkp.com/readyz && echo "OK"

# Authenticated request with a known API key (replace <KEY>)
curl -sf -H "Authorization: Bearer <KEY>" https://api.tinyzkp.com/usage | jq .total_proofs
```

Confirm tenant and usage data look correct:

```bash
sqlite3 /opt/hc-stark/data/tenant_store.sqlite "SELECT count(*) FROM tenants;"
sqlite3 /opt/hc-stark/data/usage.sqlite        "SELECT count(*) FROM usage_log;"
sqlite3 /opt/hc-stark/data/evaluation_applications.sqlite \
  "SELECT count(*) FROM evaluation_applications;"
sqlite3 /var/lib/tinyzkp-private/billing/contract_billing.sqlite \
  "SELECT count(*) FROM billing_operations;"
find /var/lib/tinyzkp-private/contracts -maxdepth 2 -type f -print
```

---

## 7. Cleanup

Once restore is confirmed good, remove the staging directory:

```bash
rm -rf /opt/hc-stark/restore
```

---

## Troubleshooting

| Symptom | Check |
|---|---|
| `rclone lsd` returns nothing | Verify `HC_BACKUP_REMOTE` and `rclone listremotes` |
| No backup for today | Check `/var/log/hc-backup.log` for WARNING/ERROR lines |
| sqlite3 "file is not a database" | Wrong file or truncated transfer — re-pull with `rclone copy --checksum` |
| Service fails to start after restore | Check `journalctl -u hc-stark -n 50` for schema/migration errors |
