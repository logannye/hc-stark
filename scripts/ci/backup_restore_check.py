#!/usr/bin/env python3
"""Validate TinyZKP backup and restore documentation against current state files."""

from __future__ import annotations

import argparse
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[2]

REQUIRED_MARKERS = {
    "billing/backup.sh": (
        "tenant_store.sqlite usage.sqlite evaluation_applications.sqlite",
        "api_keys.txt",
        "HC_BACKUP_ENV_FILE",
        "HC_BACKUP_DATA_DIR",
        "HC_BACKUP_DATE",
        "HC_BACKUP_REMOTE_DATE",
        "HC_BACKUP_RETENTION_DAYS",
        "HC_CONTRACT_DATA_DIR",
        "TINYZKP_CONTRACT_BILLING_LEDGER_PATH",
        'sqlite3 "$src" ".backup \'$dest\'"',
        "umask 077",
        'chmod 700 "$BACKUP_DIR"',
        'chmod 600 "$dest"',
        "install -m 600",
        "contracts_${DATE}.tar.gz",
        "contract_billing_${DATE}.sqlite",
        "validate_private_contract_dir.py",
        "HC_BACKUP_REMOTE",
        "rclone copy",
        "rclone delete",
        "HC_BACKUP_HTTP_RETENTION_CONFIRMED",
        "on-disk backup ONLY",
        "backup_env_exec.py",
        '-mtime "+$RETENTION_DAYS"',
        "OFFBOX_FAILED=1",
    ),
    "billing/backup_env_exec.py": (
        "O_NOFOLLOW",
        "must be owner-only",
        "must be owned by the current operator",
        "data-only KEY=value assignment",
        "BACKUP_KEYS",
        "validate_backup_values",
        "os.execve",
    ),
    "billing/validate_private_contract_dir.py": (
        "contract directory contains a symlink",
        "contract directory is not owner-only",
        "contract directory contains a special file",
        "followlinks=False",
    ),
    "docs/runbooks/restore.md": (
        "tenant_store_<YYYYMMDD_HHMMSS>.sqlite",
        "usage_<YYYYMMDD_HHMMSS>.sqlite",
        "evaluation_applications_<YYYYMMDD_HHMMSS>.sqlite",
        "contract_billing_<YYYYMMDD_HHMMSS>.sqlite",
        "api_keys_<YYYYMMDD_HHMMSS>.txt",
        "contracts_<YYYYMMDD_HHMMSS>.tar.gz",
        "systemctl stop hc-stark",
        "systemctl stop hc-billing-webhook",
        "tenant_store_${TS}.sqlite",
        "usage_${TS}.sqlite",
        "evaluation_applications_${TS}.sqlite",
        "contract_billing_${TS}.sqlite",
        "api_keys_${TS}.txt",
        "contracts_${TS}.tar.gz",
        "api_health_audit.sh",
        "https://api.tinyzkp.com/usage",
        "SELECT count(*) FROM tenants;",
        "SELECT count(*) FROM usage_log;",
        "SELECT count(*) FROM applications;",
        "SELECT count(*) FROM billing_operations;",
        "/var/lib/tinyzkp-private/contracts",
        "/var/lib/tinyzkp-private/billing/contract_billing.sqlite",
        "chown tinyzkp-billing:tinyzkp-billing",
    ),
    "billing/tenant_store.py": (
        "CREATE TABLE IF NOT EXISTS tenants",
        "CREATE TABLE IF NOT EXISTS processed_events",
        "CREATE TABLE IF NOT EXISTS magic_links",
        "CREATE TABLE IF NOT EXISTS sessions",
    ),
    "crates/hc-server/src/usage_log.rs": (
        "CREATE TABLE IF NOT EXISTS usage_log",
        "CREATE TABLE IF NOT EXISTS verify_log",
        "CREATE TABLE IF NOT EXISTS failed_proofs",
    ),
    "deploy/hetzner/setup.sh": (
        "/etc/cron.d/hc-billing",
        "rm -f /etc/cron.d/hc-backup",
        "/opt/hc-stark/billing/backup.sh",
        "HC_BACKUP_REMOTE",
    ),
}

FORBIDDEN_MARKERS = {
    "billing/backup.sh": (
        '. "${HC_BACKUP_ENV_FILE',
        "shellcheck source",
    ),
    "docs/runbooks/restore.md": (
        "/v1/ping",
        "usage_events",
    ),
}


def read(root: pathlib.Path, rel: str) -> str:
    return (root / rel).read_text(encoding="utf-8", errors="replace")


def check_file(root: pathlib.Path, rel: str, markers: tuple[str, ...]) -> list[str]:
    path = root / rel
    if not path.is_file():
        return [f"missing {rel}"]
    text = read(root, rel)
    return [
        f"{rel} missing marker: {marker}" for marker in markers if marker not in text
    ]


def check_forbidden(
    root: pathlib.Path, rel: str, markers: tuple[str, ...]
) -> list[str]:
    path = root / rel
    if not path.is_file():
        return []
    text = read(root, rel)
    return [
        f"{rel} contains stale marker: {marker}" for marker in markers if marker in text
    ]


def check(root: pathlib.Path) -> list[str]:
    failures: list[str] = []
    for rel, markers in REQUIRED_MARKERS.items():
        failures.extend(check_file(root, rel, markers))
    for rel, markers in FORBIDDEN_MARKERS.items():
        failures.extend(check_forbidden(root, rel, markers))
    return failures


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=ROOT)
    args = parser.parse_args(argv)

    failures = check(args.root.resolve())
    if failures:
        print("Backup/restore check failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("PASS backup/restore check")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
