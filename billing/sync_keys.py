#!/usr/bin/env python3
"""Regenerate api_keys.txt from tenant_store (active tenants only).

Format: tenant_id:api_key:plan (one per line).
The api_key stored here is the plaintext key needed for hc-server auth.

Called by provision_tenant.py after tenant creation/suspension/activation,
and by tenant_admin.py CLI.
"""

import fcntl
import os
import sqlite3
import sys
from typing import Optional

import tenant_store

API_KEYS_FILE = os.environ.get("HC_API_KEYS_FILE", "/opt/hc-stark/data/api_keys.txt")


def regenerate(
    conn: sqlite3.Connection,
    api_keys_file: Optional[str] = None,
    active_keys: Optional[dict[str, tuple[str, str]]] = None,
) -> int:
    """Rewrite api_keys.txt with all active tenants.

    Args:
        conn: Tenant store database connection.
        api_keys_file: Path to write. Defaults to HC_API_KEYS_FILE env var.
        active_keys: Optional dict of tenant_id -> (api_key, plan) for tenants
            whose plaintext keys are known. Tenants not in this dict are read
            from the existing api_keys.txt (preserving keys we can't recover
            from hashes).

    Returns:
        Number of active keys written.
    """
    api_keys_file = api_keys_file or API_KEYS_FILE

    # Read existing keys from file (we store hashes in DB, so we need the file
    # to recover plaintext keys for tenants we're not actively modifying).
    existing_keys: dict[str, tuple[str, str]] = {}
    if os.path.exists(api_keys_file):
        with open(api_keys_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) == 3:
                    existing_keys[parts[0]] = (parts[1], parts[2])
                elif len(parts) == 2:
                    existing_keys[parts[0]] = (parts[1], "standard")

    # Merge in any explicitly provided keys (e.g., newly created or rotated).
    if active_keys:
        existing_keys.update(active_keys)

    # Get active tenants from DB.
    active_tenants = tenant_store.list_tenants(conn, status="active")
    active_ids = {row["tenant_id"] for row in active_tenants}
    tenant_plans = {row["tenant_id"]: row["plan"] for row in active_tenants}

    # Write only active tenants that have known keys.
    lines = ["# Auto-generated — do not edit manually\n"]
    count = 0
    for tenant_id in sorted(active_ids):
        if tenant_id in existing_keys:
            api_key, _old_plan = existing_keys[tenant_id]
            plan = tenant_plans.get(tenant_id, "standard")
            lines.append(f"{tenant_id}:{api_key}:{plan}\n")
            count += 1

    # Atomic write with file locking to prevent concurrent webhook corruption.
    lock_path = api_keys_file + ".lock"
    lock_fd = open(lock_path, "w")
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        tmp_path = api_keys_file + ".tmp"
        with open(tmp_path, "w") as f:
            f.writelines(lines)
        os.replace(tmp_path, api_keys_file)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()

    return count


def main() -> None:
    conn = tenant_store.open_db()
    count = regenerate(conn)
    print(f"Wrote {count} active keys to {API_KEYS_FILE}")
    conn.close()


if __name__ == "__main__":
    main()
