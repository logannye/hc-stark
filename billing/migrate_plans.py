#!/usr/bin/env python3
"""One-time migration: rename legacy plan names.

    standard → developer
    pro      → scale

Safe to re-run (idempotent). Run after deploying the new server and billing code.
The Rust server's default arm in PlanLimits::for_plan() handles unknown plan
strings as "developer" limits, so this migration can run at any time without
breaking existing tenants.
"""

import os
import sys

import tenant_store
import sync_keys

API_KEYS_FILE = os.environ.get("HC_API_KEYS_FILE", "/opt/hc-stark/data/api_keys.txt")


def main() -> None:
    conn = tenant_store.open_db()

    # Count affected rows before migration.
    standard_count = conn.execute(
        "SELECT COUNT(*) FROM tenants WHERE plan = 'standard'"
    ).fetchone()[0]
    pro_count = conn.execute(
        "SELECT COUNT(*) FROM tenants WHERE plan = 'pro'"
    ).fetchone()[0]

    if standard_count == 0 and pro_count == 0:
        print("No tenants need migration. All plans are already up to date.")
        conn.close()
        return

    print(f"Migrating {standard_count} 'standard' → 'developer', {pro_count} 'pro' → 'scale'")

    conn.execute("UPDATE tenants SET plan = 'developer' WHERE plan = 'standard'")
    conn.execute("UPDATE tenants SET plan = 'scale' WHERE plan = 'pro'")
    conn.commit()

    # Regenerate api_keys.txt so the server picks up new plan names.
    sync_keys.regenerate(conn, API_KEYS_FILE)

    print("Migration complete. api_keys.txt regenerated.")
    print("The server will pick up new plan names within 60 seconds (hot-reload).")
    conn.close()


if __name__ == "__main__":
    main()
