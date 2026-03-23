#!/usr/bin/env python3
"""CLI tool for tenant lifecycle management.

Usage:
    python3 tenant_admin.py list
    python3 tenant_admin.py suspend <tenant_id>
    python3 tenant_admin.py activate <tenant_id>
    python3 tenant_admin.py rotate-key <tenant_id>
    python3 tenant_admin.py set-plan <tenant_id> <plan>
    python3 tenant_admin.py usage <tenant_id>
"""

import argparse
import os
import secrets
import sqlite3
import string
import sys
import time

import tenant_store
import sync_keys


def _generate_api_key(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return "tzk_" + "".join(secrets.choice(alphabet) for _ in range(length))

USAGE_DB_PATH = os.environ.get("HC_USAGE_DB_PATH", "/opt/hc-stark/data/usage.sqlite")


def cmd_list(args: argparse.Namespace) -> None:
    conn = tenant_store.open_db()
    tenants = tenant_store.list_tenants(conn, status=args.status)
    if not tenants:
        print("No tenants found.")
        return
    fmt = "{:<20} {:<30} {:<12} {:<10} {}"
    print(fmt.format("TENANT_ID", "EMAIL", "STATUS", "PLAN", "CREATED"))
    for t in tenants:
        created = time.strftime("%Y-%m-%d", time.gmtime(t["created_at_ms"] / 1000))
        print(fmt.format(
            t["tenant_id"], t["email"][:28], t["status"], t["plan"], created
        ))
    conn.close()


def cmd_suspend(args: argparse.Namespace) -> None:
    conn = tenant_store.open_db()
    t = tenant_store.get_tenant(conn, args.tenant_id)
    if not t:
        print(f"Tenant {args.tenant_id} not found.", file=sys.stderr)
        sys.exit(1)
    tenant_store.suspend_tenant(conn, args.tenant_id)
    sync_keys.regenerate(conn)
    print(f"Suspended {args.tenant_id} and regenerated api_keys.txt")
    conn.close()


def cmd_activate(args: argparse.Namespace) -> None:
    conn = tenant_store.open_db()
    t = tenant_store.get_tenant(conn, args.tenant_id)
    if not t:
        print(f"Tenant {args.tenant_id} not found.", file=sys.stderr)
        sys.exit(1)
    # Activation requires a new key since the old plaintext was removed on suspension.
    new_key = _generate_api_key()
    tenant_store.activate_tenant(conn, args.tenant_id)
    tenant_store.update_api_key(conn, args.tenant_id, new_key)
    sync_keys.regenerate(conn, active_keys={args.tenant_id: (new_key, t["plan"])})
    print(f"Activated {args.tenant_id} with new API key")
    print(f"New API key: {new_key}")
    conn.close()


def cmd_rotate_key(args: argparse.Namespace) -> None:
    conn = tenant_store.open_db()
    t = tenant_store.get_tenant(conn, args.tenant_id)
    if not t:
        print(f"Tenant {args.tenant_id} not found.", file=sys.stderr)
        sys.exit(1)

    new_key = _generate_api_key()
    tenant_store.update_api_key(conn, args.tenant_id, new_key)
    sync_keys.regenerate(conn, active_keys={args.tenant_id: (new_key, t["plan"])})
    print(f"Rotated key for {args.tenant_id}")
    print(f"New API key: {new_key}")
    print("The old key is now invalid. api_keys.txt has been regenerated.")
    conn.close()


def cmd_set_plan(args: argparse.Namespace) -> None:
    valid_plans = ("free", "developer", "team", "scale", "enterprise")
    if args.plan not in valid_plans:
        print(f"Invalid plan '{args.plan}'. Must be one of: {', '.join(valid_plans)}", file=sys.stderr)
        sys.exit(1)

    conn = tenant_store.open_db()
    t = tenant_store.get_tenant(conn, args.tenant_id)
    if not t:
        print(f"Tenant {args.tenant_id} not found.", file=sys.stderr)
        sys.exit(1)

    tenant_store.set_plan(conn, args.tenant_id, args.plan)
    sync_keys.regenerate(conn)
    print(f"Set plan for {args.tenant_id} to '{args.plan}' and regenerated api_keys.txt")
    conn.close()


def cmd_usage(args: argparse.Namespace) -> None:
    if not os.path.exists(USAGE_DB_PATH):
        print("No usage database found.")
        return

    conn = sqlite3.connect(USAGE_DB_PATH)
    conn.row_factory = sqlite3.Row

    proofs = conn.execute(
        "SELECT COUNT(*) as cnt, SUM(trace_length) as total_trace FROM usage_log WHERE tenant_id = ?",
        (args.tenant_id,),
    ).fetchone()

    unbilled = conn.execute(
        "SELECT COUNT(*) as cnt FROM usage_log WHERE tenant_id = ? AND billed = 0",
        (args.tenant_id,),
    ).fetchone()

    print(f"Usage for {args.tenant_id}:")
    print(f"  Total proofs:   {proofs['cnt']}")
    print(f"  Total trace:    {proofs['total_trace'] or 0}")
    print(f"  Unbilled proofs: {unbilled['cnt']}")
    conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="TinyZKP Tenant Admin")
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="List all tenants")
    p_list.add_argument("--status", help="Filter by status (active/suspended/cancelled)")
    p_list.set_defaults(func=cmd_list)

    p_suspend = sub.add_parser("suspend", help="Suspend a tenant")
    p_suspend.add_argument("tenant_id")
    p_suspend.set_defaults(func=cmd_suspend)

    p_activate = sub.add_parser("activate", help="Activate a tenant")
    p_activate.add_argument("tenant_id")
    p_activate.set_defaults(func=cmd_activate)

    p_rotate = sub.add_parser("rotate-key", help="Rotate a tenant's API key")
    p_rotate.add_argument("tenant_id")
    p_rotate.set_defaults(func=cmd_rotate_key)

    p_plan = sub.add_parser("set-plan", help="Change a tenant's plan")
    p_plan.add_argument("tenant_id")
    p_plan.add_argument("plan", choices=["free", "developer", "team", "scale", "enterprise"])
    p_plan.set_defaults(func=cmd_set_plan)

    p_usage = sub.add_parser("usage", help="Show tenant usage summary")
    p_usage.add_argument("tenant_id")
    p_usage.set_defaults(func=cmd_usage)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
