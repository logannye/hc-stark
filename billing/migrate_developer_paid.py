#!/usr/bin/env python3
"""Migration: move existing Developer tenants from $0 to the new $9/mo paid plan.

The new pricing (2026) introduces a $9/month base fee for the Developer plan.
This script handles the migration without breaking existing customers:

    1. Mark every current Developer tenant with `developer_grandfather_until` set to
       60 days from migration time. Their plan stays "developer" with no recurring
       charge until that date.
    2. Send each grandfathered tenant a transactional email (separate cron) one
       week and one day before the deadline, prompting them to upgrade via Stripe
       Checkout or downgrade to Free.
    3. On grandfather expiry, the billing cron downgrades any tenant that hasn't
       confirmed payment to "free" (preserving their API key but capping usage).

The script is idempotent: re-running it does not extend already-set grandfather
windows, and never charges anyone.

Usage:
    python billing/migrate_developer_paid.py [--days 60]

Run once, after deploying the server build that knows about
`developer_grandfather_until` and the new Stripe price IDs.
"""

import argparse
import datetime as dt
import os
import sys

import tenant_store


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--days",
        type=int,
        default=60,
        help="Number of days the existing Developer tenants are grandfathered at $0 (default: 60).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would change without writing.",
    )
    args = parser.parse_args()

    if args.days < 14:
        print(f"refusing: --days={args.days} is less than the 14-day minimum notice", file=sys.stderr)
        sys.exit(1)

    conn = tenant_store.open_db()

    # Detect whether the schema knows about developer_grandfather_until. If not,
    # we ALTER TABLE to add it (NULL by default; backfilled here).
    cols = {row[1] for row in conn.execute("PRAGMA table_info(tenants)").fetchall()}
    if "developer_grandfather_until" not in cols:
        if args.dry_run:
            print("[dry-run] would ALTER TABLE tenants ADD COLUMN developer_grandfather_until TEXT")
        else:
            conn.execute(
                "ALTER TABLE tenants ADD COLUMN developer_grandfather_until TEXT"
            )
            conn.commit()
            print("Added column tenants.developer_grandfather_until")

    deadline = (dt.datetime.utcnow() + dt.timedelta(days=args.days)).replace(microsecond=0)
    deadline_iso = deadline.isoformat() + "Z"

    rows = conn.execute(
        "SELECT tenant_id FROM tenants "
        "WHERE plan = 'developer' "
        "AND (developer_grandfather_until IS NULL OR developer_grandfather_until = '')"
    ).fetchall()

    if not rows:
        print("No Developer tenants need grandfathering. All set.")
        conn.close()
        return

    print(f"Grandfathering {len(rows)} Developer tenant(s) at $0/mo until {deadline_iso}")
    if args.dry_run:
        for (tid,) in rows[:5]:
            print(f"  [dry-run] {tid}")
        if len(rows) > 5:
            print(f"  [dry-run] ... and {len(rows) - 5} more")
        conn.close()
        return

    conn.executemany(
        "UPDATE tenants SET developer_grandfather_until = ? WHERE tenant_id = ?",
        [(deadline_iso, tid) for (tid,) in rows],
    )
    conn.commit()

    print(f"Migration complete. {len(rows)} tenant(s) grandfathered until {deadline_iso}.")
    print("Next steps:")
    print("  1. Wire the transactional email cron to read developer_grandfather_until and notify")
    print("     tenants 7 days and 1 day before the deadline.")
    print("  2. Wire the billing cron to downgrade any unconfirmed tenant to 'free' on expiry.")
    print("  3. Update signup.html so new Developer signups go directly to the $9/mo Stripe Checkout.")
    conn.close()


if __name__ == "__main__":
    main()
