#!/usr/bin/env python3
"""Hourly cron: reads unbilled proofs from usage.sqlite and reports to Stripe.

Idempotent — safe to re-run. Uses Stripe Meter Events API (replaces deprecated
create_usage_record). The meter event_name must match the Stripe Meter configured
in the dashboard (default: "proof_usage").

Reads tenant data from tenant_store.sqlite.
"""

import argparse
import json
import os
import sqlite3
import sys
import time
import urllib.request

import stripe

import tenant_store

# ---- Config ----

stripe.api_key = os.environ["STRIPE_SECRET_KEY"]

USAGE_DB_PATH = os.environ.get("HC_USAGE_DB_PATH", "/opt/hc-stark/data/usage.sqlite")
ALERT_WEBHOOK_URL = os.environ.get("ALERT_WEBHOOK_URL")
METER_EVENT_NAME = os.environ.get("STRIPE_METER_EVENT_NAME", "proof_usage")

# Price tiers (trace_length → cents per proof).
TIERS = [
    (10_000, 5),        # < 10K steps   → $0.05
    (100_000, 50),      # 10K–100K      → $0.50
    (1_000_000, 200),   # 100K–1M       → $2.00
    (10_000_000, 500),  # 1M–10M        → $5.00
    (None, 2000),       # > 10M steps   → $20.00 (XL)
]


def price_cents(trace_length: int) -> int:
    for limit, cents in TIERS:
        if limit is None or trace_length < limit:
            return cents
    return TIERS[-1][1]


def _log(entry: dict) -> None:
    """Write a structured JSON log line."""
    entry["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print(json.dumps(entry), flush=True)


def _send_alert(message: str, details: dict) -> None:
    """POST alert to Slack/Discord webhook if configured."""
    if not ALERT_WEBHOOK_URL:
        return
    payload = json.dumps({
        "text": f"⚠️ hc-billing alert: {message}",
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*{message}*\n```{json.dumps(details, indent=2)}```"}},
        ],
    }).encode()
    req = urllib.request.Request(
        ALERT_WEBHOOK_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        _log({"action": "alert_failed", "error": str(e)})


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync unbilled usage to Stripe via Meter Events")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without touching Stripe")
    parser.add_argument("--report", action="store_true", help="Output unbilled summary as JSON")
    args = parser.parse_args()

    if not os.path.exists(USAGE_DB_PATH):
        _log({"action": "skip", "reason": "no usage database"})
        return

    # Load tenant data from tenant_store.
    ts_conn = tenant_store.open_db()
    tenants = tenant_store.list_tenants(ts_conn)
    tenant_map: dict[str, dict] = {}
    for t in tenants:
        tenant_map[t["tenant_id"]] = {
            "stripe_customer_id": t["stripe_customer_id"],
            "email": t["email"],
            "status": t["status"],
        }
    ts_conn.close()

    if not tenant_map:
        _log({"action": "skip", "reason": "no tenants in store"})
        return

    conn = sqlite3.connect(USAGE_DB_PATH)
    conn.row_factory = sqlite3.Row

    rows = conn.execute(
        "SELECT id, tenant_id, job_id, trace_length FROM usage_log WHERE billed = 0"
    ).fetchall()

    if not rows:
        _log({"action": "complete", "billed": 0, "skipped": 0, "errors": 0})
        return

    if args.report:
        # Output unbilled summary as JSON.
        summary: dict[str, dict] = {}
        for row in rows:
            tid = row["tenant_id"]
            if tid not in summary:
                summary[tid] = {"count": 0, "total_cents": 0}
            summary[tid]["count"] += 1
            summary[tid]["total_cents"] += price_cents(row["trace_length"])
        print(json.dumps(summary, indent=2))
        conn.close()
        return

    billed = 0
    skipped = 0
    errors = 0
    unbillable: dict[str, dict] = {}

    for row in rows:
        tenant_id = row["tenant_id"]
        tenant_info = tenant_map.get(tenant_id, {})
        customer_id = tenant_info.get("stripe_customer_id")

        if not customer_id:
            skipped += 1
            cents = price_cents(row["trace_length"])
            if tenant_id not in unbillable:
                unbillable[tenant_id] = {"count": 0, "estimated_cents": 0}
            unbillable[tenant_id]["count"] += 1
            unbillable[tenant_id]["estimated_cents"] += cents
            continue

        cents = price_cents(row["trace_length"])

        if args.dry_run:
            _log({
                "action": "would_bill",
                "tenant_id": tenant_id,
                "row_id": row["id"],
                "cents": cents,
                "stripe_customer_id": customer_id,
                "meter_event": METER_EVENT_NAME,
            })
            billed += 1
            continue

        try:
            stripe.billing.MeterEvent.create(
                event_name=METER_EVENT_NAME,
                payload={
                    "value": str(cents),
                    "stripe_customer_id": customer_id,
                },
                identifier=f"hc-usage-{row['id']}",
            )
        except stripe.error.StripeError as e:
            _log({
                "action": "stripe_error",
                "tenant_id": tenant_id,
                "row_id": row["id"],
                "error": str(e),
            })
            errors += 1
            continue

        conn.execute("UPDATE usage_log SET billed = 1 WHERE id = ?", (row["id"],))
        conn.commit()
        billed += 1
        _log({"action": "billed", "tenant_id": tenant_id, "row_id": row["id"], "cents": cents})

    # Alert on unbillable usage.
    if unbillable:
        for tenant_id, info in unbillable.items():
            _log({
                "action": "unbillable",
                "tenant_id": tenant_id,
                "count": info["count"],
                "estimated_cents": info["estimated_cents"],
            })
        _send_alert(
            f"Unbillable usage detected for {len(unbillable)} tenant(s)",
            unbillable,
        )

    _log({
        "action": "complete",
        "billed": billed,
        "skipped": skipped,
        "errors": errors,
    })

    conn.close()


if __name__ == "__main__":
    main()
