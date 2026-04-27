#!/usr/bin/env python3
"""Hourly cron: reads unbilled proofs from usage.sqlite and reports to Stripe.

Idempotent — safe to re-run. Uses Stripe Meter Events API (replaces deprecated
create_usage_record). The meter event_name must match the Stripe Meter configured
in the dashboard (default: "proof_usage").

Reads tenant data from tenant_store.sqlite.

Idempotency contract
--------------------
Two layers protect against double-billing:

1. **Semantic dedup** (Stripe's `identifier` parameter on MeterEvent.create).
   Stripe deduplicates meter events whose identifier matches a prior event
   within its dedup window (~24h). Our identifier is derived from the
   immutable proof identity (tenant + job + usage row id), so retries of
   the same usage row never produce a second meter event.

2. **HTTP-level idempotency** (Stripe SDK's `idempotency_key`). Protects
   against SDK-internal HTTP retries on transient errors — a retried
   request with the same key returns the original response, never a
   duplicate event.

If the SQLite UPDATE billed=1 step fails after MeterEvent.create succeeds,
the next cron run will replay the row and the semantic dedup catches it —
PROVIDED the next run happens inside Stripe's dedup window. To guard
against this, we alert if any unbilled row is older than UNBILLED_ALERT_HOURS
(default 12h), which is well inside the ~24h window.
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
# Alert if any usage row stays unbilled longer than this. Must stay safely
# below Stripe's meter-event dedup window (~24h) so a delayed cron run can
# still rely on semantic dedup to prevent double-billing.
UNBILLED_ALERT_HOURS = int(os.environ.get("HC_UNBILLED_ALERT_HOURS", "12"))

# Price tiers (trace_length → base cents per proof).
TIERS = [
    (10_000, 5),         # < 10K steps   → $0.05
    (100_000, 50),       # 10K–100K      → $0.50
    (1_000_000, 200),    # 100K–1M       → $2.00
    (10_000_000, 800),   # 1M–10M        → $8.00
    (None, 3000),        # > 10M steps   → $30.00
]

# Plan-based discount factors. Team gets 25% off, Scale gets 40% off.
DISCOUNT_FACTORS: dict[str, float] = {
    "free": 1.0,
    "developer": 1.0,
    "standard": 1.0,   # legacy — same as developer
    "team": 0.75,
    "scale": 0.60,
    "pro": 0.60,       # legacy alias — Stripe product is named "Pro" but matches scale's rate sheet
}


def price_cents(trace_length: int) -> int:
    """Base price in cents (before plan discounts)."""
    for limit, cents in TIERS:
        if limit is None or trace_length < limit:
            return cents
    return TIERS[-1][1]


def discounted_price_cents(trace_length: int, plan: str) -> int:
    """Price in cents after applying plan-based discount."""
    base = price_cents(trace_length)
    factor = DISCOUNT_FACTORS.get(plan, 1.0)
    return max(1, round(base * factor))


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
        # tenant_store.list_tenants returns sqlite3.Row, which doesn't expose
        # dict.get(). Convert to dict so callers (including the .get fallback
        # for the legacy plan column) work correctly. This was a latent bug
        # introduced in 2aeb2b2 (pricing overhaul) — without this conversion
        # AttributeError aborts the whole billing run.
        td = dict(t)
        tenant_map[td["tenant_id"]] = {
            "stripe_customer_id": td.get("stripe_customer_id"),
            "email": td.get("email"),
            "status": td.get("status"),
            "plan": td.get("plan", "developer"),
        }
    ts_conn.close()

    if not tenant_map:
        _log({"action": "skip", "reason": "no tenants in store"})
        return

    conn = sqlite3.connect(USAGE_DB_PATH)
    conn.row_factory = sqlite3.Row
    # The Rust hc-server holds writer locks on this same file. Wait up to
    # 5s for contention rather than returning SQLITE_BUSY immediately —
    # matches the Rust side (crates/hc-server/src/usage_log.rs).
    conn.execute("PRAGMA busy_timeout = 5000")

    rows = conn.execute(
        "SELECT id, tenant_id, job_id, trace_length, completed_at_ms "
        "FROM usage_log WHERE billed = 0"
    ).fetchall()

    # Freshness check: alert if any unbilled row predates Stripe's dedup window.
    # If a cron outage has let rows age past UNBILLED_ALERT_HOURS, we can no
    # longer rely on semantic dedup against repeat MeterEvent.create calls.
    if rows and not args.report and not args.dry_run:
        threshold_ms = int(time.time() * 1000) - (UNBILLED_ALERT_HOURS * 3600 * 1000)
        stale = [r for r in rows if r["completed_at_ms"] < threshold_ms]
        if stale:
            stale_summary = {
                "stale_count": len(stale),
                "oldest_age_hours": round(
                    (int(time.time() * 1000) - min(r["completed_at_ms"] for r in stale)) / 3_600_000,
                    2,
                ),
                "threshold_hours": UNBILLED_ALERT_HOURS,
            }
            _log({"action": "stale_unbilled", **stale_summary})
            _send_alert(
                "Unbilled usage rows older than dedup window — review before next run",
                stale_summary,
            )

    if not rows:
        _log({"action": "complete", "billed": 0, "skipped": 0, "errors": 0})
        return

    if args.report:
        # Output unbilled summary as JSON.
        summary: dict[str, dict] = {}
        for row in rows:
            tid = row["tenant_id"]
            plan = tenant_map.get(tid, {}).get("plan", "developer")
            if tid not in summary:
                summary[tid] = {"count": 0, "total_cents": 0, "plan": plan}
            summary[tid]["count"] += 1
            summary[tid]["total_cents"] += discounted_price_cents(row["trace_length"], plan)
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
        plan = tenant_info.get("plan", "developer")

        if not customer_id:
            skipped += 1
            cents = discounted_price_cents(row["trace_length"], plan)
            if tenant_id not in unbillable:
                unbillable[tenant_id] = {"count": 0, "estimated_cents": 0}
            unbillable[tenant_id]["count"] += 1
            unbillable[tenant_id]["estimated_cents"] += cents
            continue

        cents = discounted_price_cents(row["trace_length"], plan)

        if args.dry_run:
            _log({
                "action": "would_bill",
                "tenant_id": tenant_id,
                "row_id": row["id"],
                "job_id": row["job_id"],
                "cents": cents,
                "stripe_customer_id": customer_id,
                "meter_event": METER_EVENT_NAME,
                "meter_identifier": f"hc-usage-{tenant_id}-{row['job_id']}",
            })
            billed += 1
            continue

        # Identifier is derived from the immutable proof identity so Stripe's
        # semantic dedup catches replays even if the SQLite row id ever
        # collides (e.g. after a restore-from-backup that resets autoincrement).
        # job_id is UNIQUE in the source schema, so {tenant_id}-{job_id} is
        # globally unique per proof.
        meter_identifier = f"hc-usage-{tenant_id}-{row['job_id']}"
        # HTTP-level idempotency: protects against SDK-internal retries on
        # transient network errors. Distinct from the semantic dedup above.
        http_idempotency_key = f"hc-usage-http-{tenant_id}-{row['job_id']}"

        try:
            stripe.billing.MeterEvent.create(
                event_name=METER_EVENT_NAME,
                payload={
                    "value": str(cents),
                    "stripe_customer_id": customer_id,
                },
                identifier=meter_identifier,
                idempotency_key=http_idempotency_key,
            )
        except stripe.error.StripeError as e:
            _log({
                "action": "stripe_error",
                "tenant_id": tenant_id,
                "row_id": row["id"],
                "job_id": row["job_id"],
                "error": str(e),
            })
            errors += 1
            continue

        # Stripe accepted the event. Mark the row billed. If this UPDATE fails
        # we must alert — on the next run we'll re-fetch the row, and the
        # MeterEvent.create call above will be deduped by Stripe (within its
        # ~24h window). The freshness check at the top of this function will
        # alert if we drift outside that window.
        try:
            conn.execute("UPDATE usage_log SET billed = 1 WHERE id = ?", (row["id"],))
            conn.commit()
        except sqlite3.Error as db_err:
            _log({
                "action": "post_meter_update_failed",
                "tenant_id": tenant_id,
                "row_id": row["id"],
                "job_id": row["job_id"],
                "meter_identifier": meter_identifier,
                "error": str(db_err),
            })
            _send_alert(
                "MeterEvent succeeded but UPDATE billed=1 failed — manual reconciliation required",
                {
                    "tenant_id": tenant_id,
                    "row_id": row["id"],
                    "job_id": row["job_id"],
                    "meter_identifier": meter_identifier,
                    "error": str(db_err),
                },
            )
            errors += 1
            continue

        billed += 1
        _log({
            "action": "billed",
            "tenant_id": tenant_id,
            "row_id": row["id"],
            "job_id": row["job_id"],
            "cents": cents,
            "meter_identifier": meter_identifier,
        })

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
