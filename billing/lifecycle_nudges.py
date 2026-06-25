#!/usr/bin/env python3
"""Send idempotent lifecycle nudges for TinyZKP activation and upgrade.

Safe to run from cron. Each nudge is keyed by (tenant_id, kind) in
tenant_store.lifecycle_emails and is marked only after SMTP succeeds.
"""

from __future__ import annotations

import argparse
import calendar
import json
import os
import smtplib
import sqlite3
import sys
import time
from dataclasses import dataclass
from email.mime.text import MIMEText
from pathlib import Path
from typing import Callable

import tenant_store


USAGE_DB_PATH = os.environ.get("HC_USAGE_DB_PATH", "/opt/hc-stark/data/usage.sqlite")

SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SMTP_FROM = os.environ.get("SMTP_FROM", "noreply@tinyzkp.com")

ZERO_PROOF_DELAY_MS = 24 * 60 * 60 * 1000
IDLE_WINBACK_DELAY_MS = 14 * 24 * 60 * 60 * 1000
FREE_QUOTA_RECEIPTS = 100
FREE_QUOTA_THRESHOLD = 80

KIND_ZERO_PROOF = "zero_proof_24h"
KIND_FIRST_PROOF = "first_proof_share"
KIND_FREE_QUOTA = "free_quota_80"
KIND_IDLE_WINBACK = "idle_winback_14d"


@dataclass(frozen=True)
class Nudge:
    tenant_id: str
    email: str
    kind: str
    subject: str
    body: str
    metadata: dict[str, object]


def now_ms() -> int:
    return int(time.time() * 1000)


def month_start_ms(value_ms: int) -> int:
    tm = time.gmtime(value_ms / 1000)
    return int(calendar.timegm((tm.tm_year, tm.tm_mon, 1, 0, 0, 0)) * 1000)


def log(entry: dict[str, object]) -> None:
    entry["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print(json.dumps(entry, sort_keys=True), flush=True)


def _empty_counts() -> dict[str, dict[str, int]]:
    return {"total": {}, "monthly": {}, "last_completed_at": {}}


def usage_counts(path: str, current_ms: int) -> dict[str, dict[str, int]]:
    if not path or not Path(path).exists():
        return _empty_counts()
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        total_rows = conn.execute(
            "SELECT tenant_id, COUNT(*) AS count FROM usage_log GROUP BY tenant_id"
        ).fetchall()
        month_rows = conn.execute(
            "SELECT tenant_id, COUNT(*) AS count FROM usage_log WHERE completed_at_ms >= ? GROUP BY tenant_id",
            (month_start_ms(current_ms),),
        ).fetchall()
        last_rows = conn.execute(
            "SELECT tenant_id, MAX(completed_at_ms) AS completed_at_ms FROM usage_log GROUP BY tenant_id"
        ).fetchall()
    except sqlite3.Error as exc:
        log({"action": "usage_counts_failed", "error": str(exc), "usage_db": path})
        return _empty_counts()
    finally:
        conn.close()
    return {
        "total": {row["tenant_id"]: int(row["count"] or 0) for row in total_rows},
        "monthly": {row["tenant_id"]: int(row["count"] or 0) for row in month_rows},
        "last_completed_at": {row["tenant_id"]: int(row["completed_at_ms"] or 0) for row in last_rows},
    }


def signup_url(plan: str | None = None, intent: str = "activation") -> str:
    base = "https://tinyzkp.com/signup"
    params = "source=lifecycle_email&medium=email"
    if plan:
        params += f"&plan={plan}"
    params += f"&intent={intent}"
    return f"{base}?{params}"


def nudge_for_tenant(
    tenant: dict,
    total_proofs: int,
    monthly_proofs: int,
    current_ms: int,
    last_completed_at_ms: int = 0,
) -> list[Nudge]:
    if tenant.get("status") != "active":
        return []
    email = str(tenant.get("email") or "").strip().lower()
    tenant_id = str(tenant.get("tenant_id") or "")
    if not email or "@" not in email or not tenant_id:
        return []

    created_at_ms = int(tenant.get("created_at_ms") or 0)
    plan = str(tenant.get("plan") or "developer")
    out: list[Nudge] = []

    if total_proofs == 0 and current_ms - created_at_ms >= ZERO_PROOF_DELAY_MS:
        out.append(Nudge(
            tenant_id=tenant_id,
            email=email,
            kind=KIND_ZERO_PROOF,
            subject="TinyZKP: create your first proof receipt",
            body=(
                "You have a TinyZKP API key, but this account has not created a proof receipt yet.\n\n"
                "Fastest next steps:\n"
                "  1. Copy the accumulator_step curl from the quickstart: https://tinyzkp.com/docs\n"
                "  2. Try the browser playground: https://tinyzkp.com/try?source=lifecycle_email&medium=email&intent=first_proof\n"
                "  3. Install the MCP server for agent workflows: https://tinyzkp.com/mcp?source=lifecycle_email&medium=email&intent=mcp_install\n\n"
                "Safety note: do not put secrets, private customer data, API keys, or raw credentials into transparent receipt parameters.\n\n"
                "Verification is always free: https://tinyzkp.com/verify\n"
            ),
            metadata={"total_proofs": total_proofs, "monthly_proofs": monthly_proofs},
        ))

    if total_proofs > 0:
        out.append(Nudge(
            tenant_id=tenant_id,
            email=email,
            kind=KIND_FIRST_PROOF,
            subject="TinyZKP: share and verify your first receipt",
            body=(
                "Your TinyZKP account has generated at least one proof receipt.\n\n"
                "Use the receipt as a distribution object:\n"
                "  - Send the proof to the public verifier: https://tinyzkp.com/verify?source=lifecycle_email&medium=email&intent=share_receipt\n"
                "  - Add a customer-visible verifier link to the workflow result.\n"
                "  - Install the Verified by TinyZKP badge: https://tinyzkp.com/badges\n"
                "  - For agents, return a structured receipt envelope with the tool result: https://tinyzkp.com/agent-policy\n\n"
                "A valid receipt proves the encoded statement. It does not prove off-chain context that was not encoded into that statement.\n"
            ),
            metadata={"total_proofs": total_proofs, "monthly_proofs": monthly_proofs},
        ))

    if plan == "free" and monthly_proofs >= FREE_QUOTA_THRESHOLD:
        out.append(Nudge(
            tenant_id=tenant_id,
            email=email,
            kind=KIND_FREE_QUOTA,
            subject="TinyZKP: your free receipt quota is close to the limit",
            body=(
                f"This account has generated {monthly_proofs} proof receipts this month on the Free plan "
                f"({FREE_QUOTA_RECEIPTS}/month included).\n\n"
                "Recommended next step: upgrade to Developer for one production workflow:\n"
                f"  {signup_url('developer', 'quota_upgrade')}\n\n"
                "Use Pro when receipts are customer-visible or auditor-visible, Scale for higher production volume, and Compute for long trace-step workloads.\n"
                "Pricing and plan guidance: https://tinyzkp.com/pricing?source=lifecycle_email&medium=email\n"
            ),
            metadata={"total_proofs": total_proofs, "monthly_proofs": monthly_proofs, "plan": plan},
        ))

    if total_proofs > 0 and last_completed_at_ms > 0 and current_ms - last_completed_at_ms >= IDLE_WINBACK_DELAY_MS:
        out.append(Nudge(
            tenant_id=tenant_id,
            email=email,
            kind=KIND_IDLE_WINBACK,
            subject="TinyZKP: restart the proof receipt workflow",
            body=(
                "This TinyZKP account has generated proof receipts before, but has not generated one recently.\n\n"
                "If the workflow is still useful, restart from the smallest production boundary:\n"
                "  - Copy a receipt pattern from recipes: https://tinyzkp.com/recipes?source=lifecycle_email&medium=email&intent=idle_winback\n"
                "  - Recheck plan limits and spend caps: https://tinyzkp.com/limits?source=lifecycle_email&medium=email\n"
                "  - Verify a receipt in the browser: https://tinyzkp.com/verify?source=lifecycle_email&medium=email&intent=verify_receipt\n"
                "  - Use a paid pilot if the proof statement or verifier placement blocked rollout: https://tinyzkp.com/pilot?source=lifecycle_email&medium=email&intent=pilot_review\n\n"
                "Reply with the boundary that blocked production: statement design, verifier placement, data handling, cost, or integration time.\n"
            ),
            metadata={
                "total_proofs": total_proofs,
                "monthly_proofs": monthly_proofs,
                "last_completed_at_ms": last_completed_at_ms,
            },
        ))

    return out


def send_email(to_email: str, subject: str, body: str) -> bool:
    if not SMTP_HOST:
        print("SMTP not configured, skipping lifecycle email", file=sys.stderr)
        return False

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = to_email

    try:
        if SMTP_PORT == 465:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
            server.starttls()
        with server:
            if SMTP_USER and SMTP_PASSWORD:
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as exc:
        print(f"WARNING: lifecycle email failed for {to_email}: {exc}", file=sys.stderr)
        return False


def run(
    *,
    dry_run: bool,
    usage_db_path: str = USAGE_DB_PATH,
    current_ms: int | None = None,
    max_emails: int = 100,
    send_email_fn: Callable[[str, str, str], bool] = send_email,
) -> dict[str, int]:
    current_ms = current_ms if current_ms is not None else now_ms()
    counts = usage_counts(usage_db_path, current_ms)
    conn = tenant_store.open_db()
    sent = 0
    skipped = 0
    failed = 0
    try:
        tenants = [dict(row) for row in tenant_store.list_tenants(conn)]
        for tenant in tenants:
            tenant_id = tenant["tenant_id"]
            total = counts["total"].get(tenant_id, 0)
            monthly = counts["monthly"].get(tenant_id, 0)
            last_completed_at = counts["last_completed_at"].get(tenant_id, 0)
            for nudge in nudge_for_tenant(tenant, total, monthly, current_ms, last_completed_at):
                if tenant_store.is_lifecycle_email_sent(conn, nudge.tenant_id, nudge.kind):
                    skipped += 1
                    continue
                if sent >= max_emails:
                    skipped += 1
                    log({"action": "skipped", "reason": "max_emails", "tenant_id": nudge.tenant_id, "kind": nudge.kind})
                    continue
                if dry_run:
                    sent += 1
                    log({
                        "action": "would_send",
                        "tenant_id": nudge.tenant_id,
                        "email": nudge.email,
                        "kind": nudge.kind,
                        **nudge.metadata,
                    })
                    continue
                if send_email_fn(nudge.email, nudge.subject, nudge.body):
                    tenant_store.mark_lifecycle_email_sent(conn, nudge.tenant_id, nudge.kind, current_ms)
                    sent += 1
                    log({"action": "sent", "tenant_id": nudge.tenant_id, "kind": nudge.kind})
                else:
                    failed += 1
                    log({"action": "failed", "tenant_id": nudge.tenant_id, "kind": nudge.kind})
    finally:
        conn.close()
    log({"action": "complete", "sent": sent, "skipped": skipped, "failed": failed, "dry_run": dry_run})
    return {"sent": sent, "skipped": skipped, "failed": failed}


def main() -> None:
    parser = argparse.ArgumentParser(description="Send TinyZKP lifecycle activation and upgrade nudges")
    parser.add_argument("--dry-run", action="store_true", help="Print eligible nudges without sending or marking")
    parser.add_argument("--usage-db", default=USAGE_DB_PATH, help="Path to usage.sqlite")
    parser.add_argument("--max-emails", type=int, default=100, help="Max emails to send per run")
    parser.add_argument("--now-ms", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    run(
        dry_run=args.dry_run,
        usage_db_path=args.usage_db,
        current_ms=args.now_ms,
        max_emails=args.max_emails,
    )


if __name__ == "__main__":
    main()
