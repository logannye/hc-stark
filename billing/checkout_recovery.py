#!/usr/bin/env python3
"""Send idempotent recovery emails for abandoned Stripe Checkout sessions.

The signup page can create paid subscription Checkout Sessions before a tenant
exists. This worker uses Stripe as the durable source for those starts, finds
open sessions older than a short delay, and sends one plaintext recovery email
per session while suppressing repeat emails to the same address for a cooldown
window.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import smtplib
import sys
import time
from dataclasses import dataclass
from email.mime.text import MIMEText
from typing import Callable, Iterable
from urllib.parse import quote

import stripe

import tenant_store


STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
stripe.api_key = STRIPE_SECRET_KEY or None

SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SMTP_FROM = os.environ.get("SMTP_FROM", "noreply@tinyzkp.com")

RECOVERY_DELAY_HOURS = float(os.environ.get("CHECKOUT_RECOVERY_DELAY_HOURS", "3"))
RECOVERY_LOOKBACK_HOURS = float(os.environ.get("CHECKOUT_RECOVERY_LOOKBACK_HOURS", "48"))
RECOVERY_COOLDOWN_HOURS = float(os.environ.get("CHECKOUT_RECOVERY_COOLDOWN_HOURS", "168"))
SELF_SERVE_PLANS = {"developer", "pro", "scale", "compute"}
PRODUCTION_PILOT_PLAN = "production_pilot"
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
STRIPE_ID_RE = re.compile(r"\b(?:cs|cus|pi|sub|price|prod)_[A-Za-z0-9_]{8,}\b")
TRUE_VALUES = {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class CheckoutRecovery:
    session_id: str
    email: str
    plan: str
    checkout_url: str
    created: int
    metadata: dict[str, str]

    @property
    def is_pilot(self) -> bool:
        return self.plan == PRODUCTION_PILOT_PLAN


def now_ms() -> int:
    return int(time.time() * 1000)


def log(entry: dict[str, object]) -> None:
    entry["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print(json.dumps(entry, sort_keys=True), flush=True)


def customer_emails_enabled() -> bool:
    return os.environ.get("TINYZKP_CUSTOMER_EMAILS_ENABLED", "0").strip().lower() in TRUE_VALUES


def effective_dry_run(cli_dry_run: bool) -> bool:
    return bool(cli_dry_run or not customer_emails_enabled())


def _stable_ref(value: str, prefix: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}_{digest}"


def _redact_text(value: object) -> str:
    text = str(value)
    text = EMAIL_RE.sub("[redacted-email]", text)
    return STRIPE_ID_RE.sub("[redacted-id]", text)


def _recovery_log_fields(recovery: CheckoutRecovery) -> dict[str, object]:
    return {
        "recipient_ref": _stable_ref(recovery.email, "email"),
        "session_ref": _stable_ref(recovery.session_id, "session"),
        "plan": recovery.plan,
        "is_pilot": recovery.is_pilot,
        "created": recovery.created,
    }


def log_recovery(action: str, recovery: CheckoutRecovery, **extra: object) -> None:
    entry = {"action": action, **_recovery_log_fields(recovery)}
    entry.update(extra)
    log(entry)


def _get(obj: object, key: str, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    getter = getattr(obj, "get", None)
    if callable(getter):
        return getter(key, default)
    return getattr(obj, key, default)


def _metadata(obj: object) -> dict[str, str]:
    raw = _get(obj, "metadata", {}) or {}
    if not isinstance(raw, dict):
        getter = getattr(raw, "to_dict", None)
        raw = getter() if callable(getter) else {}
    clean: dict[str, str] = {}
    for key, value in raw.items():
        if isinstance(key, str) and isinstance(value, str):
            clean[key] = value[:160]
    return clean


def _email_from_session(session: object) -> str:
    email = _get(session, "customer_email", "") or ""
    if not email:
        details = _get(session, "customer_details", {}) or {}
        email = _get(details, "email", "") or ""
    email = str(email).strip().lower()
    return email if "@" in email and len(email) <= 254 else ""


def _plan_from_session(session: object) -> str:
    metadata = _metadata(session)
    plan = (metadata.get("plan") or "developer").strip().lower()
    package = (metadata.get("package") or "").strip().lower()
    if plan in {"pilot", PRODUCTION_PILOT_PLAN} or package == PRODUCTION_PILOT_PLAN:
        return PRODUCTION_PILOT_PLAN
    if plan == "team":
        return "pro"
    return plan if plan in SELF_SERVE_PLANS else "developer"


def fallback_recovery_url(plan: str, metadata: dict[str, str]) -> str:
    source = quote(metadata.get("source") or "checkout_recovery")
    platform = quote(metadata.get("platform") or "stripe_checkout")
    if plan == PRODUCTION_PILOT_PLAN:
        workflow = quote(metadata.get("pilot_workflow") or metadata.get("workflow") or "production_pilot")
        return (
            "https://tinyzkp.com/pilot"
            f"?source=checkout_recovery&medium=email"
            f"&intent=paid_pilot_checkout&previous_source={source}"
            f"&platform={platform}&workflow={workflow}"
        )
    workflow = quote(metadata.get("workflow") or "paid_signup")
    return (
        "https://tinyzkp.com/signup"
        f"?source=checkout_recovery&medium=email&plan={quote(plan)}"
        f"&intent=finish_checkout&previous_source={source}&platform={platform}&workflow={workflow}"
    )


def recovery_body(recovery: CheckoutRecovery) -> str:
    checkout_url = recovery.checkout_url or fallback_recovery_url(recovery.plan, recovery.metadata)
    if recovery.is_pilot:
        return (
            "You started TinyZKP Production Pilot checkout but did not finish payment.\n\n"
            "Finish the $5,000 pilot checkout here:\n"
            f"  {checkout_url}\n\n"
            "The pilot is for one scoped proof-receipt workflow, statement review, verifier placement, success metrics, and a rollout decision.\n"
            "If converted within 60 days, the pilot is creditable toward an annual, platform, or reserved-capacity agreement.\n\n"
            "Safety note: do not put secrets, private customer data, API keys, or raw credentials into transparent receipt parameters.\n\n"
            "If checkout was not intentional, ignore this email.\n"
        )

    plan_label = recovery.plan.capitalize()
    return (
        f"You started TinyZKP {plan_label} checkout but did not finish setting up billing.\n\n"
        "Finish checkout here:\n"
        f"  {checkout_url}\n\n"
        "Why finish now:\n"
        "  - Developer is for one production proof-receipt workflow.\n"
        "  - Pro is for recurring customer-visible or auditor-visible receipts.\n"
        "  - Scale is for higher-volume production workflows.\n"
        "  - Compute is for long supported traces priced by trace steps.\n\n"
        "Spend caps and current limits are published here:\n"
        "  https://tinyzkp.com/limits?source=checkout_recovery&medium=email\n\n"
        "Safety note: do not put secrets, private customer data, API keys, or raw credentials into transparent receipt parameters.\n\n"
        "If checkout was not intentional, ignore this email.\n"
    )


def list_open_checkout_sessions(created_gte: int, created_lte: int) -> Iterable[object]:
    if not stripe.api_key:
        raise RuntimeError("STRIPE_SECRET_KEY is required")
    response = stripe.checkout.Session.list(
        status="open",
        created={"gte": created_gte, "lte": created_lte},
        limit=100,
    )
    pager = getattr(response, "auto_paging_iter", None)
    if callable(pager):
        return pager()
    return response.get("data", []) if isinstance(response, dict) else []


def recovery_from_session(session: object) -> CheckoutRecovery | None:
    session_id = str(_get(session, "id", "") or "")
    if not session_id:
        return None
    mode = str(_get(session, "mode", "") or "")
    metadata = _metadata(session)
    plan = _plan_from_session(session)
    if mode == "payment" and plan != PRODUCTION_PILOT_PLAN:
        return None
    if mode and mode not in {"subscription", "payment"}:
        return None
    if mode == "subscription" and plan == PRODUCTION_PILOT_PLAN:
        return None
    email = _email_from_session(session)
    if not email:
        return None
    checkout_url = str(_get(session, "url", "") or "")
    created = int(_get(session, "created", 0) or 0)
    return CheckoutRecovery(
        session_id=session_id,
        email=email,
        plan=plan,
        checkout_url=checkout_url,
        created=created,
        metadata=metadata,
    )


def send_email(to_email: str, subject: str, body: str) -> bool:
    if not SMTP_HOST:
        print("SMTP not configured, skipping checkout recovery email", file=sys.stderr)
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
        print(
            "WARNING: checkout recovery email failed "
            f"for recipient_ref={_stable_ref(to_email.strip().lower(), 'email')}: {_redact_text(exc)}",
            file=sys.stderr,
        )
        return False


def run(
    *,
    dry_run: bool,
    current_ms: int | None = None,
    max_emails: int = 50,
    list_sessions_fn: Callable[[int, int], Iterable[object]] = list_open_checkout_sessions,
    send_email_fn: Callable[[str, str, str], bool] = send_email,
) -> dict[str, int]:
    current_ms = current_ms if current_ms is not None else now_ms()
    now_s = current_ms // 1000
    created_lte = int(now_s - RECOVERY_DELAY_HOURS * 3600)
    created_gte = int(now_s - RECOVERY_LOOKBACK_HOURS * 3600)
    cooldown_ms = int(RECOVERY_COOLDOWN_HOURS * 3600 * 1000)

    conn = tenant_store.open_db()
    sent = 0
    skipped = 0
    failed = 0
    try:
        for session in list_sessions_fn(created_gte, created_lte):
            recovery = recovery_from_session(session)
            if recovery is None:
                skipped += 1
                continue
            if tenant_store.is_checkout_recovery_sent(conn, recovery.session_id):
                skipped += 1
                continue
            if not recovery.is_pilot and tenant_store.get_by_email(conn, recovery.email):
                skipped += 1
                log_recovery("skipped", recovery, reason="tenant_exists")
                continue
            last_sent_at = tenant_store.last_checkout_recovery_sent_at(conn, recovery.email)
            if last_sent_at is not None and current_ms - last_sent_at < cooldown_ms:
                skipped += 1
                log_recovery("skipped", recovery, reason="cooldown")
                continue
            if sent >= max_emails:
                skipped += 1
                log_recovery("skipped", recovery, reason="max_emails")
                continue

            subject = (
                "TinyZKP: finish your production pilot checkout"
                if recovery.is_pilot
                else "TinyZKP: finish setting up proof receipts"
            )
            body = recovery_body(recovery)
            if dry_run:
                sent += 1
                log_recovery("would_send", recovery)
                continue
            if send_email_fn(recovery.email, subject, body):
                tenant_store.mark_checkout_recovery_sent(
                    conn,
                    recovery.session_id,
                    recovery.email,
                    recovery.plan,
                    current_ms,
                )
                sent += 1
                log_recovery("sent", recovery)
            else:
                failed += 1
                log_recovery("failed", recovery)
    finally:
        conn.close()
    log({"action": "complete", "sent": sent, "skipped": skipped, "failed": failed, "dry_run": dry_run})
    return {"sent": sent, "skipped": skipped, "failed": failed}


def main() -> None:
    parser = argparse.ArgumentParser(description="Send TinyZKP abandoned Checkout recovery emails")
    parser.add_argument("--dry-run", action="store_true", help="Print eligible recoveries without sending or marking")
    parser.add_argument("--max-emails", type=int, default=50, help="Max recovery emails per run")
    parser.add_argument("--now-ms", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    dry_run = effective_dry_run(args.dry_run)
    if dry_run and not args.dry_run:
        log({
            "action": "customer_email_disabled",
            "script": "checkout_recovery",
            "env": "TINYZKP_CUSTOMER_EMAILS_ENABLED",
            "mode": "dry_run",
        })
    run(dry_run=dry_run, current_ms=args.now_ms, max_emails=args.max_emails)


if __name__ == "__main__":
    main()
