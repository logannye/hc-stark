#!/usr/bin/env python3
"""Summarize live Stripe Checkout revenue signals without printing buyer PII."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

import stripe
import stripe_account_context_check


PRODUCTION_PILOT_PLAN = "production_pilot"
DEFAULT_ACCOUNT_SOURCE = os.environ.get(
    "TINYZKP_GROWTH_STRIPE_ACCOUNT_SOURCE",
    os.environ.get("TINYZKP_STRIPE_ACCOUNT_SOURCE", "cli"),
).strip().lower() or "cli"
DEFAULT_API_KEY_ENV = os.environ.get(
    "TINYZKP_GROWTH_STRIPE_API_KEY_ENV",
    os.environ.get("TINYZKP_STRIPE_API_KEY_ENV", "STRIPE_SECRET_KEY"),
)
SAFE_METADATA_KEYS = ("plan", "source", "medium", "platform", "intent")
MONITORING_SOURCES = {"api_health_audit"}
SECRET_RE = re.compile(r"\b(?:sk|rk|whsec|acct|cs|cus|pi|sub|price|prod)_[A-Za-z0-9_]{8,}\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


@dataclass
class CheckoutGroup:
    plan: str
    source: str
    medium: str
    platform: str
    intent: str
    sessions: int = 0
    open: int = 0
    complete: int = 0
    expired: int = 0
    paid: int = 0
    amount_total_by_currency: dict[str, int] = field(default_factory=dict)
    paid_amount_by_currency: dict[str, int] = field(default_factory=dict)


@dataclass
class CheckoutSummary:
    mode: str
    lookback_hours: float
    sessions: int = 0
    open: int = 0
    complete: int = 0
    expired: int = 0
    paid: int = 0
    unpaid: int = 0
    no_payment_required: int = 0
    production_pilot_starts: int = 0
    production_pilot_paid: int = 0
    amount_total_by_currency: dict[str, int] = field(default_factory=dict)
    paid_amount_by_currency: dict[str, int] = field(default_factory=dict)
    first_created: int = 0
    last_created: int = 0
    excluded_monitoring_sessions: int = 0
    groups: list[CheckoutGroup] = field(default_factory=list)


def redact(text: object) -> str:
    value = EMAIL_RE.sub("[redacted-email]", str(text))
    return SECRET_RE.sub("[redacted-id]", value)


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    getter = getattr(obj, "get", None)
    if callable(getter):
        return getter(key, default)
    return getattr(obj, key, default)


def _metadata(session: Any) -> dict[str, str]:
    raw = _get(session, "metadata", {}) or {}
    if not isinstance(raw, dict):
        getter = getattr(raw, "to_dict", None)
        raw = getter() if callable(getter) else {}
    clean: dict[str, str] = {}
    for key in SAFE_METADATA_KEYS:
        value = raw.get(key, "")
        if isinstance(value, str):
            value = redact(value.strip().lower()).replace("|", "/").replace("\n", " ")
            clean[key] = value[:80] if value else "-"
    return clean


def plan_from_session(session: Any) -> str:
    metadata = _metadata(session)
    plan = metadata.get("plan", "-")
    package = str((_get(session, "metadata", {}) or {}).get("package", "")).strip().lower()
    amount_total = int(_get(session, "amount_total", 0) or 0)
    mode = str(_get(session, "mode", "") or "").lower()
    if plan in {"pilot", PRODUCTION_PILOT_PLAN} or package == PRODUCTION_PILOT_PLAN:
        return PRODUCTION_PILOT_PLAN
    if mode == "payment" and amount_total == 500_000:
        return PRODUCTION_PILOT_PLAN
    if plan == "team":
        return "pro"
    return plan if plan != "-" else "unknown"


def is_monitoring_session(session: Any) -> bool:
    metadata = _metadata(session)
    source = metadata.get("source", "-")
    return source in MONITORING_SOURCES


def _currency(session: Any) -> str:
    currency = str(_get(session, "currency", "") or "").lower()
    return currency if currency else "unknown"


def _add_amount(bucket: dict[str, int], currency: str, cents: int) -> None:
    if cents <= 0:
        return
    bucket[currency] = bucket.get(currency, 0) + cents


def _status_counter(summary: CheckoutSummary, status: str) -> None:
    if status == "open":
        summary.open += 1
    elif status == "complete":
        summary.complete += 1
    elif status == "expired":
        summary.expired += 1


def _payment_counter(summary: CheckoutSummary, payment_status: str) -> None:
    if payment_status == "paid":
        summary.paid += 1
    elif payment_status == "no_payment_required":
        summary.no_payment_required += 1
    else:
        summary.unpaid += 1


def summarize_sessions(
    sessions: list[Any],
    *,
    mode: str,
    lookback_hours: float,
    include_monitoring: bool = False,
) -> CheckoutSummary:
    summary = CheckoutSummary(mode=mode, lookback_hours=lookback_hours)
    groups: dict[tuple[str, str, str, str, str], CheckoutGroup] = {}
    for session in sessions:
        if not include_monitoring and is_monitoring_session(session):
            summary.excluded_monitoring_sessions += 1
            continue
        summary.sessions += 1
        status = str(_get(session, "status", "") or "").lower()
        payment_status = str(_get(session, "payment_status", "") or "").lower()
        amount_total = int(_get(session, "amount_total", 0) or 0)
        currency = _currency(session)
        created = int(_get(session, "created", 0) or 0)
        metadata = _metadata(session)
        plan = plan_from_session(session)
        key = (
            plan,
            metadata.get("source") or "-",
            metadata.get("medium") or "-",
            metadata.get("platform") or "-",
            metadata.get("intent") or "-",
        )
        group = groups.setdefault(
            key,
            CheckoutGroup(plan=key[0], source=key[1], medium=key[2], platform=key[3], intent=key[4]),
        )

        _status_counter(summary, status)
        _payment_counter(summary, payment_status)
        group.sessions += 1
        if status == "open":
            group.open += 1
        elif status == "complete":
            group.complete += 1
        elif status == "expired":
            group.expired += 1
        if payment_status == "paid":
            group.paid += 1
        if plan == PRODUCTION_PILOT_PLAN:
            summary.production_pilot_starts += 1
            if payment_status == "paid":
                summary.production_pilot_paid += 1

        _add_amount(summary.amount_total_by_currency, currency, amount_total)
        _add_amount(group.amount_total_by_currency, currency, amount_total)
        if payment_status == "paid":
            _add_amount(summary.paid_amount_by_currency, currency, amount_total)
            _add_amount(group.paid_amount_by_currency, currency, amount_total)

        if created and (not summary.first_created or created < summary.first_created):
            summary.first_created = created
        if created > summary.last_created:
            summary.last_created = created

    summary.groups = sorted(
        groups.values(),
        key=lambda group: (
            sum(group.paid_amount_by_currency.values()),
            group.paid,
            group.sessions,
            group.plan,
            group.source,
        ),
        reverse=True,
    )
    return summary


def _safe_json_loads(raw: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Stripe CLI did not return JSON: {redact(str(exc))}") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError("Stripe CLI returned an unexpected JSON shape")
    return parsed


def _stripe_command(
    stripe_bin: str,
    *,
    live: bool,
    limit: int,
    lookback_hours: float,
    stripe_project_name: str = "",
    starting_after: str | None = None,
) -> list[str]:
    created_gte = int(time.time() - lookback_hours * 3600)
    command = [
        stripe_bin,
        "checkout",
        "sessions",
        "list",
        "--limit",
        str(limit),
        "--color",
        "off",
        "--log-level",
        "error",
        "-d",
        f"created[gte]={created_gte}",
    ]
    if live:
        command.append("--live")
    if stripe_project_name:
        command.extend(["--project-name", stripe_project_name])
    if starting_after:
        command.extend(["--starting-after", starting_after])
    return command


def load_sessions_from_stripe_cli(
    *,
    stripe_bin: str = "stripe",
    live: bool = True,
    limit: int = 100,
    max_pages: int = 3,
    lookback_hours: float = 168,
    stripe_project_name: str = "",
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> list[dict[str, Any]]:
    sessions: list[dict[str, Any]] = []
    starting_after: str | None = None
    for _page in range(max_pages):
        command = _stripe_command(
            stripe_bin,
            live=live,
            limit=limit,
            lookback_hours=lookback_hours,
            stripe_project_name=stripe_project_name,
            starting_after=starting_after,
        )
        completed = runner(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if completed.returncode != 0:
            stderr = redact((completed.stderr or completed.stdout or "").strip())
            raise RuntimeError(f"Stripe CLI checkout session query failed: {stderr[:500]}")
        payload = _safe_json_loads(completed.stdout)
        data = payload.get("data", [])
        if not isinstance(data, list):
            raise RuntimeError("Stripe CLI checkout session payload is missing data[]")
        sessions.extend(session for session in data if isinstance(session, dict))
        if not payload.get("has_more") or not data:
            break
        last_id = str(data[-1].get("id") or "")
        if not last_id:
            break
        starting_after = last_id
    return sessions


def _stripe_obj_to_dict(value: Any) -> Any:
    if isinstance(value, dict):
        return value
    to_dict_recursive = getattr(value, "to_dict_recursive", None)
    if callable(to_dict_recursive):
        return to_dict_recursive()
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    return value


def load_sessions_from_stripe_api(
    *,
    stripe_api_key_env: str = DEFAULT_API_KEY_ENV,
    limit: int = 100,
    max_pages: int = 3,
    lookback_hours: float = 168,
) -> list[Any]:
    env_name = (stripe_api_key_env or DEFAULT_API_KEY_ENV).strip()
    api_key = os.environ.get(env_name, "").strip()
    if not api_key:
        raise RuntimeError(f"Stripe API key env var {env_name} is not set")

    sessions: list[Any] = []
    starting_after: str | None = None
    created_gte = int(time.time() - lookback_hours * 3600)
    previous_key = getattr(stripe, "api_key", None)
    try:
        stripe.api_key = api_key
        for _page in range(max_pages):
            params: dict[str, Any] = {
                "created": {"gte": created_gte},
                "limit": limit,
            }
            if starting_after:
                params["starting_after"] = starting_after
            response = stripe.checkout.Session.list(**params)
            data = _get(response, "data", []) or []
            if not isinstance(data, list):
                data = list(data)
            sessions.extend(_stripe_obj_to_dict(session) for session in data)
            if not _get(response, "has_more", False) or not data:
                break
            last_id = str(_get(data[-1], "id", "") or "")
            if not last_id:
                break
            starting_after = last_id
    except Exception as exc:
        raise RuntimeError(f"Stripe API checkout session query failed: {redact(exc)}") from exc
    finally:
        stripe.api_key = previous_key
    return sessions


def summary_to_dict(summary: CheckoutSummary) -> dict[str, Any]:
    return {
        **asdict(summary),
        "groups": [asdict(group) for group in summary.groups],
    }


def _fmt_date(timestamp: int) -> str:
    if not timestamp:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(timestamp))


def _fmt_money(cents_by_currency: dict[str, int]) -> str:
    if not cents_by_currency:
        return "$0.00"
    parts = []
    for currency, cents in sorted(cents_by_currency.items()):
        prefix = "$" if currency == "usd" else f"{currency.upper()} "
        parts.append(f"{prefix}{cents / 100:.2f}")
    return ", ".join(parts)


def report_markdown(summary: CheckoutSummary) -> str:
    rows = [
        "# TinyZKP Stripe Checkout Monitor",
        "",
        f"Mode: {summary.mode}",
        f"Lookback: {summary.lookback_hours:g} hours",
        f"First session: {_fmt_date(summary.first_created)}",
        f"Last session: {_fmt_date(summary.last_created)}",
        "",
        f"- Checkout sessions: {summary.sessions}",
        f"- Open / complete / expired: {summary.open} / {summary.complete} / {summary.expired}",
        f"- Paid / unpaid / no-payment-required: {summary.paid} / {summary.unpaid} / {summary.no_payment_required}",
        f"- Checkout amount started: {_fmt_money(summary.amount_total_by_currency)}",
        f"- Paid revenue observed: {_fmt_money(summary.paid_amount_by_currency)}",
        f"- Production Pilot starts / paid: {summary.production_pilot_starts} / {summary.production_pilot_paid}",
        f"- Monitoring canary sessions excluded: {summary.excluded_monitoring_sessions}",
        "",
        "| Plan | Source | Medium | Platform | Intent | Sessions | Open | Complete | Expired | Paid | Started amount | Paid revenue |",
        "|---|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for group in summary.groups:
        rows.append(
            "| "
            + " | ".join(
                [
                    group.plan,
                    group.source,
                    group.medium,
                    group.platform,
                    group.intent,
                    str(group.sessions),
                    str(group.open),
                    str(group.complete),
                    str(group.expired),
                    str(group.paid),
                    _fmt_money(group.amount_total_by_currency),
                    _fmt_money(group.paid_amount_by_currency),
                ]
            )
            + " |"
        )
    return "\n".join(rows) + "\n"


def collect_checkout_summary(
    *,
    stripe_bin: str = "stripe",
    live: bool = True,
    limit: int = 100,
    max_pages: int = 3,
    lookback_hours: float = 168,
    include_monitoring: bool = False,
    expected_display_name: str = "LN Holdings",
    stripe_project_name: str = "",
    account_source: str = DEFAULT_ACCOUNT_SOURCE,
    stripe_api_key_env: str = DEFAULT_API_KEY_ENV,
    skip_account_check: bool = False,
    timeout: int = 30,
) -> CheckoutSummary:
    source = (account_source or "cli").strip().lower()
    if not skip_account_check:
        account_result = stripe_account_context_check.run_check(
            stripe_bin=stripe_bin,
            stripe_project_name=stripe_project_name,
            account_source=source,
            stripe_api_key_env=stripe_api_key_env,
            expected_display_name=expected_display_name,
            timeout=timeout,
        )
        if account_result.status != "PASS":
            raise RuntimeError(f"Stripe account context failed: {account_result.detail}")
    if source == "api":
        sessions = load_sessions_from_stripe_api(
            stripe_api_key_env=stripe_api_key_env,
            limit=limit,
            max_pages=max_pages,
            lookback_hours=lookback_hours,
        )
    elif source == "cli":
        sessions = load_sessions_from_stripe_cli(
            stripe_bin=stripe_bin,
            live=live,
            limit=limit,
            max_pages=max_pages,
            lookback_hours=lookback_hours,
            stripe_project_name=stripe_project_name,
        )
    else:
        raise RuntimeError(f"Unsupported Stripe account source: {redact(source)}")
    return summarize_sessions(
        sessions,
        mode="live" if live else "test",
        lookback_hours=lookback_hours,
        include_monitoring=include_monitoring,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stripe-bin", default="stripe", help="Stripe CLI executable path")
    parser.add_argument("--stripe-project-name", default="", help="Optional Stripe CLI project profile name")
    parser.add_argument(
        "--account-source",
        choices=("cli", "api"),
        default=DEFAULT_ACCOUNT_SOURCE,
        help="Stripe account/session source: CLI profile or Stripe API key",
    )
    parser.add_argument(
        "--stripe-api-key-env",
        default=DEFAULT_API_KEY_ENV,
        help="Environment variable containing the Stripe secret key for --account-source api",
    )
    parser.add_argument("--test", action="store_true", help="Use Stripe test mode instead of live mode")
    parser.add_argument("--limit", type=int, default=100, help="Checkout sessions per Stripe page")
    parser.add_argument("--max-pages", type=int, default=3, help="Maximum Stripe pages to read")
    parser.add_argument("--lookback-hours", type=float, default=168, help="Only read sessions created in this trailing window")
    parser.add_argument("--from-json", type=Path, help="Read a Stripe checkout.sessions.list JSON payload from disk")
    parser.add_argument("--include-monitoring-sessions", action="store_true", help="Include source=api_health_audit canary sessions in revenue summaries")
    parser.add_argument(
        "--expected-stripe-display-name",
        default=os.environ.get("TINYZKP_STRIPE_EXPECTED_DISPLAY_NAME", "LN Holdings"),
        help="Required substring in the active Stripe account display_name",
    )
    parser.add_argument("--skip-account-check", action="store_true", help="Skip Stripe account display_name validation")
    parser.add_argument("--account-check-timeout", type=int, default=30, help="Stripe account-context timeout in seconds")
    parser.add_argument("--json", action="store_true", help="Emit sanitized machine-readable JSON")
    parser.add_argument("--min-paid-sessions", type=int, help="Fail unless at least this many paid sessions are observed")
    parser.add_argument("--min-pilot-paid-sessions", type=int, help="Fail unless at least this many paid Production Pilot sessions are observed")
    return parser


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    if args.limit < 1 or args.limit > 100:
        raise SystemExit("--limit must be between 1 and 100")
    if args.max_pages < 1:
        raise SystemExit("--max-pages must be at least 1")
    if args.lookback_hours <= 0:
        raise SystemExit("--lookback-hours must be positive")

    if args.from_json:
        payload = _safe_json_loads(args.from_json.read_text(encoding="utf-8"))
        data = payload.get("data", [])
        if not isinstance(data, list):
            raise SystemExit("--from-json payload must contain data[]")
        summary = summarize_sessions(
            data,
            mode="file",
            lookback_hours=args.lookback_hours,
            include_monitoring=args.include_monitoring_sessions,
        )
    else:
        try:
            summary = collect_checkout_summary(
                stripe_bin=args.stripe_bin,
                stripe_project_name=args.stripe_project_name,
                account_source=args.account_source,
                stripe_api_key_env=args.stripe_api_key_env,
                live=not args.test,
                limit=args.limit,
                max_pages=args.max_pages,
                lookback_hours=args.lookback_hours,
                include_monitoring=args.include_monitoring_sessions,
                expected_display_name=args.expected_stripe_display_name,
                skip_account_check=args.skip_account_check,
                timeout=args.account_check_timeout,
            )
        except RuntimeError as exc:
            print(f"FAIL {redact(exc)}", file=sys.stderr)
            return 1

    if args.json:
        print(json.dumps(summary_to_dict(summary), indent=2, sort_keys=True))
    else:
        print(report_markdown(summary), end="")

    failures = []
    if args.min_paid_sessions is not None and summary.paid < args.min_paid_sessions:
        failures.append(f"paid sessions {summary.paid} < {args.min_paid_sessions}")
    if args.min_pilot_paid_sessions is not None and summary.production_pilot_paid < args.min_pilot_paid_sessions:
        failures.append(f"paid pilot sessions {summary.production_pilot_paid} < {args.min_pilot_paid_sessions}")
    for failure in failures:
        print(f"FAIL {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
