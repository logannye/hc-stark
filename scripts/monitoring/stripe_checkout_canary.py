#!/usr/bin/env python3
"""Create tagged live Stripe Checkout Sessions through TinyZKP public routes.

This is a positive canary for revenue-critical checkout creation. It creates
real open Checkout Sessions, so every request is tagged with
source=api_health_audit and medium=monitoring. Revenue monitors exclude that
source by default.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
STRIPE_ID_RE = re.compile(r"\b(?:cs|cus|pi|price|prod|acct|req)_[A-Za-z0-9_]{8,}\b")
CHECKOUT_HOST = "checkout.stripe.com"
SESSION_ID_RE = re.compile(r"\bcs_(?:live|test)_[A-Za-z0-9_]+\b")


@dataclass(frozen=True)
class CanaryResult:
    name: str
    status: str
    detail: str


def redact(value: object) -> str:
    text = EMAIL_RE.sub("[redacted-email]", str(value))
    text = STRIPE_ID_RE.sub("[redacted-id]", text)
    return text.replace("https://checkout.stripe.com/", "https://checkout.stripe.com/[redacted]/")


def _json_request(
    url: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    timeout: float,
    opener: Callable[..., Any] = urlopen,
) -> tuple[int, dict[str, Any]]:
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = Request(
        url,
        data=body,
        method=method,
        headers={
            "Content-Type": "application/json",
            "Origin": "https://tinyzkp.com",
            "User-Agent": "TinyZKP-Stripe-Checkout-Canary/1.0",
        },
    )
    try:
        with opener(request, timeout=timeout) as response:
            parsed = json.loads(response.read().decode("utf-8"))
            return int(getattr(response, "status", 200)), parsed if isinstance(parsed, dict) else {}
    except HTTPError as exc:
        try:
            parsed = json.loads(exc.read().decode("utf-8"))
        except Exception:
            parsed = {"error": str(exc)}
        return exc.code, parsed if isinstance(parsed, dict) else {"error": str(parsed)}
    except (URLError, OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(redact(exc)) from exc


def _checkout_session_id(payload: dict[str, Any]) -> str:
    url = str(payload.get("url") or "")
    match = SESSION_ID_RE.search(url)
    return match.group(0) if match else ""


def _checkout_url_ok(payload: dict[str, Any], *, require_live: bool) -> bool:
    url = str(payload.get("url") or "")
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.netloc != CHECKOUT_HOST or not parsed.path.startswith("/c/"):
        return False
    session_id = _checkout_session_id(payload)
    if require_live and not session_id.startswith("cs_live_"):
        return False
    return True


def _verify_cli_can_read_session(
    session_id: str,
    *,
    stripe_bin: str,
    stripe_project_name: str = "",
    timeout: float,
) -> CanaryResult:
    command = [
        stripe_bin,
        "checkout",
        "sessions",
        "retrieve",
        session_id,
        "--live",
        "--color",
        "off",
        "--log-level",
        "error",
    ]
    if stripe_project_name:
        command.extend(["--project-name", stripe_project_name])
    try:
        completed = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CanaryResult("local Stripe CLI visibility", "WARN", f"could not run Stripe CLI: {redact(exc)}")
    if completed.returncode != 0:
        error = redact((completed.stderr or completed.stdout or "").strip())
        return CanaryResult("local Stripe CLI visibility", "WARN", f"canary session was not readable by local Stripe CLI: {error[:240]}")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        return CanaryResult("local Stripe CLI visibility", "WARN", f"Stripe CLI returned non-JSON output: {redact(exc)}")
    if payload.get("id") == session_id:
        return CanaryResult("local Stripe CLI visibility", "PASS", "local Stripe CLI can retrieve the canary Checkout Session")
    return CanaryResult("local Stripe CLI visibility", "WARN", "local Stripe CLI returned an unexpected session payload")


def _canary_email(kind: str, now: int | None = None) -> str:
    timestamp = now or int(time.time())
    return f"audit+{kind}-{timestamp}@tinyzkp.com"


def run_canaries(
    *,
    site_url: str,
    timeout: float,
    include_subscription: bool,
    include_pilot: bool,
    require_live: bool = True,
    verify_stripe_cli: bool = False,
    stripe_bin: str = "stripe",
    stripe_project_name: str = "",
    opener: Callable[..., Any] = urlopen,
    now: int | None = None,
) -> list[CanaryResult]:
    results: list[CanaryResult] = []
    site = site_url.rstrip("/") + "/"

    if include_subscription:
        status, payload = _json_request(
            urljoin(site, "api/create-checkout"),
            method="POST",
            timeout=timeout,
            opener=opener,
            payload={
                "email": _canary_email("stripe", now),
                "plan": "developer",
                "cadence": "monthly",
                "source": "api_health_audit",
                "medium": "monitoring",
                "intent": "checkout_canary",
            },
        )
        if status == 200 and _checkout_url_ok(payload, require_live=require_live):
            results.append(CanaryResult("subscription checkout", "PASS", "returned live hosted Stripe Checkout URL"))
            if verify_stripe_cli:
                results.append(
                    _verify_cli_can_read_session(
                        _checkout_session_id(payload),
                        stripe_bin=stripe_bin,
                        stripe_project_name=stripe_project_name,
                        timeout=timeout,
                    )
                )
        else:
            results.append(CanaryResult("subscription checkout", "FAIL", f"status={status}, payload={redact(payload)}"))

    if include_pilot:
        capability_status, capability = _json_request(
            urljoin(site, "api/create-pilot-checkout"),
            timeout=timeout,
            opener=opener,
        )
        if capability_status != 200 or capability.get("available") is not True:
            results.append(CanaryResult("pilot checkout", "WARN", f"capability unavailable: status={capability_status}"))
        else:
            status, payload = _json_request(
                urljoin(site, "api/create-pilot-checkout"),
                method="POST",
                timeout=timeout,
                opener=opener,
                payload={
                    "email": _canary_email("pilot", now),
                    "pilot_workflow": "Production pilot checkout canary",
                    "source": "api_health_audit",
                    "medium": "monitoring",
                    "intent": "paid_pilot_checkout_canary",
                },
            )
            if status == 200 and _checkout_url_ok(payload, require_live=require_live):
                results.append(CanaryResult("pilot checkout", "PASS", "returned live hosted Stripe Checkout URL"))
                if verify_stripe_cli:
                    results.append(
                        _verify_cli_can_read_session(
                            _checkout_session_id(payload),
                            stripe_bin=stripe_bin,
                            stripe_project_name=stripe_project_name,
                            timeout=timeout,
                        )
                    )
            else:
                results.append(CanaryResult("pilot checkout", "FAIL", f"status={status}, payload={redact(payload)}"))

    return results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site-url", default="https://tinyzkp.com", help="TinyZKP site origin")
    parser.add_argument("--timeout", type=float, default=20.0, help="HTTP timeout in seconds")
    parser.add_argument("--skip-subscription", action="store_true", help="Skip Developer subscription checkout canary")
    parser.add_argument("--skip-pilot", action="store_true", help="Skip Production Pilot checkout canary")
    parser.add_argument("--allow-test-mode", action="store_true", help="Accept cs_test Checkout URLs; intended only for staging")
    parser.add_argument("--verify-stripe-cli", action="store_true", help="Check whether the local Stripe CLI can retrieve created canary sessions")
    parser.add_argument("--stripe-bin", default="stripe", help="Stripe CLI executable path for --verify-stripe-cli")
    parser.add_argument("--stripe-project-name", default="", help="Optional Stripe CLI project profile name for --verify-stripe-cli")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    return parser


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    if args.timeout <= 0:
        raise SystemExit("--timeout must be positive")
    results = run_canaries(
        site_url=args.site_url,
        timeout=args.timeout,
        include_subscription=not args.skip_subscription,
        include_pilot=not args.skip_pilot,
        require_live=not args.allow_test_mode,
        verify_stripe_cli=args.verify_stripe_cli,
        stripe_bin=args.stripe_bin,
        stripe_project_name=args.stripe_project_name,
    )
    failed = [result for result in results if result.status == "FAIL"]
    if args.json:
        print(json.dumps({"ok": not failed, "results": [asdict(result) for result in results]}, indent=2))
    else:
        for result in results:
            print(f"{result.status} {result.name} - {result.detail}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
