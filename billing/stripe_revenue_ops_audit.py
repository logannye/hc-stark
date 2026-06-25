#!/usr/bin/env python3
"""Read-only Stripe and Cloudflare revenue-ops audit for TinyZKP."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import stripe_account_context_check


STRIPE_ID_RE = re.compile(r"\b(?:sk|rk|whsec|acct|cs|cus|pi|sub|price|prod|mtr|req)_[A-Za-z0-9_*]{8,}\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SECRET_RE = re.compile(r"^\s*-\s+([A-Z][A-Z0-9_]*):\s+Value Encrypted\s*$")

REQUIRED_SECRET_NAMES = {
    "INTERNAL_SECRET",
    "STRIPE_SECRET_KEY",
    "STRIPE_PRICE_ID_TRACE_STEP_METERED",
    "STRIPE_PRICE_ID_DEVELOPER",
    "STRIPE_PRICE_ID_PRO",
    "STRIPE_PRICE_ID_SCALE",
    "TINYZKP_DEMO_API_KEY",
}
ONE_OF_SECRET_GROUPS = (("STRIPE_PRICE_ID_METERED", "STRIPE_PRICE_ID"),)
OPTIONAL_SECRET_NAMES = {"STRIPE_PRICE_ID_PILOT"}

EXPECTED_PRODUCTS = {
    "TinyZKP Developer",
    "TinyZKP Pro",
    "TinyZKP Scale",
    "TinyZKP Proof Generation",
    "TinyZKP Compute",
}
OPTIONAL_PRODUCTS = {"TinyZKP Production Pilot"}
LEGACY_PRODUCTS = {"TinyZKP Team", "TinyZKP Researcher"}

EXPECTED_METERS = {
    "proof_usage": "Proof Usage",
    "trace_step_usage": "TinyZKP trace step usage",
}

EXPECTED_PRICE_SPECS = {
    "Developer Monthly v2": {"unit_amount": 1900, "currency": "usd", "interval": "month", "usage_type": "licensed"},
    "Developer Annual v2": {"unit_amount": 18240, "currency": "usd", "interval": "year", "usage_type": "licensed"},
    "Pro Monthly v2": {"unit_amount": 7900, "currency": "usd", "interval": "month", "usage_type": "licensed"},
    "Pro Annual v2": {"unit_amount": 75840, "currency": "usd", "interval": "year", "usage_type": "licensed"},
    "Scale Monthly": {"unit_amount": 19900, "currency": "usd", "interval": "month", "usage_type": "licensed"},
    "Scale Annual": {"unit_amount": 191040, "currency": "usd", "interval": "year", "usage_type": "licensed"},
    "Per-proof usage (cents)": {"currency": "usd", "interval": "month", "usage_type": "metered"},
    "Trace-step usage": {"currency": "usd", "interval": "month", "usage_type": "metered"},
}
OPTIONAL_PRICE_SPECS = {
    "Production Pilot": {"unit_amount": 500000, "currency": "usd"},
}


@dataclass(frozen=True)
class Check:
    status: str
    category: str
    name: str
    detail: str


def redact(text: object) -> str:
    value = EMAIL_RE.sub("[redacted-email]", str(text))
    return STRIPE_ID_RE.sub("[redacted-id]", value)


def run_json_command(
    command: tuple[str, ...],
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    timeout: int = 30,
) -> dict[str, Any]:
    completed = runner(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        error = redact((completed.stderr or completed.stdout or "").strip())
        raise RuntimeError(error[:500] or f"{command[0]} exited with {completed.returncode}")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{command[0]} returned non-JSON output: {redact(exc)}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"{command[0]} returned unexpected JSON")
    return payload


def stripe_list(
    resource: str | tuple[str, ...],
    *,
    stripe_bin: str,
    live: bool,
    timeout: int,
    stripe_project_name: str = "",
) -> dict[str, Any]:
    resource_parts = (resource,) if isinstance(resource, str) else resource
    command = [
        stripe_bin,
        *resource_parts,
        "list",
        "--limit",
        "100",
        "--color",
        "off",
        "--log-level",
        "error",
    ]
    if live:
        command.append("--live")
    if stripe_project_name:
        command.extend(["--project-name", stripe_project_name])
    return run_json_command(tuple(command), timeout=timeout)


def read_secret_names(project_name: str, *, timeout: int) -> set[str]:
    completed = subprocess.run(
        ("wrangler", "pages", "secret", "list", "--project-name", project_name),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(redact(completed.stdout.strip()) or f"wrangler exited with {completed.returncode}")
    names: set[str] = set()
    for line in completed.stdout.splitlines():
        match = SECRET_RE.match(line)
        if match:
            names.add(match.group(1))
    return names


def fetch_pilot_capability(url: str, *, timeout: int) -> dict[str, Any]:
    request = Request(url, headers={"User-Agent": "TinyZKP-Revenue-Ops-Audit/1.0"})
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = json.load(response)
    except (HTTPError, URLError, OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(redact(exc)) from exc
    if not isinstance(payload, dict):
        raise RuntimeError("pilot capability returned unexpected JSON")
    return payload


def _product_names(products_payload: dict[str, Any]) -> set[str]:
    return {
        str(product.get("name") or "")
        for product in products_payload.get("data", [])
        if isinstance(product, dict) and product.get("active") is not False
    }


def _meter_events(meters_payload: dict[str, Any]) -> set[str]:
    return {
        str(meter.get("event_name") or "")
        for meter in meters_payload.get("data", [])
        if isinstance(meter, dict) and str(meter.get("status") or "active") == "active"
    }


def _prices_by_nickname(prices_payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    prices: dict[str, dict[str, Any]] = {}
    for price in prices_payload.get("data", []):
        if not isinstance(price, dict) or price.get("active") is False:
            continue
        nickname = str(price.get("nickname") or "")
        if nickname:
            prices[nickname] = price
    return prices


def _price_matches(price: dict[str, Any], spec: dict[str, Any]) -> tuple[bool, str]:
    recurring = price.get("recurring") if isinstance(price.get("recurring"), dict) else {}
    checks = {
        "currency": price.get("currency"),
        "unit_amount": price.get("unit_amount"),
        "interval": recurring.get("interval"),
        "usage_type": recurring.get("usage_type"),
    }
    mismatches = [
        f"{key}={checks.get(key)!r} expected {expected!r}"
        for key, expected in spec.items()
        if checks.get(key) != expected
    ]
    if mismatches:
        return False, "; ".join(mismatches)
    return True, "active price matches expected catalog spec"


def evaluate(
    *,
    products_payload: dict[str, Any],
    meters_payload: dict[str, Any],
    prices_payload: dict[str, Any],
    secret_names: set[str],
    pilot_capability: dict[str, Any],
) -> list[Check]:
    checks: list[Check] = []
    products = _product_names(products_payload)
    meters = _meter_events(meters_payload)
    prices = _prices_by_nickname(prices_payload)

    checks.append(Check("PASS", "Stripe CLI", "products list", f"{len(products_payload.get('data', []))} product(s) readable"))
    checks.append(Check("PASS", "Stripe CLI", "billing meters list", f"{len(meters_payload.get('data', []))} meter(s) readable"))
    checks.append(Check("PASS", "Stripe CLI", "prices list", f"{len(prices_payload.get('data', []))} price(s) readable"))

    for event_name, display_name in sorted(EXPECTED_METERS.items()):
        if event_name in meters:
            checks.append(Check("PASS", "Stripe meters", event_name, f"active meter is present for {display_name}"))
        else:
            checks.append(Check("WARN", "Stripe meters", event_name, "billing meter is missing; setup script needs a write-capable Stripe profile"))

    for name in sorted(EXPECTED_PRODUCTS):
        if name in products:
            checks.append(Check("PASS", "Stripe catalog", name, "active product is present"))
        else:
            checks.append(Check("WARN", "Stripe catalog", name, "current catalog product is missing; setup script needs a write-capable Stripe profile"))
    for name in sorted(OPTIONAL_PRODUCTS):
        status = "PASS" if name in products else "WARN"
        detail = "active optional product is present" if status == "PASS" else "optional catalog product is missing; live pilot can still use inline price_data"
        checks.append(Check(status, "Stripe catalog", name, detail))
    for name in sorted(LEGACY_PRODUCTS & products):
        checks.append(Check("WARN", "Stripe catalog", name, "legacy product is still active; verify current Pages secrets do not point at stale plan economics"))

    for nickname, spec in EXPECTED_PRICE_SPECS.items():
        price = prices.get(nickname)
        if not price:
            checks.append(Check("WARN", "Stripe prices", nickname, "current expected price nickname is missing from readable live catalog"))
            continue
        ok, detail = _price_matches(price, spec)
        checks.append(Check("PASS" if ok else "FAIL", "Stripe prices", nickname, detail))
    for nickname, spec in OPTIONAL_PRICE_SPECS.items():
        price = prices.get(nickname)
        if not price:
            checks.append(Check("WARN", "Stripe prices", nickname, "optional pilot catalog price is missing; inline price_data fallback is expected"))
            continue
        ok, detail = _price_matches(price, spec)
        checks.append(Check("PASS" if ok else "FAIL", "Stripe prices", nickname, detail))

    for name in sorted(REQUIRED_SECRET_NAMES):
        if name in secret_names:
            checks.append(Check("PASS", "Cloudflare Pages", name, "secret name is present"))
        else:
            checks.append(Check("FAIL", "Cloudflare Pages", name, "required secret name is missing"))
    for group in ONE_OF_SECRET_GROUPS:
        present = sorted(name for name in group if name in secret_names)
        checks.append(
            Check(
                "PASS" if present else "FAIL",
                "Cloudflare Pages",
                " / ".join(group),
                "accepted proof-meter secret present: " + ", ".join(present) if present else "missing all accepted proof-meter secret names",
            )
        )
    for name in sorted(OPTIONAL_SECRET_NAMES):
        if name in secret_names:
            checks.append(Check("PASS", "Cloudflare Pages", name, "optional catalog pilot price secret is present"))
        else:
            checks.append(Check("WARN", "Cloudflare Pages", name, "optional pilot price secret missing; live route must keep inline price_data fallback available"))

    available = pilot_capability.get("available") is True
    amount = int(pilot_capability.get("amount") or 0)
    mode = str(pilot_capability.get("mode") or "")
    pricing_source = str(pilot_capability.get("pricing_source") or "")
    if available and amount == 5000 and mode == "payment":
        checks.append(Check("PASS", "live pilot checkout", "capability endpoint", f"available via {pricing_source or 'unknown pricing source'}"))
    else:
        checks.append(Check("FAIL", "live pilot checkout", "capability endpoint", f"unexpected capability payload: {redact(pilot_capability)}"))
    if pilot_capability.get("catalog_price_configured") is True:
        checks.append(Check("PASS", "live pilot checkout", "catalog price binding", "STRIPE_PRICE_ID_PILOT is active in production"))
    elif pricing_source == "inline_price_data":
        checks.append(Check("PASS", "live pilot checkout", "inline price fallback", "pilot checkout remains sellable without STRIPE_PRICE_ID_PILOT"))
    else:
        checks.append(Check("WARN", "live pilot checkout", "pilot pricing source", "pilot route is available but pricing source is unclear"))

    return checks


def run_audit(args: argparse.Namespace) -> list[Check]:
    checks: list[Check] = []
    if not getattr(args, "skip_account_check", False):
        result = stripe_account_context_check.run_check(
            stripe_bin=args.stripe_bin,
            stripe_project_name=getattr(args, "stripe_project_name", ""),
            expected_display_name=getattr(args, "expected_stripe_display_name", "TinyZKP"),
            timeout=args.timeout,
        )
        checks.append(Check(result.status, "Stripe CLI", result.name, result.detail))
        if result.status != "PASS":
            return checks
    try:
        products_payload = stripe_list(
            "products",
            stripe_bin=args.stripe_bin,
            live=not args.test,
            timeout=args.timeout,
            stripe_project_name=getattr(args, "stripe_project_name", ""),
        )
    except Exception as exc:
        return [Check("FAIL", "Stripe CLI", "products list", redact(exc))]
    try:
        meters_payload = stripe_list(
            ("billing", "meters"),
            stripe_bin=args.stripe_bin,
            live=not args.test,
            timeout=args.timeout,
            stripe_project_name=getattr(args, "stripe_project_name", ""),
        )
    except Exception as exc:
        return [Check("FAIL", "Stripe CLI", "billing meters list", redact(exc))]
    try:
        prices_payload = stripe_list(
            "prices",
            stripe_bin=args.stripe_bin,
            live=not args.test,
            timeout=args.timeout,
            stripe_project_name=getattr(args, "stripe_project_name", ""),
        )
    except Exception as exc:
        return [Check("FAIL", "Stripe CLI", "prices list", redact(exc))]
    try:
        secret_names = read_secret_names(args.project_name, timeout=args.timeout)
    except Exception as exc:
        return [Check("FAIL", "Cloudflare Pages", "secret inventory", redact(exc))]
    try:
        pilot_capability = fetch_pilot_capability(args.pilot_capability_url, timeout=args.timeout)
    except Exception as exc:
        return [Check("FAIL", "live pilot checkout", "capability endpoint", redact(exc))]

    checks.extend(
        evaluate(
            products_payload=products_payload,
            meters_payload=meters_payload,
            prices_payload=prices_payload,
            secret_names=secret_names,
            pilot_capability=pilot_capability,
        )
    )
    return checks


def _print_text(checks: list[Check]) -> None:
    generated = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    print(f"TinyZKP Stripe revenue ops audit - {generated}")
    for check in checks:
        print(f"{check.status:<4} {check.category}: {check.name} - {check.detail}")
    failures = [check for check in checks if check.status == "FAIL"]
    warnings = [check for check in checks if check.status == "WARN"]
    passes = [check for check in checks if check.status == "PASS"]
    print()
    print(f"Stripe revenue ops audit: {len(passes)} passed, {len(warnings)} warned, {len(failures)} failed")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stripe-bin", default="stripe", help="Stripe CLI executable path")
    parser.add_argument("--stripe-project-name", default="", help="Optional Stripe CLI project profile name")
    parser.add_argument("--test", action="store_true", help="Use Stripe test mode instead of live mode")
    parser.add_argument("--project-name", default="tinyzkp", help="Cloudflare Pages project name")
    parser.add_argument("--pilot-capability-url", default="https://tinyzkp.com/api/create-pilot-checkout")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--strict-catalog", action="store_true", help="Treat WARN catalog hygiene checks as failures")
    parser.add_argument(
        "--expected-stripe-display-name",
        default=os.environ.get("TINYZKP_STRIPE_EXPECTED_DISPLAY_NAME", "TinyZKP"),
        help="Required substring in the active Stripe CLI display_name",
    )
    parser.add_argument("--skip-account-check", action="store_true", help="Skip Stripe CLI display_name validation")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    return parser


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    checks = run_audit(args)
    if args.json:
        print(json.dumps({"checks": [asdict(check) for check in checks]}, indent=2))
    else:
        _print_text(checks)
    failures = [check for check in checks if check.status == "FAIL"]
    warnings = [check for check in checks if check.status == "WARN"]
    if failures or (args.strict_catalog and warnings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
