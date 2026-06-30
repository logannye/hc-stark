#!/usr/bin/env python3
"""Check whether the Stripe CLI profile can reach catalog write endpoints.

The probes are intentionally invalid create requests. A write-capable key should
reach Stripe validation and fail without creating anything. A restricted key
fails earlier with a permissions error, which lets setup scripts stop before a
partial catalog build.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from typing import Callable

import stripe_account_context_check


STRIPE_ID_RE = re.compile(r"\b(?:sk|rk|whsec|acct|cs|cus|pi|sub|price|prod|mtr|req)_[A-Za-z0-9_*]{8,}\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PERMISSION_MARKERS = (
    "does not have the required permissions",
    "restricted key",
    "not authorized",
    "permission denied",
)
VALIDATION_MARKERS = (
    "invalid",
    "must",
    "cannot",
    "no such",
    "resource_missing",
    "parameter_invalid",
    "missing required param",
)


@dataclass(frozen=True)
class Probe:
    name: str
    command: tuple[str, ...]


@dataclass(frozen=True)
class ProbeResult:
    status: str
    name: str
    detail: str


def redact(text: object) -> str:
    value = EMAIL_RE.sub("[redacted-email]", str(text))
    return STRIPE_ID_RE.sub("[redacted-id]", value)


def build_probes(*, stripe_bin: str, live: bool, scope: str, stripe_project_name: str = "") -> list[Probe]:
    suffix = ("--live",) if live else ()
    project = ("--project-name", stripe_project_name) if stripe_project_name else ()
    common = ("--color", "off", "--log-level", "error", *suffix, *project)
    probes = [
        Probe(
            "products create",
            (
                stripe_bin,
                "products",
                "create",
                "--name",
                "",
                "--confirm",
                *common,
            ),
        ),
        Probe(
            "prices create",
            (
                stripe_bin,
                "prices",
                "create",
                "--currency",
                "usd",
                "--unit-amount",
                "1",
                "--product",
                "prod_00000000000000",
                "--confirm",
                *common,
            ),
        ),
    ]
    if scope == "full":
        probes.append(
            Probe(
                "billing meters create",
                (
                    stripe_bin,
                    "billing",
                    "meters",
                    "create",
                    "--display-name",
                    "",
                    "--event-name",
                    "",
                    "-d",
                    "default_aggregation[formula]=sum",
                    "-d",
                    "customer_mapping[event_payload_key]=stripe_customer_id",
                    "-d",
                    "customer_mapping[type]=by_id",
                    "-d",
                    "value_settings[event_payload_key]=value",
                    "--confirm",
                    *common,
                ),
            )
        )
    return probes


def run_probe(
    probe: Probe,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    timeout: int = 30,
) -> ProbeResult:
    try:
        completed = runner(
            probe.command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except OSError as exc:
        return ProbeResult("FAIL", probe.name, redact(exc))
    except subprocess.TimeoutExpired:
        return ProbeResult("FAIL", probe.name, f"timed out after {timeout}s")

    raw_output = "\n".join(part for part in (completed.stderr, completed.stdout) if part).strip()
    output = redact(raw_output)
    lowered = output.lower()
    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        payload = {}
    if isinstance(payload, dict) and payload.get("error"):
        error = payload.get("error") if isinstance(payload.get("error"), dict) else {}
        message = error.get("message") if isinstance(error, dict) else payload.get("error")
        error_type = error.get("type") if isinstance(error, dict) else ""
        output = redact(f"{message or raw_output}\n{error_type or ''}".strip())
        lowered = output.lower()
    elif completed.returncode == 0:
        return ProbeResult(
            "FAIL",
            probe.name,
            "invalid write-permission probe unexpectedly succeeded; inspect Stripe dashboard before running setup",
        )
    if any(marker in lowered for marker in PERMISSION_MARKERS):
        return ProbeResult("FAIL", probe.name, output[:600] or "Stripe denied catalog write access")
    if any(marker in lowered for marker in VALIDATION_MARKERS):
        return ProbeResult("PASS", probe.name, "write endpoint reached Stripe validation without creating a resource")
    return ProbeResult("FAIL", probe.name, output[:600] or "unexpected Stripe CLI error")


def run_preflight(*, stripe_bin: str, live: bool, scope: str, timeout: int, stripe_project_name: str = "") -> list[ProbeResult]:
    return [
        run_probe(probe, timeout=timeout)
        for probe in build_probes(
            stripe_bin=stripe_bin,
            live=live,
            scope=scope,
            stripe_project_name=stripe_project_name,
        )
    ]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stripe-bin", default="stripe", help="Stripe CLI executable path")
    parser.add_argument("--stripe-project-name", default="", help="Optional Stripe CLI project profile name")
    parser.add_argument("--live", action="store_true", help="Pass --live to Stripe CLI probes")
    parser.add_argument("--scope", choices=("full", "pilot"), default="full")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument(
        "--expected-stripe-display-name",
        default=os.environ.get("TINYZKP_STRIPE_EXPECTED_DISPLAY_NAME", "LN Holdings"),
        help="Required substring in the active Stripe CLI display_name",
    )
    parser.add_argument("--skip-account-check", action="store_true", help="Skip Stripe CLI display_name validation")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    return parser


def print_text(results: list[ProbeResult], *, scope: str, live: bool) -> None:
    mode = "live" if live else "configured key/profile"
    print(f"TinyZKP Stripe catalog write preflight ({scope}, {mode})")
    for result in results:
        print(f"{result.status:<4} {result.name} - {result.detail}")


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    account_result = None
    if not args.skip_account_check:
        account_result = stripe_account_context_check.run_check(
            stripe_bin=args.stripe_bin,
            stripe_project_name=args.stripe_project_name,
            expected_display_name=args.expected_stripe_display_name,
            timeout=args.timeout,
        )
        if account_result.status != "PASS":
            if args.json:
                print(json.dumps({"account_context": asdict(account_result), "results": []}, indent=2))
            else:
                stripe_account_context_check.print_text(account_result)
            return 1
    results = run_preflight(
        stripe_bin=args.stripe_bin,
        live=args.live,
        scope=args.scope,
        timeout=args.timeout,
        stripe_project_name=args.stripe_project_name,
    )
    if args.json:
        payload = {"results": [asdict(result) for result in results]}
        if account_result:
            payload["account_context"] = asdict(account_result)
        print(json.dumps(payload, indent=2))
    else:
        if account_result:
            stripe_account_context_check.print_text(account_result)
        print_text(results, scope=args.scope, live=args.live)
    return 1 if any(result.status != "PASS" for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
