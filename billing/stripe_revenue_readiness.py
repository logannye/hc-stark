#!/usr/bin/env python3
"""Run the safe Stripe revenue-readiness sequence for TinyZKP."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

import stripe_account_context_check


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXPECTED_DISPLAY_NAME = "LN Holdings"
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SECRET_RE = re.compile(r"\b(?:sk|rk|pk|whsec)_(?:live|test)?_?[^\s'\"}]+")
STRIPE_ID_RE = re.compile(r"\b(?:acct|cs|cus|pi|sub|price|prod|mtr|req)_[A-Za-z0-9_*]{8,}\b")


@dataclass(frozen=True)
class ReadinessStep:
    name: str
    command: list[str]
    mutates_stripe: bool = False
    mutates_repo: bool = False


@dataclass(frozen=True)
class StepResult:
    status: str
    name: str
    detail: str
    command: list[str] | None = None


def redact(text: object) -> str:
    value = EMAIL_RE.sub("[redacted-email]", str(text))
    value = SECRET_RE.sub("[redacted-key]", value)
    return STRIPE_ID_RE.sub("[redacted-id]", value)


def build_steps(args: argparse.Namespace, *, python: str = sys.executable) -> list[ReadinessStep]:
    expected = getattr(args, "expected_stripe_display_name", DEFAULT_EXPECTED_DISPLAY_NAME)
    stripe_bin = getattr(args, "stripe_bin", "stripe")
    stripe_project_name = getattr(args, "stripe_project_name", "")
    account_source = getattr(args, "account_source", "cli")
    stripe_api_key_env = getattr(args, "stripe_api_key_env", "STRIPE_SECRET_KEY")
    lookback = str(getattr(args, "lookback_hours", 168))
    timeout = str(getattr(args, "timeout", 30))
    steps: list[ReadinessStep] = []
    if account_source == "cli":
        steps.append(ReadinessStep(
            "Stripe revenue ops audit",
            [
                python,
                "billing/stripe_revenue_ops_audit.py",
                "--stripe-bin",
                stripe_bin,
                *(["--stripe-project-name", stripe_project_name] if stripe_project_name else []),
                "--timeout",
                timeout,
                "--expected-stripe-display-name",
                expected,
            ]
            + (["--strict-catalog"] if getattr(args, "strict_catalog", False) else []),
        ))
    steps.extend([
        ReadinessStep(
            "Stripe checkout monitor",
            [
                python,
                "billing/stripe_checkout_monitor.py",
                "--stripe-bin",
                stripe_bin,
                *(["--stripe-project-name", stripe_project_name] if stripe_project_name else []),
                "--account-source",
                account_source,
                "--stripe-api-key-env",
                stripe_api_key_env,
                "--lookback-hours",
                lookback,
                "--expected-stripe-display-name",
                expected,
            ],
        ),
    ])
    if getattr(args, "sync_pipeline", False):
        steps.append(
            ReadinessStep(
                "Stripe checkout pipeline sync",
                [
                    python,
                    "scripts/marketing/sync_stripe_checkout_pipeline.py",
                    "--stripe-bin",
                    stripe_bin,
                    *(["--stripe-project-name", stripe_project_name] if stripe_project_name else []),
                    "--account-source",
                    account_source,
                    "--stripe-api-key-env",
                    stripe_api_key_env,
                    "--lookback-hours",
                    lookback,
                    "--expected-stripe-display-name",
                    expected,
                ],
                mutates_repo=True,
            )
        )

    catalog = getattr(args, "setup_catalog", "none")
    if catalog == "pilot":
        command = ["bash", "billing/setup_pilot_price.sh", "--stripe-cli", "--stripe-bin", stripe_bin]
        if stripe_project_name:
            command.extend(["--stripe-project-name", stripe_project_name])
        if getattr(args, "push_cloudflare", False):
            command.append("--push-cloudflare")
        steps.append(ReadinessStep("Stripe pilot catalog setup", command, mutates_stripe=True))
    elif catalog == "full":
        command = ["bash", "billing/setup_stripe_products.sh", "--stripe-cli", "--stripe-bin", stripe_bin]
        if stripe_project_name:
            command.extend(["--stripe-project-name", stripe_project_name])
        if getattr(args, "push_cloudflare", False):
            command.append("--push-cloudflare")
        steps.append(ReadinessStep("Stripe full catalog setup", command, mutates_stripe=True))
    return steps


def _resolve_stripe_project_name(args: argparse.Namespace) -> tuple[str, StepResult | None]:
    explicit = getattr(args, "stripe_project_name", "")
    if explicit or not getattr(args, "auto_discover_profile", False):
        return explicit, None
    result = stripe_account_context_check.discover_profile(
        expected_display_name=getattr(args, "expected_stripe_display_name", DEFAULT_EXPECTED_DISPLAY_NAME),
        config_path=getattr(args, "stripe_config_path", stripe_account_context_check.DEFAULT_CONFIG_PATH),
    )
    step = StepResult(result.status, "Stripe profile discovery", result.detail)
    if result.status == "PASS":
        return result.project_name, step
    return "", step


def _run_command(
    step: ReadinessStep,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    timeout: int = 120,
) -> StepResult:
    try:
        completed = runner(
            step.command,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except OSError as exc:
        return StepResult("FAIL", step.name, redact(exc), step.command)
    except subprocess.TimeoutExpired:
        return StepResult("FAIL", step.name, f"timed out after {timeout}s", step.command)

    output = "\n".join(part for part in (completed.stdout, completed.stderr) if part).strip()
    if completed.returncode == 0:
        detail = "completed"
        if output:
            detail = redact(output)[-600:]
        return StepResult("PASS", step.name, detail, step.command)
    detail = redact(output)[:1000] or f"command exited with {completed.returncode}"
    return StepResult("FAIL", step.name, detail, step.command)


def run_readiness(
    args: argparse.Namespace,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    account_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> list[StepResult]:
    stripe_project_name, discovery_result = _resolve_stripe_project_name(args)
    effective_args = argparse.Namespace(**vars(args))
    effective_args.stripe_project_name = stripe_project_name
    if discovery_result and discovery_result.status != "PASS":
        return [discovery_result]

    if getattr(args, "plan_only", False):
        plan = [
            StepResult(
                "PLAN",
                step.name,
                " ".join(step.command),
                step.command,
            )
            for step in build_steps(effective_args)
        ]
        return ([discovery_result] if discovery_result else []) + plan

    account = stripe_account_context_check.run_check(
        stripe_bin=getattr(args, "stripe_bin", "stripe"),
        stripe_project_name=stripe_project_name,
        account_source=getattr(args, "account_source", "cli"),
        stripe_api_key_env=getattr(args, "stripe_api_key_env", "STRIPE_SECRET_KEY"),
        expected_display_name=getattr(args, "expected_stripe_display_name", DEFAULT_EXPECTED_DISPLAY_NAME),
        timeout=getattr(args, "timeout", 30),
        runner=account_runner,
    )
    results = ([discovery_result] if discovery_result else []) + [StepResult(account.status, "Stripe account context", account.detail)]
    if account.status != "PASS":
        return results

    for step in build_steps(effective_args):
        result = _run_command(step, runner=runner, timeout=getattr(args, "command_timeout", 120))
        results.append(result)
        if result.status != "PASS":
            break
    return results


def print_text(results: list[StepResult]) -> None:
    print("TinyZKP Stripe revenue readiness")
    for result in results:
        print(f"{result.status:<4} {result.name} - {result.detail}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stripe-bin", default="stripe", help="Stripe CLI executable path")
    parser.add_argument("--stripe-project-name", default="", help="Optional Stripe CLI project profile name")
    parser.add_argument(
        "--account-source",
        choices=("cli", "api"),
        default=os.environ.get("TINYZKP_STRIPE_ACCOUNT_SOURCE", "cli"),
        help="Account validation and checkout query source",
    )
    parser.add_argument(
        "--stripe-api-key-env",
        default=os.environ.get("TINYZKP_STRIPE_API_KEY_ENV", "STRIPE_SECRET_KEY"),
        help="Environment variable containing the Stripe secret key for --account-source api",
    )
    parser.add_argument("--auto-discover-profile", action="store_true", help="Find a local Stripe CLI profile whose display_name matches --expected-stripe-display-name")
    parser.add_argument(
        "--stripe-config-path",
        type=Path,
        default=stripe_account_context_check.DEFAULT_CONFIG_PATH,
        help="Stripe CLI config path used by --auto-discover-profile",
    )
    parser.add_argument(
        "--expected-stripe-display-name",
        default=os.environ.get("TINYZKP_STRIPE_EXPECTED_DISPLAY_NAME", DEFAULT_EXPECTED_DISPLAY_NAME),
        help="Required substring in the active Stripe CLI display_name",
    )
    parser.add_argument("--lookback-hours", type=float, default=168, help="Trailing checkout monitor window")
    parser.add_argument("--timeout", type=int, default=30, help="Account-context and audit timeout in seconds")
    parser.add_argument("--command-timeout", type=int, default=120, help="Per-step subprocess timeout in seconds")
    parser.add_argument("--strict-catalog", action="store_true", help="Pass --strict-catalog to the read-only revenue audit")
    parser.add_argument("--sync-pipeline", action="store_true", help="Sync aggregate Stripe checkout evidence into the no-PII GTM pipeline")
    parser.add_argument(
        "--setup-catalog",
        choices=("none", "pilot", "full"),
        default="none",
        help="Optionally run Stripe catalog setup after read-only checks pass",
    )
    parser.add_argument("--push-cloudflare", action="store_true", help="Pass --push-cloudflare to catalog setup scripts")
    parser.add_argument("--plan-only", action="store_true", help="Print the planned steps without touching Stripe or local ledgers")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    return parser


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    results = run_readiness(args)
    if args.json:
        print(json.dumps({"ok": all(result.status in {"PASS", "PLAN"} for result in results), "results": [asdict(result) for result in results]}, indent=2))
    else:
        print_text(results)
    return 0 if all(result.status in {"PASS", "PLAN"} for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
