#!/usr/bin/env python3
"""Aggregate the launch gates for the static TinyZKP Guard business.

The production surface is Cloudflare Pages. Guard launch state, sales state,
and every public contract are derived from checked-in evidence and remain
fail-closed until the independently anchored Guard gates pass. This command is
read-only: it validates the source, the Pages release transaction, and optional
live static canaries; it does not deploy or enable checkout.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
TRUSTED_SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
DEFAULT_SITE_URL = "https://tinyzkp.com"
GUARD_STATE = Path("release/guard-launch-state-v2.json")
GUARD_AUTHORIZATION = Path("release/guard-candidate-build-authorization-v1.json")
GUARD_TRUST_ENV = (
    "TINYZKP_GUARD_TRUST_POLICY_SHA256",
    "TINYZKP_GUARD_SIGNING_TRUST_POLICY_SHA256",
    "TINYZKP_COSIGN",
)
MARKET_TRUST_ENV = ("TINYZKP_GUARD_MARKET_TRUST_POLICY_SHA256",)
CLOUDFLARE_ENV = ("CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID")
NONPRODUCTION_SECRET_PREFIXES = (
    "CLOUDFLARE_",
    "GUMROAD_",
    "LEMONSQUEEZY_",
    "LEMON_SQUEEZY_",
    "MERCHANT_",
    "PADDLE_",
    "PAYPAL_",
    "SHOPIFY_",
    "STRIPE_",
)
NONPRODUCTION_SECRET_SUFFIXES = (
    "_ACCESS_KEY",
    "_API_KEY",
    "_API_TOKEN",
    "_PASSWORD",
    "_PRIVATE_KEY",
    "_SECRET",
    "_TOKEN",
)
NONPRODUCTION_SECRET_EXACT = {
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "NODE_AUTH_TOKEN",
    "NPM_TOKEN",
    "PYPI_API_TOKEN",
    "TWINE_PASSWORD",
}


class PreflightError(ValueError):
    """A launch input or requested preflight mode is unsafe or incomplete."""


@dataclass(frozen=True)
class Step:
    name: str
    command: tuple[str, ...]
    env: dict[str, str] = field(default_factory=dict)
    timeout_secs: int = 120


@dataclass(frozen=True)
class StepResult:
    name: str
    status: str
    command: tuple[str, ...]
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    duration_secs: float = 0.0
    error: str | None = None


@dataclass(frozen=True)
class GuardMode:
    readiness_argument: str | None
    decommission_claimed: bool


def _duplicates_rejected(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PreflightError(f"duplicate JSON key in Guard launch state: {key}")
        result[key] = value
    return result


def _nonfinite_rejected(value: str) -> None:
    raise PreflightError(f"non-finite JSON number in Guard launch state: {value}")


def _strict_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_bytes(),
            object_pairs_hook=_duplicates_rejected,
            parse_constant=_nonfinite_rejected,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PreflightError(f"cannot read strict Guard launch state: {path}") from error
    if not isinstance(value, dict):
        raise PreflightError(f"Guard launch state must be an object: {path}")
    return value


def guard_mode(root: Path = ROOT) -> GuardMode:
    """Mirror the protected Pages workflow's fail-closed readiness selection."""

    launch = _strict_object(root / GUARD_STATE)
    authorization = _strict_object(root / GUARD_AUTHORIZATION)
    commerce_state = launch.get("commerce_state")
    authorization_state = authorization.get("authorization_state")
    gates = launch.get("gate_status")
    if commerce_state not in {
        "unconfigured",
        "test_published",
        "test_verified",
        "live_hidden",
        "public_live",
        "sales_frozen",
    }:
        raise PreflightError("Guard commerce state is missing or unknown")
    if authorization_state not in {
        "blocked",
        "authorized",
        "candidate_prepared",
        "published",
    }:
        raise PreflightError("Guard candidate authorization state is missing or unknown")
    if not isinstance(gates, dict) or not gates:
        raise PreflightError("Guard launch gate status is missing")
    statuses: dict[str, str] = {}
    for name, value in gates.items():
        if not isinstance(name, str) or not isinstance(value, dict):
            raise PreflightError("Guard launch gate status is malformed")
        status = value.get("status")
        if status not in {"blocked", "passed"}:
            raise PreflightError(f"Guard launch gate has an unknown status: {name}")
        statuses[name] = status

    if commerce_state == "public_live":
        readiness = "--require-ready"
    elif authorization_state == "candidate_prepared":
        readiness = "--require-promotion-ready"
    elif authorization_state == "authorized":
        readiness = "--require-candidate-build-ready"
    elif authorization_state == "published":
        readiness = "--require-current-evaluation"
    elif "passed" in statuses.values():
        readiness = "--require-current-evaluation"
    else:
        readiness = None
    return GuardMode(
        readiness_argument=readiness,
        decommission_claimed=(
            statuses.get("hosted_infrastructure_decommissioned") == "passed"
        ),
    )


def _selected_environment(names: tuple[str, ...]) -> dict[str, str]:
    return {name: os.environ[name] for name in names if os.environ.get(name)}


def build_steps(
    args: argparse.Namespace,
    *,
    python: str = "python3",
    node: str = "node",
    root: Path = ROOT,
) -> list[Step]:
    mode = guard_mode(root)
    source_trust = (
        args.source_guard_trust_sha256,
        args.source_signing_trust_sha256,
        args.source_market_trust_sha256,
    )
    if any(source_trust) and not all(source_trust):
        raise PreflightError(
            "source-derived Guard, signing, and market trust anchors must be "
            "supplied together"
        )
    if args.production and any(source_trust):
        raise PreflightError(
            "production preflight refuses source-derived trust anchors"
        )
    if args.production and not args.node_executable:
        raise PreflightError(
            "production preflight requires an explicit reviewed Node executable"
        )
    if args.production and not args.wrangler_entrypoint:
        raise PreflightError(
            "production preflight requires an explicit reviewed Wrangler entrypoint"
        )
    if args.require_decommissioned_hosts and not args.live:
        raise PreflightError(
            "retired-host verification is a live post-deploy check"
        )

    guard_command = [python, "scripts/ci/guard_launch_gate.py", "--check"]
    if mode.readiness_argument:
        guard_command.append(mode.readiness_argument)
    if args.source_guard_trust_sha256:
        guard_command.extend(
            ["--trusted-policy-sha256", args.source_guard_trust_sha256]
        )
        guard_command.extend(
            [
                "--trusted-signing-policy-sha256",
                args.source_signing_trust_sha256,
            ]
        )
    market_command = [python, "scripts/ci/guard_market_clock.py", "--check"]
    if args.source_market_trust_sha256:
        market_command.extend(
            ["--trusted-policy-sha256", args.source_market_trust_sha256]
        )
    toolchain_command: tuple[str, ...] = (
        python,
        "scripts/ci/cloudflare_toolchain_check.py",
    )
    if args.production:
        toolchain_command = (
            python,
            "scripts/ci/cloudflare_toolchain_check.py",
            "--runtime",
            "--node-executable",
            args.node_executable,
            "--wrangler-entrypoint",
            args.wrangler_entrypoint,
        )

    steps = [
        Step(
            "Guard launch state derivation",
            tuple(guard_command),
            env=_selected_environment(GUARD_TRUST_ENV),
        ),
        Step(
            "Guard market clock derivation",
            tuple(market_command),
            env=_selected_environment(MARKET_TRUST_ENV),
        ),
        Step(
            "low-maintenance operations scorecard",
            (python, "scripts/ci/passive_operations_scorecard.py", "--check"),
        ),
        Step(
            "public claim containment",
            (python, "scripts/ci/claim_containment_scan.py"),
        ),
        Step(
            "static site route check",
            (python, "scripts/ci/site_route_check.py"),
        ),
        Step(
            "Cloudflare Pages static deploy check",
            (python, "scripts/ci/site_deploy_check.py"),
        ),
        Step(
            "Community and Guard offer parity",
            (python, "scripts/commercial/render_offers.py", "--check"),
        ),
        Step(
            "Guard revenue-readiness execution source parity",
            (
                python,
                "scripts/marketing/render_gtm_execution_ledger.py",
                "--check",
            ),
        ),
        Step(
            "Guard revenue-readiness execution contracts",
            (python, "scripts/ci/gtm_execution_ledger_check.py"),
        ),
        Step(
            "Guard revenue-readiness pipeline source parity",
            (
                python,
                "scripts/marketing/render_gtm_pipeline_ledger.py",
                "--check",
            ),
        ),
        Step(
            "Guard revenue-readiness pipeline contracts",
            (python, "scripts/ci/gtm_pipeline_ledger_check.py"),
        ),
        Step(
            "Guard and static-site policy tests",
            (
                python,
                "-m",
                "pytest",
                "-q",
                "scripts/ci/test_guard_launch_gate.py",
                "scripts/ci/test_guard_market_clock.py",
                "scripts/ci/test_guard_site_contract.py",
                "scripts/ci/test_gtm_execution_ledger.py",
                "scripts/ci/test_gtm_pipeline_ledger.py",
                "scripts/ci/test_passive_operations_scorecard.py",
                "scripts/ci/test_claim_containment_scan.py",
                "scripts/ci/test_site_route_check.py",
                "scripts/ci/test_site_deploy_check.py",
                "scripts/ci/test_cloudflare_pages_secret_check.py",
                "scripts/ci/test_cloudflare_toolchain_check.py",
                "scripts/deploy/test_static_site_canary.py",
            ),
            timeout_secs=300,
        ),
        Step(
            "Cloudflare Pages release transaction adversarial tests",
            (
                python,
                "-m",
                "pytest",
                "-q",
                "scripts/deploy/test_cloudflare_pages_release.py",
            ),
            timeout_secs=300,
        ),
        Step("pinned Cloudflare production toolchain", toolchain_command),
        Step(
            "Cloudflare Pages worker syntax check",
            (node, "--check", "site/_worker.js"),
        ),
        Step(
            "Cloudflare Pages worker dispatch check",
            (node, "scripts/ci/site_worker_dispatch_test.mjs"),
        ),
        Step(
            "static checkout and billing portal browser contract",
            (node, "scripts/ci/site_shared_checkout_test.mjs"),
        ),
    ]

    if args.production:
        steps.append(
            Step(
                "Cloudflare Pages live secret inventory check",
                (
                    python,
                    "scripts/ci/cloudflare_pages_secret_check.py",
                    "--node-executable",
                    args.node_executable,
                    "--wrangler-entrypoint",
                    args.wrangler_entrypoint,
                ),
                env=_selected_environment(CLOUDFLARE_ENV),
                timeout_secs=60,
            )
        )

    if args.live:
        steps.extend(
            [
                Step(
                    "live static contract canary",
                    (
                        python,
                        "scripts/deploy/static_site_canary.py",
                        "--base-url",
                        args.site_url,
                        "--mode",
                        "contracts",
                    ),
                    timeout_secs=180,
                ),
                Step(
                    "live static route and legacy containment canary",
                    (
                        python,
                        "scripts/deploy/static_site_canary.py",
                        "--base-url",
                        args.site_url,
                        "--mode",
                        "routes",
                    ),
                    timeout_secs=180,
                ),
            ]
        )
        if mode.decommission_claimed or args.require_decommissioned_hosts:
            steps.append(
                Step(
                    "live retired-host decommission canary",
                    (
                        python,
                        "scripts/deploy/static_site_canary.py",
                        "--mode",
                        "retired-hosts",
                    ),
                    timeout_secs=180,
                )
            )
    return steps


def _tail(value: str | bytes, limit: int = 4000) -> str:
    text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
    return text if len(text) <= limit else text[-limit:]


def production_subprocess_environment(
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    environment = {
        "PATH": TRUSTED_SYSTEM_PATH,
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTEST_ADDOPTS": "-p no:cacheprovider",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "NO_COLOR": "1",
        "WRANGLER_SEND_METRICS": "false",
    }
    if extra:
        forbidden = {
            key
            for key in extra
            if key in {"PATH", "HOME", "PYTHONPATH", "PYTHONHOME", "NODE_OPTIONS"}
            or key.startswith("LD_")
            or key.startswith("DYLD_")
            or key.startswith("GIT_")
        }
        if forbidden:
            raise PreflightError(
                "production step requested forbidden environment keys: "
                + ", ".join(sorted(forbidden))
            )
        environment.update(extra)
    return environment


def _nonproduction_secret_key(name: str) -> bool:
    normalized = name.upper()
    return (
        normalized in NONPRODUCTION_SECRET_EXACT
        or normalized.startswith(NONPRODUCTION_SECRET_PREFIXES)
        or normalized.endswith(NONPRODUCTION_SECRET_SUFFIXES)
    )


def nonproduction_subprocess_environment(
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not _nonproduction_secret_key(key)
    }
    if extra:
        forbidden = sorted(key for key in extra if _nonproduction_secret_key(key))
        if forbidden:
            raise PreflightError(
                "non-production step requested credential environment keys: "
                + ", ".join(forbidden)
            )
        environment.update(extra)
    return environment


def run_step(
    step: Step, *, root: Path = ROOT, production: bool = False
) -> StepResult:
    environment = (
        production_subprocess_environment(step.env)
        if production
        else nonproduction_subprocess_environment(step.env)
    )
    started = time.monotonic()
    try:
        completed = subprocess.run(
            step.command,
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=step.timeout_secs,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        return StepResult(
            name=step.name,
            status="FAIL",
            command=step.command,
            stdout=_tail(error.stdout or ""),
            stderr=_tail(error.stderr or ""),
            duration_secs=time.monotonic() - started,
            error=f"timed out after {step.timeout_secs}s",
        )
    except OSError as error:
        return StepResult(
            name=step.name,
            status="FAIL",
            command=step.command,
            duration_secs=time.monotonic() - started,
            error=str(error),
        )
    return StepResult(
        name=step.name,
        status="PASS" if completed.returncode == 0 else "FAIL",
        command=step.command,
        stdout=_tail(completed.stdout),
        stderr=_tail(completed.stderr),
        returncode=completed.returncode,
        duration_secs=time.monotonic() - started,
    )


def run_steps(
    steps: list[Step], *, root: Path = ROOT, production: bool = False
) -> list[StepResult]:
    results: list[StepResult] = []
    for step in steps:
        result = run_step(step, root=root, production=production)
        results.append(result)
        if production and result.status != "PASS":
            break
    return results


def result_to_json(result: StepResult) -> dict[str, object]:
    return {
        "name": result.name,
        "status": result.status,
        "command": list(result.command),
        "returncode": result.returncode,
        "duration_secs": round(result.duration_secs, 3),
        "error": result.error,
        "stdout_tail": result.stdout,
        "stderr_tail": result.stderr,
    }


def print_text(results: list[StepResult]) -> None:
    for result in results:
        print(f"{result.status:<4} {result.name} ({result.duration_secs:.1f}s)")
        if result.status != "FAIL":
            continue
        print(f"     command: {shlex.join(result.command)}")
        if result.error:
            print(f"     error: {result.error}")
        if result.stdout.strip():
            print("     stdout:")
            for line in result.stdout.strip().splitlines()[-20:]:
                print(f"       {line}")
        if result.stderr.strip():
            print("     stderr:")
            for line in result.stderr.strip().splitlines()[-20:]:
                print(f"       {line}")


def _absolute_file(
    parser: argparse.ArgumentParser,
    option: str,
    value: str | None,
    *,
    executable: bool,
) -> None:
    if not value:
        parser.error(f"--production requires {option}")
    path = Path(value)
    if not path.is_absolute() or not path.is_file():
        parser.error(f"{option} must be an existing regular absolute path")
    if executable and not os.access(path, os.X_OK):
        parser.error(f"{option} must be executable")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--production",
        action="store_true",
        help="Validate the exact production Cloudflare runtime and live secret inventory",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Compare the deployed site with reviewed static contracts and routes",
    )
    parser.add_argument(
        "--site-url",
        default=DEFAULT_SITE_URL,
        help="TinyZKP Pages origin used by the live static canary",
    )
    parser.add_argument(
        "--source-guard-trust-sha256",
        help=(
            "repository-derived Guard trust digest for deterministic, "
            "non-production source validation"
        ),
    )
    parser.add_argument(
        "--source-signing-trust-sha256",
        help=(
            "repository-derived signing trust digest for deterministic, "
            "non-production source validation"
        ),
    )
    parser.add_argument(
        "--source-market-trust-sha256",
        help=(
            "repository-derived market trust digest for deterministic, "
            "non-production source validation"
        ),
    )
    parser.add_argument(
        "--node-executable",
        help="Absolute reviewed Node executable for production JavaScript gates",
    )
    parser.add_argument(
        "--wrangler-entrypoint",
        help="Absolute reviewed local Wrangler entrypoint for production checks",
    )
    parser.add_argument(
        "--require-decommissioned-hosts",
        action="store_true",
        help="Require api/mcp/webhook hosts to return the reviewed 410 retirement response",
    )
    parser.add_argument(
        "--json", action="store_true", help="Emit machine-readable JSON"
    )
    args = parser.parse_args(argv)

    if args.production:
        _absolute_file(
            parser,
            "--node-executable",
            args.node_executable,
            executable=True,
        )
        _absolute_file(
            parser,
            "--wrangler-entrypoint",
            args.wrangler_entrypoint,
            executable=False,
        )
    if args.require_decommissioned_hosts and not args.live:
        parser.error("--require-decommissioned-hosts requires --live")

    python = sys.executable
    node = args.node_executable if args.production else "node"
    try:
        steps = build_steps(args, python=python, node=node)
        results = run_steps(steps, production=args.production)
    except PreflightError as error:
        print(f"Production launch preflight: FAIL: {error}", file=sys.stderr)
        return 1
    failures = [result for result in results if result.status != "PASS"]
    if args.json:
        print(
            json.dumps(
                {
                    "status": "pass" if not failures else "fail",
                    "production": args.production,
                    "live": args.live,
                    "results": [result_to_json(result) for result in results],
                },
                indent=2,
            )
        )
    else:
        print_text(results)
        print()
        print(
            f"Guard/static production preflight: "
            f"{len(results) - len(failures)} passed, {len(failures)} failed"
        )
        if args.live and not failures:
            print("Live static contracts and containment routes match reviewed source.")
        elif not args.live:
            print("Live static canaries were not run; add --live after deployment.")
        print("This command never authorizes Guard sales or mutates checkout state.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
