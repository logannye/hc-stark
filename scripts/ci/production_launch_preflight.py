#!/usr/bin/env python3
"""Aggregate the fast gates required for a TinyZKP reconciliation launch.

The individual checks stay as the source of truth. This script gives operators
one deterministic command for local/CI preflight, plus opt-in live canaries for
the post-deploy announcement gate.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field


ROOT = pathlib.Path(__file__).resolve().parents[2]


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


def build_steps(args: argparse.Namespace, *, python: str = "python3", node: str = "node") -> list[Step]:
    launch_cmd = [python, "scripts/ci/launch_gate_audit.py"]
    if args.require_legacy:
        launch_cmd.append("--require-legacy")

    deploy_readiness_cmd = [
        python,
        "scripts/ci/deploy_readiness_check.py",
        "--env-file",
        args.env_file,
    ]
    if args.production:
        deploy_readiness_cmd.append("--production")
    if args.check_host_python:
        deploy_readiness_cmd.append("--check-host-python")
    if args.host_python:
        deploy_readiness_cmd.extend(["--host-python", args.host_python])

    steps = [
        Step("local reconciliation invariants", ("bash", "./scripts/ci/reconciliation_invariants.sh")),
        Step("launch gate audit", tuple(launch_cmd)),
        Step("backup/restore drift check", (python, "scripts/ci/backup_restore_check.py")),
        Step("static site route check", (python, "scripts/ci/site_route_check.py")),
        Step("static site route policy tests", (python, "-m", "pytest", "scripts/ci/test_site_route_check.py")),
        Step("analytics attribution handoff test", (node, "scripts/ci/test_analytics_attribution.mjs")),
        Step("release identity policy tests", (python, "-m", "pytest", "scripts/ci/test_release_identity_check.py")),
        Step("agent-readable offer metadata check", (python, "scripts/ci/offer_metadata_check.py")),
        Step("receipt-share contract check", (python, "scripts/ci/receipt_share_contract_check.py")),
        Step("receipt-share contract policy tests", (python, "-m", "pytest", "scripts/ci/test_receipt_share_contract_check.py")),
        Step("badge embed contract check", (python, "scripts/ci/badge_embed_check.py")),
        Step("badge embed contract policy tests", (python, "-m", "pytest", "scripts/ci/test_badge_embed_check.py")),
        Step("OpenAI ChatGPT app prototype check", (python, "scripts/ci/openai_chatgpt_app_check.py")),
        Step("OpenAI ChatGPT app policy tests", (python, "-m", "pytest", "scripts/ci/test_openai_chatgpt_app_check.py")),
        Step("GTM distribution target check", (python, "scripts/monitoring/gtm_distribution_monitor.py", "--offline")),
        Step("GTM distribution policy tests", (python, "-m", "pytest", "scripts/ci/test_gtm_distribution_monitor.py")),
        Step("GTM growth monitor", (python, "scripts/monitoring/gtm_growth_monitor.py", "--offline")),
        Step("GTM growth monitor policy tests", (python, "-m", "pytest", "scripts/ci/test_gtm_growth_monitor.py")),
        Step("GTM execution ledger freshness check", (python, "scripts/marketing/render_gtm_execution_ledger.py", "--check")),
        Step("GTM execution ledger check", (python, "scripts/ci/gtm_execution_ledger_check.py")),
        Step(
            "GTM execution ledger policy tests",
            (python, "-m", "pytest", "scripts/ci/test_gtm_execution_ledger.py"),
        ),
        Step("GTM pipeline ledger freshness check", (python, "scripts/marketing/render_gtm_pipeline_ledger.py", "--check")),
        Step("GTM pipeline ledger check", (python, "scripts/ci/gtm_pipeline_ledger_check.py")),
        Step(
            "GTM pipeline ledger policy tests",
            (python, "-m", "pytest", "scripts/ci/test_gtm_pipeline_ledger.py"),
        ),
        Step("manual distribution asset check", (python, "scripts/ci/manual_distribution_assets_check.py")),
        Step(
            "manual distribution asset policy tests",
            (python, "-m", "pytest", "scripts/ci/test_manual_distribution_assets_check.py"),
        ),
        Step("founder outbound target catalog check", (python, "scripts/ci/outbound_targets_check.py")),
        Step(
            "founder outbound target policy tests",
            (python, "-m", "pytest", "scripts/ci/test_outbound_target_pipeline.py"),
        ),
        Step("founder outbound send queue freshness check", (python, "scripts/marketing/render_outbound_send_queue.py", "--check")),
        Step("founder outbound send queue check", (python, "scripts/ci/outbound_send_queue_check.py")),
        Step(
            "founder outbound send queue policy tests",
            (python, "-m", "pytest", "scripts/ci/test_outbound_send_queue.py"),
        ),
        Step("founder outbound research packets freshness check", (python, "scripts/marketing/enrich_outbound_research.py", "--check")),
        Step("founder outbound research packet check", (python, "scripts/ci/outbound_research_packets_check.py")),
        Step("founder outbound research pipeline sync check", (python, "scripts/marketing/sync_outbound_research_pipeline.py", "--check")),
        Step(
            "founder outbound research packet policy tests",
            (python, "-m", "pytest", "scripts/ci/test_outbound_research_packets.py"),
        ),
        Step("MCP submission drafts freshness check", (python, "scripts/marketing/render_mcp_submissions.py", "--check")),
        Step("MCP submission renderer tests", (python, "-m", "pytest", "scripts/ci/test_mcp_submission_renderer.py")),
        Step("Cursor plugin package check", (python, "scripts/ci/cursor_plugin_check.py")),
        Step("Cursor plugin package tests", (python, "-m", "pytest", "scripts/ci/test_cursor_plugin_check.py")),
        Step("IndexNow submission dry-run", (python, "scripts/marketing/indexnow_submit.py")),
        Step("package distribution surface check", (python, "scripts/ci/package_distribution_check.py")),
        Step("package distribution policy tests", (python, "-m", "pytest", "scripts/ci/test_package_distribution_check.py")),
        Step("SEO conversion surface check", (python, "scripts/ci/seo_conversion_check.py")),
        Step("SEO conversion policy tests", (python, "-m", "pytest", "scripts/ci/test_seo_conversion_check.py")),
        Step("GTM revenue report tests", (python, "-m", "pytest", "billing/tests/test_gtm_revenue_report.py")),
        Step("Stripe account context tests", (python, "-m", "pytest", "billing/tests/test_stripe_account_context_check.py")),
        Step("Stripe revenue readiness tests", (python, "-m", "pytest", "billing/tests/test_stripe_revenue_readiness.py")),
        Step("Stripe checkout monitor tests", (python, "-m", "pytest", "billing/tests/test_stripe_checkout_monitor.py")),
        Step("Stripe checkout canary policy tests", (python, "-m", "pytest", "scripts/ci/test_stripe_checkout_canary.py")),
        Step("Stripe revenue ops audit tests", (python, "-m", "pytest", "billing/tests/test_stripe_revenue_ops_audit.py")),
        Step("Stripe catalog write preflight tests", (python, "-m", "pytest", "billing/tests/test_stripe_catalog_write_preflight.py")),
        Step("Stripe checkout pipeline sync tests", (python, "-m", "pytest", "scripts/ci/test_stripe_checkout_pipeline_sync.py")),
        Step("MCP server-card check", (python, "scripts/ci/server_card_check.py")),
        Step("MCP server-card policy tests", (python, "-m", "pytest", "scripts/ci/test_server_card_check.py")),
        Step("Cloudflare Pages static deploy check", (python, "scripts/ci/site_deploy_check.py")),
        Step("Cloudflare Pages worker dispatch check", (node, "scripts/ci/site_worker_dispatch_test.mjs")),
        Step("Docker Compose render check", (python, "scripts/ci/compose_config_check.py")),
        Step("deploy readiness check", tuple(deploy_readiness_cmd)),
    ]

    if args.production:
        steps.append(
            Step(
                "Cloudflare Pages production binding check",
                (
                    python,
                    "scripts/ci/site_deploy_check.py",
                    "--production",
                    "--bindings-file",
                    args.pages_bindings_file,
                ),
            )
        )

    if args.live:
        steps.extend(
            [
                Step(
                    "Cloudflare Pages live secret inventory check",
                    (python, "scripts/ci/cloudflare_pages_secret_check.py"),
                    timeout_secs=60,
                ),
                Step(
                    "live reconciliation canary",
                    ("bash", "./scripts/ci/reconciliation_invariants.sh", "--live"),
                    timeout_secs=180,
                ),
                Step(
                    "live public smoke",
                    ("bash", "scripts/monitoring/shared_dispatch_smoke.sh"),
                    env={"TINYZKP_SMOKE_PUBLIC_ONLY": "1"},
                    timeout_secs=180,
                ),
            ]
        )
        expected_release_sha = (args.expected_release_sha or os.environ.get("TINYZKP_EXPECT_RELEASE_SHA", "")).strip()
        if expected_release_sha:
            steps.append(
                Step(
                    "live release identity check",
                    (
                        python,
                        "scripts/ci/release_identity_check.py",
                        "--expected-sha",
                        expected_release_sha,
                        "--site-url",
                        args.site_url,
                        "--api-url",
                        args.api_url,
                        "--mcp-url",
                        args.mcp_url,
                    ),
                    timeout_secs=120,
                )
            )

    if args.authenticated_smoke:
        steps.append(
            Step(
                "live authenticated prove/verify smoke",
                ("bash", "scripts/monitoring/shared_dispatch_smoke.sh"),
                timeout_secs=300,
            )
        )

    return steps


def _tail(text: str, limit: int = 4000) -> str:
    if len(text) <= limit:
        return text
    return text[-limit:]


def run_step(step: Step, *, root: pathlib.Path = ROOT) -> StepResult:
    env = os.environ.copy()
    env.update(step.env)
    started = time.monotonic()
    try:
        completed = subprocess.run(
            step.command,
            cwd=root,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=step.timeout_secs,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return StepResult(
            name=step.name,
            status="FAIL",
            command=step.command,
            stdout=_tail(exc.stdout or ""),
            stderr=_tail(exc.stderr or ""),
            duration_secs=time.monotonic() - started,
            error=f"timed out after {step.timeout_secs}s",
        )
    except OSError as exc:
        return StepResult(
            name=step.name,
            status="FAIL",
            command=step.command,
            duration_secs=time.monotonic() - started,
            error=str(exc),
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


def run_steps(steps: list[Step], *, root: pathlib.Path = ROOT) -> list[StepResult]:
    return [run_step(step, root=root) for step in steps]


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
        if result.status == "FAIL":
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


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-legacy", action="store_true", help="Require sibling legacy checkout evidence")
    parser.add_argument("--env-file", default=".env", help="Production env file for deploy readiness checks")
    parser.add_argument("--production", action="store_true", help="Enable production env and Pages binding checks")
    parser.add_argument("--pages-bindings-file", help="Cloudflare Pages production bindings/secrets file")
    parser.add_argument("--check-host-python", action="store_true", help="Verify host Python packages for enabled services")
    parser.add_argument("--host-python", help="Host Python interpreter used by billing services")
    parser.add_argument("--live", action="store_true", help="Run public live canaries; use after deploy")
    parser.add_argument("--site-url", default="https://tinyzkp.com", help="TinyZKP website origin for live checks")
    parser.add_argument("--api-url", default="https://api.tinyzkp.com", help="TinyZKP API origin for live checks")
    parser.add_argument("--mcp-url", default="https://mcp.tinyzkp.com", help="TinyZKP MCP origin for live checks")
    parser.add_argument(
        "--expected-release-sha",
        help="Expected Git SHA for live site/API release identity checks; defaults to TINYZKP_EXPECT_RELEASE_SHA",
    )
    parser.add_argument(
        "--authenticated-smoke",
        action="store_true",
        help="Run authenticated prove/verify smoke using TINYZKP_SMOKE_API_KEY or TINYZKP_AUDIT_API_KEY",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    args = parser.parse_args(argv)

    if args.production and not args.pages_bindings_file:
        parser.error("--production requires --pages-bindings-file")

    steps = build_steps(args, python=sys.executable)
    results = run_steps(steps)
    failures = [result for result in results if result.status != "PASS"]

    if args.json:
        print(json.dumps({"results": [result_to_json(result) for result in results]}, indent=2))
    else:
        print_text(results)
        print()
        print(f"Production launch preflight: {len(results) - len(failures)} passed, {len(failures)} failed")
        if args.live and not failures:
            print("Live canaries passed; public launch/announcement gate is clear.")
        elif not args.live:
            print("Live canaries were not run; use --live after deploy before public announcement.")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
