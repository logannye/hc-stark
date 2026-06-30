#!/usr/bin/env python3
"""Aggregate TinyZKP GTM health, revenue, and distribution signals.

Default mode is offline and CI-safe: it validates checked-in acquisition
surfaces and summarizes local tenant/usage stores when present. Use --live for
non-mutating public smoke checks after deploy, and --strict-revenue for
production alerts that should fail when activation or paid-customer thresholds
are not met.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sqlite3
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[2]
BILLING_DIR = ROOT / "billing"
if str(BILLING_DIR) not in sys.path:
    sys.path.insert(0, str(BILLING_DIR))

REGISTRY_TARGETS = (
    ("PyPI Python SDK", "https://pypi.org/pypi/tinyzkp/json"),
    ("npm TypeScript SDK", "https://registry.npmjs.org/tinyzkp"),
    ("npm CLI", "https://registry.npmjs.org/@tinyzkp%2fcli"),
    ("npm WASM verifier", "https://registry.npmjs.org/@tinyzkp%2fverify"),
    ("crates Rust SDK", "https://crates.io/api/v1/crates/tinyzkp"),
)


@dataclass(frozen=True)
class Check:
    status: str
    category: str
    name: str
    detail: str = ""


@dataclass(frozen=True)
class RevenueSummary:
    tenant_db_exists: bool
    usage_db_exists: bool
    accounts: int = 0
    active_accounts: int = 0
    monthly_active_accounts: int = 0
    activated_accounts: int = 0
    paid_accounts: int = 0
    free_accounts: int = 0
    total_proofs: int = 0
    monthly_proofs: int = 0
    paid_proofs: int = 0
    compute_trace_steps: int = 0
    estimated_base_mrr: int = 0
    estimated_usage_revenue_cents: int = 0
    avg_time_to_first_proof_hours: float = 0.0
    lifecycle_emails: int = 0
    checkout_recoveries: int = 0
    top_sources: list[dict[str, Any]] = field(default_factory=list)

    @property
    def activation_rate(self) -> float:
        return self.activated_accounts / self.accounts if self.accounts else 0.0

    @property
    def paid_rate(self) -> float:
        return self.paid_accounts / self.accounts if self.accounts else 0.0

    @property
    def estimated_usage_revenue(self) -> float:
        return self.estimated_usage_revenue_cents / 100


@dataclass(frozen=True)
class MonitorResult:
    checks: list[Check]
    revenue: RevenueSummary
    stripe_checkout: dict[str, Any] | None = None


def _load_module(name: str, rel_path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _normalize_checks(category: str, raw_checks: list[Any]) -> list[Check]:
    checks: list[Check] = []
    for raw in raw_checks:
        checks.append(
            Check(
                status=str(getattr(raw, "status", "FAIL")),
                category=category,
                name=str(getattr(raw, "name", category)),
                detail=str(getattr(raw, "detail", "")),
            )
        )
    return checks


def run_policy_checks(*, offline: bool, timeout: float) -> list[Check]:
    checks: list[Check] = []

    offer_check = _load_module("offer_metadata_check_for_growth", "scripts/ci/offer_metadata_check.py")
    offer_failures = offer_check.validate()
    if offer_failures:
        checks.extend(Check("FAIL", "agent offers", "offer metadata", failure) for failure in offer_failures)
    else:
        checks.append(Check("PASS", "agent offers", "offer metadata", "agent-readable paid offers are valid"))

    receipt_check = _load_module("receipt_share_contract_check_for_growth", "scripts/ci/receipt_share_contract_check.py")
    checks.extend(_normalize_checks("receipt sharing", receipt_check.validate(ROOT)))

    badge_check = _load_module("badge_embed_check_for_growth", "scripts/ci/badge_embed_check.py")
    checks.extend(_normalize_checks("badge embeds", badge_check.validate(ROOT)))

    openai_check = _load_module("openai_chatgpt_app_check_for_growth", "scripts/ci/openai_chatgpt_app_check.py")
    checks.extend(_normalize_checks("ChatGPT app", openai_check.validate(ROOT)))

    distribution = _load_module("gtm_distribution_monitor_for_growth", "scripts/monitoring/gtm_distribution_monitor.py")
    config = distribution.load_config(distribution.DEFAULT_TARGETS)
    checks.extend(_normalize_checks("MCP distribution", distribution.validate_config(config)))
    if not offline and all(check.status == "PASS" for check in checks if check.category == "MCP distribution"):
        checks.extend(_normalize_checks("MCP distribution", distribution.run_online_checks(config, timeout=timeout)))

    manual_check = _load_module("manual_distribution_assets_check_for_growth", "scripts/ci/manual_distribution_assets_check.py")
    checks.extend(_normalize_checks("manual launch assets", manual_check.validate(ROOT)))

    package_check = _load_module("package_distribution_check_for_growth", "scripts/ci/package_distribution_check.py")
    checks.extend(_normalize_checks("package registries", package_check.validate(ROOT)))

    seo_check = _load_module("seo_conversion_check_for_growth", "scripts/ci/seo_conversion_check.py")
    checks.extend(_normalize_checks("SEO conversion", seo_check.validate(ROOT)))

    renderer = _load_module("render_mcp_submissions_for_growth", "scripts/marketing/render_mcp_submissions.py")
    outputs = renderer.render_all(renderer.load_config(renderer.DEFAULT_TARGETS))
    submission_failures = renderer.check_outputs(outputs, renderer.DEFAULT_OUT_DIR)
    if submission_failures:
        checks.extend(Check("FAIL", "MCP submissions", "generated submission drafts", failure) for failure in submission_failures)
    else:
        checks.append(Check("PASS", "MCP submissions", "generated submission drafts", "MCP submission drafts are current"))

    return checks


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def _count_table(path: Path, table_name: str) -> int:
    if not path.exists():
        return 0
    conn = sqlite3.connect(path)
    try:
        if not _table_exists(conn, table_name):
            return 0
        row = conn.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()
        return int(row[0] or 0)
    finally:
        conn.close()


def load_revenue_summary(tenant_db: Path, usage_db: Path) -> RevenueSummary:
    revenue_report = _load_module("gtm_revenue_report_for_growth", "billing/gtm_revenue_report.py")
    tenants = revenue_report.load_tenants(str(tenant_db))
    usage = revenue_report.load_usage_by_tenant(str(usage_db))
    groups = revenue_report.summarize(tenants, usage)

    top_sources = [
        {
            "source": group.source,
            "medium": group.medium,
            "platform": group.platform,
            "accounts": group.accounts,
            "activated_accounts": group.activated_accounts,
            "monthly_active_accounts": group.monthly_active_accounts,
            "paid_accounts": group.paid_accounts,
            "paid_proofs": group.paid_proofs,
            "total_proofs": group.total_proofs,
            "estimated_base_mrr": group.estimated_base_mrr,
            "estimated_usage_revenue_cents": group.estimated_usage_revenue_cents,
            "compute_trace_steps": group.compute_trace_steps,
            "avg_time_to_first_proof_hours": round(group.avg_time_to_first_proof_hours, 4),
            "activation_rate": round(group.activation_rate, 4),
            "paid_rate": round(group.paid_rate, 4),
        }
        for group in groups[:10]
    ]
    first_proof_accounts = sum(group.first_proof_accounts for group in groups)
    time_to_first_proof_sum_ms = sum(group.time_to_first_proof_sum_ms for group in groups)

    return RevenueSummary(
        tenant_db_exists=tenant_db.exists(),
        usage_db_exists=usage_db.exists(),
        accounts=sum(group.accounts for group in groups),
        active_accounts=sum(group.active_accounts for group in groups),
        monthly_active_accounts=sum(group.monthly_active_accounts for group in groups),
        activated_accounts=sum(group.activated_accounts for group in groups),
        paid_accounts=sum(group.paid_accounts for group in groups),
        free_accounts=sum(group.free_accounts for group in groups),
        total_proofs=sum(group.total_proofs for group in groups),
        monthly_proofs=sum(group.monthly_proofs for group in groups),
        paid_proofs=sum(group.paid_proofs for group in groups),
        compute_trace_steps=sum(group.compute_trace_steps for group in groups),
        estimated_base_mrr=sum(group.estimated_base_mrr for group in groups),
        estimated_usage_revenue_cents=sum(group.estimated_usage_revenue_cents for group in groups),
        avg_time_to_first_proof_hours=(
            time_to_first_proof_sum_ms / first_proof_accounts / (60 * 60 * 1000)
            if first_proof_accounts else 0.0
        ),
        lifecycle_emails=_count_table(tenant_db, "lifecycle_emails"),
        checkout_recoveries=_count_table(tenant_db, "checkout_recovery_emails"),
        top_sources=top_sources,
    )


def revenue_checks(
    revenue: RevenueSummary,
    *,
    strict_revenue: bool,
    min_activated_accounts: int | None,
    min_paid_accounts: int | None,
    min_paid_proofs: int | None,
    min_total_proofs: int | None,
) -> list[Check]:
    checks: list[Check] = []
    if not revenue.tenant_db_exists:
        status = "FAIL" if strict_revenue else "WARN"
        checks.append(Check(status, "revenue", "tenant store", "tenant database is missing; attribution summary is unavailable"))
    else:
        checks.append(Check("PASS", "revenue", "tenant store", f"{revenue.accounts} account(s) loaded"))

    if not revenue.usage_db_exists:
        status = "FAIL" if strict_revenue else "WARN"
        checks.append(Check(status, "revenue", "usage store", "usage database is missing; proof activation summary is unavailable"))
    else:
        checks.append(Check("PASS", "revenue", "usage store", f"{revenue.total_proofs} total proof(s), {revenue.monthly_proofs} in 30d"))

    activated_floor = min_activated_accounts
    paid_floor = min_paid_accounts
    proofs_floor = min_total_proofs
    if strict_revenue:
        activated_floor = 1 if activated_floor is None else activated_floor
        paid_floor = 1 if paid_floor is None else paid_floor
        min_paid_proofs = 1 if min_paid_proofs is None else min_paid_proofs
        proofs_floor = 1 if proofs_floor is None else proofs_floor

    threshold_checks = [
        ("activated accounts", revenue.activated_accounts, activated_floor),
        ("paid accounts", revenue.paid_accounts, paid_floor),
        ("paid proofs", revenue.paid_proofs, min_paid_proofs),
        ("total proofs", revenue.total_proofs, proofs_floor),
    ]
    for name, actual, floor in threshold_checks:
        if floor is None:
            continue
        if actual < floor:
            checks.append(Check("FAIL", "revenue", name, f"{actual} observed, minimum is {floor}"))
        else:
            checks.append(Check("PASS", "revenue", name, f"{actual} observed, minimum is {floor}"))

    if revenue.tenant_db_exists and revenue.accounts == 0:
        checks.append(Check("WARN", "revenue", "account volume", "tenant store has no accounts yet"))
    if revenue.tenant_db_exists and revenue.accounts and revenue.activated_accounts == 0:
        checks.append(Check("WARN", "revenue", "activation", "accounts exist but none have completed a proof"))
    if revenue.tenant_db_exists and revenue.accounts and revenue.paid_accounts == 0:
        checks.append(Check("WARN", "revenue", "paid conversion", "accounts exist but no paid-plan tenants are recorded"))

    checks.append(
        Check(
            "PASS",
            "revenue",
            "lifecycle ledgers",
            f"{revenue.lifecycle_emails} lifecycle nudge(s), {revenue.checkout_recoveries} checkout recoveries recorded",
        )
    )
    return checks


def stripe_checkout_checks(
    args: argparse.Namespace,
    collector_fn: Any | None = None,
) -> tuple[list[Check], dict[str, Any] | None]:
    if collector_fn is None:
        checkout_monitor = _load_module("stripe_checkout_monitor_for_growth", "billing/stripe_checkout_monitor.py")
        collector_fn = checkout_monitor.collect_checkout_summary
        summary_to_dict = checkout_monitor.summary_to_dict
    else:
        summary_to_dict = lambda summary: summary

    try:
        summary = collector_fn(
            stripe_bin=getattr(args, "stripe_bin", "stripe"),
            stripe_project_name=getattr(args, "stripe_project_name", ""),
            live=not getattr(args, "stripe_checkout_test_mode", False),
            limit=getattr(args, "stripe_checkout_limit", 100),
            max_pages=getattr(args, "stripe_checkout_max_pages", 3),
            lookback_hours=getattr(args, "stripe_checkout_lookback_hours", 168),
            include_monitoring=getattr(args, "stripe_checkout_include_monitoring_sessions", False),
            expected_display_name=getattr(args, "stripe_expected_display_name", "LN Holdings"),
            skip_account_check=getattr(args, "stripe_skip_account_check", False),
            timeout=getattr(args, "stripe_account_check_timeout", 30),
            account_source=getattr(args, "stripe_account_source", "cli"),
            stripe_api_key_env=getattr(args, "stripe_api_key_env", "STRIPE_SECRET_KEY"),
        )
        payload = summary_to_dict(summary)
    except Exception as exc:
        return [
            Check(
                "FAIL",
                "Stripe checkout",
                "live checkout query",
                f"Stripe checkout monitor failed: {exc}",
            )
        ], None

    sessions = int(payload.get("sessions", 0) or 0)
    paid = int(payload.get("paid", 0) or 0)
    pilot_paid = int(payload.get("production_pilot_paid", 0) or 0)
    pilot_starts = int(payload.get("production_pilot_starts", 0) or 0)
    paid_amount = payload.get("paid_amount_by_currency", {}) or {}
    paid_amount_detail = ", ".join(
        f"{currency.upper()} {int(cents) / 100:.2f}"
        for currency, cents in sorted(paid_amount.items())
    ) or "no paid revenue observed"

    checks = [
        Check(
            "PASS",
            "Stripe checkout",
            "live checkout query",
            f"{sessions} session(s), {paid} paid, paid revenue: {paid_amount_detail}",
        )
    ]
    if sessions == 0:
        checks.append(Check("WARN", "Stripe checkout", "checkout starts", "no Checkout Sessions observed in the selected lookback"))
    checks.append(
        Check(
            "PASS" if pilot_starts else "WARN",
            "Stripe checkout",
            "Production Pilot starts",
            f"{pilot_starts} Production Pilot checkout start(s) observed",
        )
    )

    min_paid = getattr(args, "stripe_checkout_min_paid_sessions", None)
    if min_paid is not None:
        checks.append(
            Check(
                "PASS" if paid >= min_paid else "FAIL",
                "Stripe checkout",
                "paid checkout threshold",
                f"{paid} paid session(s) observed, minimum is {min_paid}",
            )
        )
    min_pilot_paid = getattr(args, "stripe_checkout_min_pilot_paid_sessions", None)
    if min_pilot_paid is not None:
        checks.append(
            Check(
                "PASS" if pilot_paid >= min_pilot_paid else "FAIL",
                "Stripe checkout",
                "paid Production Pilot threshold",
                f"{pilot_paid} paid Production Pilot session(s) observed, minimum is {min_pilot_paid}",
            )
        )
    return checks, payload


def fetch_status(url: str, *, method: str = "GET", body: bytes | None = None, timeout: float) -> tuple[int | None, str | None]:
    headers = {"User-Agent": "TinyZKP-GTM-Growth-Monitor/1.0"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = Request(url, data=body, method=method, headers=headers)
    try:
        with urlopen(request, timeout=timeout) as response:
            return int(getattr(response, "status", 200)), None
    except HTTPError as exc:
        return exc.code, str(exc)
    except (URLError, OSError) as exc:
        return None, str(exc)


def live_checks(site_url: str, api_url: str, mcp_url: str, *, timeout: float) -> list[Check]:
    checks: list[Check] = []
    get_targets = [
        ("site home", site_url, 200),
        ("playground", urljoin(site_url, "/try"), 200),
        ("verifier", urljoin(site_url, "/verify"), 200),
        ("signup", urljoin(site_url, "/signup"), 200),
        ("agent offers", urljoin(site_url, "/.well-known/tinyzkp-offers.json"), 200),
        ("receipt-share contract", urljoin(site_url, "/.well-known/tinyzkp-receipt-share.json"), 200),
        ("API health", urljoin(api_url, "/healthz"), 200),
        ("MCP version", urljoin(mcp_url, "/version"), 200),
    ]
    for name, url, expected in get_targets:
        status, error = fetch_status(url, timeout=timeout)
        if status == expected:
            checks.append(Check("PASS", "live public funnel", name, f"{url} returned {status}"))
        else:
            checks.append(Check("FAIL", "live public funnel", name, f"{url} returned {status or 'network error'} ({error or 'no detail'})"))

    post_targets = [
        ("signup endpoint", urljoin(site_url, "/api/create-free-account"), {400, 429}),
        ("checkout endpoint", urljoin(site_url, "/api/create-checkout"), {400, 429}),
        ("pilot checkout endpoint", urljoin(site_url, "/api/create-pilot-checkout"), {400, 429}),
    ]
    for name, url, expected_statuses in post_targets:
        status, error = fetch_status(url, method="POST", body=b"{}", timeout=timeout)
        if status in expected_statuses:
            detail = (
                f"{url} rate-limited repeated invalid probes with {status}"
                if status == 429
                else f"{url} rejected invalid email with {status}"
            )
            checks.append(Check("PASS", "live public funnel", name, detail))
        else:
            expected = "/".join(str(code) for code in sorted(expected_statuses))
            checks.append(Check("FAIL", "live public funnel", name, f"{url} returned {status or 'network error'}; expected {expected} ({error or 'no detail'})"))
    checks.extend(registry_live_checks(timeout=timeout))
    return checks


def registry_live_checks(*, timeout: float) -> list[Check]:
    checks: list[Check] = []
    for name, url in REGISTRY_TARGETS:
        status, error = fetch_status(url, timeout=timeout)
        if status == 200:
            checks.append(Check("PASS", "package registry live", name, f"{url} returned 200"))
        else:
            checks.append(Check("FAIL", "package registry live", name, f"{url} returned {status or 'network error'} ({error or 'no detail'})"))
    return checks


def run_monitor(args: argparse.Namespace) -> MonitorResult:
    checks = run_policy_checks(offline=args.offline, timeout=args.timeout)
    revenue = load_revenue_summary(Path(args.tenant_db), Path(args.usage_db))
    checks.extend(
        revenue_checks(
            revenue,
            strict_revenue=args.strict_revenue,
            min_activated_accounts=args.min_activated_accounts,
            min_paid_accounts=args.min_paid_accounts,
            min_paid_proofs=args.min_paid_proofs,
            min_total_proofs=args.min_total_proofs,
        )
    )
    if args.live:
        checks.extend(live_checks(args.site_url, args.api_url, args.mcp_url, timeout=args.timeout))
    stripe_checkout = None
    if getattr(args, "stripe_checkout", False):
        stripe_checks, stripe_checkout = stripe_checkout_checks(args)
        checks.extend(stripe_checks)
    return MonitorResult(checks=checks, revenue=revenue, stripe_checkout=stripe_checkout)


def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def _print_text(result: MonitorResult) -> None:
    generated = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    print(f"TinyZKP GTM growth monitor - {generated}")
    for check in result.checks:
        suffix = f" - {check.detail}" if check.detail else ""
        print(f"{check.status:<4} {check.category}: {check.name}{suffix}")

    revenue = result.revenue
    print()
    print(
        "Revenue summary: "
        f"accounts={revenue.accounts}, active={revenue.active_accounts}, "
        f"active_30d={revenue.monthly_active_accounts}, "
        f"activated={revenue.activated_accounts} ({_pct(revenue.activation_rate)}), "
        f"paid={revenue.paid_accounts} ({_pct(revenue.paid_rate)}), "
        f"proofs={revenue.total_proofs}, 30d_proofs={revenue.monthly_proofs}, "
        f"paid_proofs={revenue.paid_proofs}, base_mrr=${revenue.estimated_base_mrr}, "
        f"usage_revenue=${revenue.estimated_usage_revenue:.2f}, "
        f"compute_steps={revenue.compute_trace_steps}, "
        f"avg_first_proof={revenue.avg_time_to_first_proof_hours:.2f}h"
    )
    if revenue.top_sources:
        print("Top sources:")
        for source in revenue.top_sources[:5]:
            print(
                "  - "
                f"{source['source']} / {source['medium']} / {source['platform']}: "
                f"accounts={source['accounts']}, activated={source['activated_accounts']}, "
                f"active_30d={source['monthly_active_accounts']}, "
                f"paid={source['paid_accounts']}, paid_proofs={source['paid_proofs']}, "
                f"proofs={source['total_proofs']}, base_mrr=${source['estimated_base_mrr']}, "
                f"usage_revenue=${source['estimated_usage_revenue_cents'] / 100:.2f}"
            )
    else:
        print("Top sources: none yet")

    if result.stripe_checkout:
        checkout = result.stripe_checkout
        paid_amount = checkout.get("paid_amount_by_currency", {}) or {}
        paid_amount_detail = ", ".join(
            f"{currency.upper()} {int(cents) / 100:.2f}"
            for currency, cents in sorted(paid_amount.items())
        ) or "no paid revenue observed"
        print(
            "Stripe checkout summary: "
            f"sessions={checkout.get('sessions', 0)}, "
            f"open={checkout.get('open', 0)}, complete={checkout.get('complete', 0)}, "
            f"paid={checkout.get('paid', 0)}, "
            f"pilot_starts={checkout.get('production_pilot_starts', 0)}, "
            f"pilot_paid={checkout.get('production_pilot_paid', 0)}, "
            f"paid_revenue={paid_amount_detail}"
        )

    failures = [check for check in result.checks if check.status == "FAIL"]
    warnings = [check for check in result.checks if check.status == "WARN"]
    passes = [check for check in result.checks if check.status == "PASS"]
    print()
    print(f"GTM growth monitor: {len(passes)} passed, {len(warnings)} warned, {len(failures)} failed")
    if failures:
        labels = sorted({check.category for check in failures})
        print("Action labels: " + ", ".join(labels))


def _json_result(result: MonitorResult) -> dict[str, Any]:
    failures = [check for check in result.checks if check.status == "FAIL"]
    warnings = [check for check in result.checks if check.status == "WARN"]
    return {
        "ok": not failures,
        "generated_at_ms": int(time.time() * 1000),
        "summary": {
            "passed": sum(1 for check in result.checks if check.status == "PASS"),
            "warned": len(warnings),
            "failed": len(failures),
        },
        "checks": [asdict(check) for check in result.checks],
        "revenue": {
            **asdict(result.revenue),
            "activation_rate": round(result.revenue.activation_rate, 4),
            "paid_rate": round(result.revenue.paid_rate, 4),
            "estimated_usage_revenue": round(result.revenue.estimated_usage_revenue, 2),
        },
        "stripe_checkout": result.stripe_checkout,
        "action_labels": sorted({check.category for check in failures}),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true", help="Skip network checks; suitable for CI and local development")
    parser.add_argument("--live", action="store_true", help="Run non-mutating public funnel checks against live origins")
    parser.add_argument("--timeout", type=float, default=15.0, help="HTTP timeout for online checks")
    parser.add_argument("--tenant-db", default="/opt/hc-stark/data/tenant_store.sqlite", help="Path to tenant_store.sqlite")
    parser.add_argument("--usage-db", default="/opt/hc-stark/data/usage.sqlite", help="Path to usage.sqlite")
    parser.add_argument("--strict-revenue", action="store_true", help="Fail when revenue stores or default activation/paid/proof floors are missing")
    parser.add_argument("--min-activated-accounts", type=int, help="Fail unless at least this many accounts have completed proofs")
    parser.add_argument("--min-paid-accounts", type=int, help="Fail unless at least this many paid-plan accounts exist")
    parser.add_argument("--min-paid-proofs", type=int, help="Fail unless at least this many paid-plan proofs have completed")
    parser.add_argument("--min-total-proofs", type=int, help="Fail unless at least this many proofs have completed")
    parser.add_argument("--site-url", default="https://tinyzkp.com", help="TinyZKP site origin for live checks")
    parser.add_argument("--api-url", default="https://api.tinyzkp.com", help="TinyZKP API origin for live checks")
    parser.add_argument("--mcp-url", default="https://mcp.tinyzkp.com", help="TinyZKP MCP origin for live checks")
    parser.add_argument("--stripe-checkout", action="store_true", help="Run live Stripe Checkout Session summary")
    parser.add_argument("--stripe-bin", default="stripe", help="Stripe CLI executable path for --stripe-checkout")
    parser.add_argument("--stripe-project-name", default="", help="Optional Stripe CLI project profile name for --stripe-checkout")
    parser.add_argument(
        "--stripe-account-source",
        choices=("cli", "api"),
        default=os.environ.get(
            "TINYZKP_GROWTH_STRIPE_ACCOUNT_SOURCE",
            os.environ.get("TINYZKP_STRIPE_ACCOUNT_SOURCE", "cli"),
        ),
        help="Stripe checkout source: CLI profile or Stripe API key",
    )
    parser.add_argument(
        "--stripe-api-key-env",
        default=os.environ.get(
            "TINYZKP_GROWTH_STRIPE_API_KEY_ENV",
            os.environ.get("TINYZKP_STRIPE_API_KEY_ENV", "STRIPE_SECRET_KEY"),
        ),
        help="Environment variable containing the Stripe secret key for --stripe-account-source api",
    )
    parser.add_argument("--stripe-checkout-test-mode", action="store_true", help="Use Stripe test mode for --stripe-checkout")
    parser.add_argument("--stripe-checkout-limit", type=int, default=100, help="Checkout sessions per Stripe page")
    parser.add_argument("--stripe-checkout-max-pages", type=int, default=3, help="Maximum Stripe pages to read")
    parser.add_argument("--stripe-checkout-lookback-hours", type=float, default=168, help="Trailing checkout window for Stripe summary")
    parser.add_argument("--stripe-checkout-include-monitoring-sessions", action="store_true", help="Include source=api_health_audit canary sessions in Stripe Checkout revenue summaries")
    parser.add_argument(
        "--stripe-expected-display-name",
        default=os.environ.get("TINYZKP_STRIPE_EXPECTED_DISPLAY_NAME", "LN Holdings"),
        help="Required substring in the active Stripe account display_name for --stripe-checkout",
    )
    parser.add_argument("--stripe-skip-account-check", action="store_true", help="Skip Stripe account display_name validation for --stripe-checkout")
    parser.add_argument("--stripe-account-check-timeout", type=int, default=30, help="Stripe account-context timeout in seconds")
    parser.add_argument("--stripe-checkout-min-paid-sessions", type=int, help="Fail unless at least this many paid Checkout Sessions are observed")
    parser.add_argument("--stripe-checkout-min-pilot-paid-sessions", type=int, help="Fail unless at least this many paid Production Pilot Sessions are observed")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    return parser


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    result = run_monitor(args)
    failures = [check for check in result.checks if check.status == "FAIL"]
    if args.json:
        print(json.dumps(_json_result(result), indent=2))
    else:
        _print_text(result)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
