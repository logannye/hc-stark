import argparse
import importlib.util
import json
import sqlite3
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BILLING_DIR = ROOT / "billing"
MODULE_PATH = ROOT / "scripts" / "monitoring" / "gtm_growth_monitor.py"
sys.path.insert(0, str(BILLING_DIR))
spec = importlib.util.spec_from_file_location("gtm_growth_monitor", MODULE_PATH)
monitor = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = monitor
spec.loader.exec_module(monitor)

import tenant_store  # noqa: E402


def args(**overrides):
    defaults = {
        "offline": True,
        "live": False,
        "timeout": 0.01,
        "tenant_db": "/tmp/tinyzkp-missing-test-tenant.sqlite",
        "usage_db": "/tmp/tinyzkp-missing-test-usage.sqlite",
        "strict_revenue": False,
        "min_activated_accounts": None,
        "min_paid_accounts": None,
        "min_paid_proofs": None,
        "min_total_proofs": None,
        "site_url": "https://tinyzkp.com",
        "api_url": "https://api.tinyzkp.com",
        "mcp_url": "https://mcp.tinyzkp.com",
        "stripe_checkout": False,
        "stripe_bin": "stripe",
        "stripe_project_name": "",
        "stripe_checkout_test_mode": False,
        "stripe_checkout_limit": 100,
        "stripe_checkout_max_pages": 3,
        "stripe_checkout_lookback_hours": 168,
        "stripe_checkout_include_monitoring_sessions": False,
        "stripe_expected_display_name": "TinyZKP",
        "stripe_skip_account_check": False,
        "stripe_account_check_timeout": 30,
        "stripe_checkout_min_paid_sessions": None,
        "stripe_checkout_min_pilot_paid_sessions": None,
        "json": False,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def create_usage_db(path):
    conn = sqlite3.connect(path)
    with conn:
        conn.execute(
            """CREATE TABLE usage_log (
              tenant_id TEXT NOT NULL,
              job_id TEXT UNIQUE,
              trace_length INTEGER NOT NULL,
              workload_id TEXT,
              duration_ms INTEGER,
              completed_at_ms INTEGER NOT NULL,
              billed INTEGER DEFAULT 0
            )"""
        )
        conn.execute(
            "INSERT INTO usage_log (tenant_id, job_id, trace_length, completed_at_ms) VALUES (?, ?, ?, ?)",
            ("t_free", "job_free", 64, 2_000),
        )
        conn.execute(
            "INSERT INTO usage_log (tenant_id, job_id, trace_length, completed_at_ms) VALUES (?, ?, ?, ?)",
            ("t_paid", "job_paid", 128, 3_000),
        )
    conn.close()


def test_offline_monitor_passes_policy_checks_and_warns_on_missing_revenue_stores(tmp_path):
    result = monitor.run_monitor(
        args(
            tenant_db=str(tmp_path / "missing-tenant.sqlite"),
            usage_db=str(tmp_path / "missing-usage.sqlite"),
        )
    )

    assert not [check for check in result.checks if check.status == "FAIL"]
    assert any(check.status == "WARN" and check.name == "tenant store" for check in result.checks)
    assert any(check.category == "badge embeds" for check in result.checks)
    assert any(check.category == "SEO conversion" for check in result.checks)
    assert any(check.category == "MCP submissions" for check in result.checks)


def test_revenue_summary_counts_attributed_paid_activation_and_ledgers(tmp_path):
    tenant_db = tmp_path / "tenant.sqlite"
    usage_db = tmp_path / "usage.sqlite"
    conn = tenant_store.open_db(str(tenant_db))
    tenant_store.create_tenant(
        conn,
        tenant_id="t_free",
        email="free@example.com",
        api_key="tzk_free",
        plan="free",
        attribution={"source": "receipt_share", "medium": "verifier", "platform": "browser"},
    )
    tenant_store.create_tenant(
        conn,
        tenant_id="t_paid",
        email="paid@example.com",
        api_key="tzk_paid",
        plan="pro",
        attribution={"source": "smithery_mcp", "medium": "mcp_directory", "platform": "smithery"},
    )
    tenant_store.mark_lifecycle_email_sent(conn, "t_free", "first_proof", 4_000)
    tenant_store.mark_checkout_recovery_sent(conn, "cs_paid", "paid@example.com", "pro", 5_000)
    conn.close()
    create_usage_db(usage_db)

    revenue = monitor.load_revenue_summary(tenant_db, usage_db)

    assert revenue.accounts == 2
    assert revenue.activated_accounts == 2
    assert revenue.paid_accounts == 1
    assert revenue.free_accounts == 1
    assert revenue.total_proofs == 2
    assert revenue.paid_proofs == 1
    assert revenue.estimated_base_mrr == 79
    assert revenue.estimated_usage_revenue_cents == 4
    assert revenue.lifecycle_emails == 1
    assert revenue.checkout_recoveries == 1
    assert revenue.top_sources[0]["source"] == "smithery_mcp"
    assert revenue.top_sources[0]["paid_proofs"] == 1

    checks = monitor.revenue_checks(
        revenue,
        strict_revenue=False,
        min_activated_accounts=2,
        min_paid_accounts=1,
        min_paid_proofs=1,
        min_total_proofs=2,
    )
    assert not [check for check in checks if check.status == "FAIL"]


def test_strict_revenue_fails_when_no_paid_accounts_are_recorded(tmp_path):
    tenant_db = tmp_path / "tenant.sqlite"
    conn = tenant_store.open_db(str(tenant_db))
    tenant_store.create_tenant(
        conn,
        tenant_id="t_free",
        email="free@example.com",
        api_key="tzk_free",
        plan="free",
        attribution={"source": "pypi_tinyzkp", "medium": "package_registry", "platform": "pypi"},
    )
    conn.close()

    revenue = monitor.load_revenue_summary(tenant_db, tmp_path / "missing-usage.sqlite")
    checks = monitor.revenue_checks(
        revenue,
        strict_revenue=True,
        min_activated_accounts=None,
        min_paid_accounts=None,
        min_paid_proofs=None,
        min_total_proofs=None,
    )

    failed_details = "\n".join(check.detail for check in checks if check.status == "FAIL")
    assert "minimum is 1" in failed_details
    assert any(check.name == "paid accounts" and check.status == "FAIL" for check in checks)
    assert any(check.name == "paid proofs" and check.status == "FAIL" for check in checks)


def test_json_result_omits_tenant_email_addresses(tmp_path):
    tenant_db = tmp_path / "tenant.sqlite"
    usage_db = tmp_path / "usage.sqlite"
    conn = tenant_store.open_db(str(tenant_db))
    tenant_store.create_tenant(
        conn,
        tenant_id="t_paid",
        email="secret@example.com",
        api_key="tzk_paid",
        plan="pro",
        attribution={"source": "agent_offer", "medium": "llm", "platform": "agent"},
    )
    conn.close()
    create_usage_db(usage_db)

    revenue = monitor.load_revenue_summary(tenant_db, usage_db)
    payload = json.dumps(monitor._json_result(monitor.MonitorResult(checks=[], revenue=revenue)))

    assert "secret@example.com" not in payload
    assert "agent_offer" in payload
    assert "estimated_base_mrr" in payload
    assert "paid_proofs" in payload


def test_live_checks_cover_public_funnel_and_package_registries(monkeypatch):
    seen_urls = []

    def fake_fetch_status(url, *, method="GET", body=None, timeout=0.01):
        seen_urls.append(url)
        if "/api/create-" in url:
            return 400, None
        return 200, None

    monkeypatch.setattr(monitor, "fetch_status", fake_fetch_status)

    checks = monitor.live_checks("https://site.example", "https://api.example", "https://mcp.example", timeout=0.01)

    assert not [check for check in checks if check.status == "FAIL"]
    assert any(check.category == "live public funnel" and check.name == "checkout endpoint" for check in checks)
    assert any(check.category == "live public funnel" and check.name == "pilot checkout endpoint" for check in checks)
    assert any(check.category == "package registry live" and check.name == "PyPI Python SDK" for check in checks)
    assert "https://registry.npmjs.org/@tinyzkp%2fcli" in seen_urls
    assert "https://crates.io/api/v1/crates/tinyzkp" in seen_urls


def test_live_checks_accept_invalid_probe_rate_limits(monkeypatch):
    def fake_fetch_status(url, *, method="GET", body=None, timeout=0.01):
        if "/api/create-" in url:
            return 429, "rate limited"
        return 200, None

    monkeypatch.setattr(monitor, "fetch_status", fake_fetch_status)

    checks = monitor.live_checks("https://site.example", "https://api.example", "https://mcp.example", timeout=0.01)

    assert not [check for check in checks if check.status == "FAIL"]
    assert any(
        check.category == "live public funnel"
        and check.name == "signup endpoint"
        and "rate-limited repeated invalid probes" in check.detail
        for check in checks
    )


def test_stripe_checkout_checks_summarize_paid_sessions_without_live_api():
    def fake_collector(**kwargs):
        assert kwargs["stripe_bin"] == "/opt/homebrew/bin/stripe"
        assert kwargs["stripe_project_name"] == "tinyzkp-prod"
        assert kwargs["live"] is True
        assert kwargs["limit"] == 25
        assert kwargs["include_monitoring"] is False
        return {
            "sessions": 2,
            "open": 1,
            "complete": 1,
            "paid": 1,
            "production_pilot_starts": 1,
            "production_pilot_paid": 1,
            "paid_amount_by_currency": {"usd": 500_000},
        }

    checks, payload = monitor.stripe_checkout_checks(
        args(
            stripe_bin="/opt/homebrew/bin/stripe",
            stripe_project_name="tinyzkp-prod",
            stripe_checkout_limit=25,
            stripe_checkout_min_paid_sessions=1,
            stripe_checkout_min_pilot_paid_sessions=1,
        ),
        collector_fn=fake_collector,
    )

    assert payload["paid"] == 1
    assert not [check for check in checks if check.status == "FAIL"]
    assert any(check.category == "Stripe checkout" and check.name == "live checkout query" for check in checks)
    assert any("USD 5000.00" in check.detail for check in checks)
