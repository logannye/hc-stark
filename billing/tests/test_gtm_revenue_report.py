import importlib.util
import sqlite3
import sys
from pathlib import Path


BILLING_DIR = Path(__file__).resolve().parents[1]
MODULE_PATH = BILLING_DIR / "gtm_revenue_report.py"
sys.path.insert(0, str(BILLING_DIR))
spec = importlib.util.spec_from_file_location("gtm_revenue_report", MODULE_PATH)
report = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = report
spec.loader.exec_module(report)


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
            ("t_pypi", "job_1", 128, 2_000_000),
        )
        conn.execute(
            "INSERT INTO usage_log (tenant_id, job_id, trace_length, completed_at_ms) VALUES (?, ?, ?, ?)",
            ("t_paid", "job_2", 256, 2_500_000),
        )
    conn.close()


def test_report_groups_accounts_by_attribution_source(tmp_path):
    tenant_db = tmp_path / "tenant.sqlite"
    usage_db = tmp_path / "usage.sqlite"
    conn = report.tenant_store.open_db(str(tenant_db))
    report.tenant_store.create_tenant(
        conn,
        tenant_id="t_pypi",
        email="python@example.com",
        api_key="tzk_python",
        plan="free",
        attribution={"source": "pypi_tinyzkp", "medium": "package_registry", "platform": "pypi"},
    )
    report.tenant_store.create_tenant(
        conn,
        tenant_id="t_paid",
        email="smithery@example.com",
        api_key="tzk_paid",
        plan="pro",
        attribution={"source": "smithery_mcp", "medium": "mcp_directory", "platform": "smithery"},
    )
    with conn:
        conn.execute("UPDATE tenants SET created_at_ms = 1000000")
    conn.close()
    create_usage_db(usage_db)

    tenants = report.load_tenants(str(tenant_db))
    usage = report.load_usage_by_tenant(str(usage_db), current_ms=3_000_000)
    groups = report.summarize(tenants, usage)

    by_source = {group.source: group for group in groups}
    assert by_source["pypi_tinyzkp"].accounts == 1
    assert by_source["pypi_tinyzkp"].activated_accounts == 1
    assert by_source["pypi_tinyzkp"].paid_accounts == 0
    assert by_source["smithery_mcp"].paid_accounts == 1
    assert by_source["smithery_mcp"].paid_proofs == 1
    assert by_source["smithery_mcp"].estimated_base_mrr == 79
    assert by_source["smithery_mcp"].estimated_usage_revenue_cents == 4
    assert by_source["smithery_mcp"].trace_length_sum == 256
    assert by_source["smithery_mcp"].first_proof_accounts == 1
    assert by_source["smithery_mcp"].avg_time_to_first_proof_hours > 0


def test_report_estimates_compute_trace_step_revenue(tmp_path):
    tenant_db = tmp_path / "tenant.sqlite"
    usage_db = tmp_path / "usage.sqlite"
    conn = report.tenant_store.open_db(str(tenant_db))
    report.tenant_store.create_tenant(
        conn,
        tenant_id="t_compute",
        email="compute@example.com",
        api_key="tzk_compute",
        plan="compute",
        attribution={"source": "calculator", "medium": "site", "platform": "website"},
    )
    with conn:
        conn.execute("UPDATE tenants SET created_at_ms = 1000000")
    conn.close()

    usage_conn = sqlite3.connect(usage_db)
    with usage_conn:
        usage_conn.execute(
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
        usage_conn.execute(
            "INSERT INTO usage_log (tenant_id, job_id, trace_length, completed_at_ms) VALUES (?, ?, ?, ?)",
            ("t_compute", "job_compute", 10_000_000, 2_000_000),
        )
    usage_conn.close()

    groups = report.summarize(
        report.load_tenants(str(tenant_db)),
        report.load_usage_by_tenant(str(usage_db), current_ms=3_000_000),
    )

    group = groups[0]
    assert group.source == "calculator"
    assert group.paid_accounts == 1
    assert group.compute_trace_steps == 10_000_000
    assert group.estimated_base_mrr == 0
    assert group.estimated_usage_revenue_cents == 500


def test_markdown_report_omits_email_addresses(tmp_path):
    tenant_db = tmp_path / "tenant.sqlite"
    conn = report.tenant_store.open_db(str(tenant_db))
    report.tenant_store.create_tenant(
        conn,
        tenant_id="t_direct",
        email="secret@example.com",
        api_key="tzk_direct",
        plan="free",
        attribution={"landing_path": "/pricing"},
    )
    conn.close()

    groups = report.summarize(report.load_tenants(str(tenant_db)), {})
    markdown = report.report_markdown(groups, generated_ms=1_000)

    assert "secret@example.com" not in markdown
    assert "landing:/pricing" in markdown
    assert "Estimated active base MRR" in markdown
    assert "Estimated usage revenue" in markdown
