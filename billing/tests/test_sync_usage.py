"""Tests for billing/sync_usage.py."""

import json
import os
import sqlite3
import sys
from io import StringIO
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# sync_usage reads STRIPE_SECRET_KEY at import time.
os.environ.setdefault("STRIPE_SECRET_KEY", "sk_test_fake")

import sync_usage
import tenant_store


@pytest.fixture
def setup(tmp_path):
    """Create tenant_store and usage databases with test data."""
    # Tenant store.
    ts_path = str(tmp_path / "tenant_store.sqlite")
    ts_conn = tenant_store.open_db(ts_path)
    tenant_store.create_tenant(
        ts_conn, "t_1", "user@example.com", "key1",
        stripe_customer_id="cus_abc",
        stripe_subscription_id="sub_1",
        stripe_subscription_item_id="si_1",
    )
    ts_conn.close()

    # Usage database.
    usage_path = str(tmp_path / "usage.sqlite")
    usage_conn = sqlite3.connect(usage_path)
    usage_conn.execute("""
        CREATE TABLE usage_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            job_id TEXT NOT NULL,
            trace_length INTEGER NOT NULL,
            billed INTEGER NOT NULL DEFAULT 0
        )
    """)
    usage_conn.execute(
        "INSERT INTO usage_log (tenant_id, job_id, trace_length) VALUES (?, ?, ?)",
        ("t_1", "job_100", 5000),  # < 10K → 5 cents
    )
    usage_conn.execute(
        "INSERT INTO usage_log (tenant_id, job_id, trace_length) VALUES (?, ?, ?)",
        ("t_1", "job_101", 50_000),  # 10K-100K → 50 cents
    )
    usage_conn.commit()
    usage_conn.close()

    return {"ts_path": ts_path, "usage_path": usage_path, "tmp_path": tmp_path}


class TestPriceCents:
    def test_small_trace(self):
        assert sync_usage.price_cents(100) == 5

    def test_boundary_10k(self):
        assert sync_usage.price_cents(9_999) == 5
        assert sync_usage.price_cents(10_000) == 50

    def test_medium_trace(self):
        assert sync_usage.price_cents(50_000) == 50

    def test_boundary_100k(self):
        assert sync_usage.price_cents(99_999) == 50
        assert sync_usage.price_cents(100_000) == 200

    def test_large_trace(self):
        assert sync_usage.price_cents(500_000) == 200

    def test_boundary_1m(self):
        assert sync_usage.price_cents(999_999) == 200
        assert sync_usage.price_cents(1_000_000) == 500

    def test_very_large_trace(self):
        assert sync_usage.price_cents(5_000_000) == 500

    def test_xl_trace(self):
        assert sync_usage.price_cents(10_000_000) == 2000
        assert sync_usage.price_cents(100_000_000) == 2000


class TestDryRun:
    def test_dry_run_prints_meter_events(self, setup, capsys):
        ts_path = setup["ts_path"]
        usage_path = setup["usage_path"]

        with patch.dict(os.environ, {
            "STRIPE_SECRET_KEY": "sk_test_fake",
            "HC_USAGE_DB_PATH": usage_path,
            "HC_TENANT_STORE_PATH": ts_path,
        }):
            # Re-import to pick up env vars.
            sync_usage.USAGE_DB_PATH = usage_path
            # Patch tenant_store.open_db to use our test path.
            with patch("tenant_store.open_db", return_value=tenant_store.open_db(ts_path)):
                with patch("sys.argv", ["sync_usage.py", "--dry-run"]):
                    sync_usage.main()

        output = capsys.readouterr().out
        lines = [json.loads(l) for l in output.strip().split("\n") if l.strip()]

        would_bill = [l for l in lines if l.get("action") == "would_bill"]
        assert len(would_bill) == 2
        # Verify meter event fields present instead of subscription_item_id.
        assert "stripe_customer_id" in would_bill[0]
        assert "meter_event" in would_bill[0]
        assert would_bill[0]["stripe_customer_id"] == "cus_abc"


class TestReport:
    def test_report_mode(self, setup, capsys):
        usage_path = setup["usage_path"]
        ts_path = setup["ts_path"]

        sync_usage.USAGE_DB_PATH = usage_path
        with patch("tenant_store.open_db", return_value=tenant_store.open_db(ts_path)):
            with patch("sys.argv", ["sync_usage.py", "--report"]):
                sync_usage.main()

        output = capsys.readouterr().out
        summary = json.loads(output)
        assert "t_1" in summary
        assert summary["t_1"]["count"] == 2
        assert summary["t_1"]["total_cents"] == 55  # 5 + 50


class TestUnbillable:
    def test_skips_tenant_without_customer_id(self, setup, capsys):
        tmp_path = setup["tmp_path"]

        # Create tenant without stripe_customer_id.
        ts_path = str(tmp_path / "ts_no_cus.sqlite")
        ts_conn = tenant_store.open_db(ts_path)
        tenant_store.create_tenant(ts_conn, "t_no_cus", "x@y.com", "key1")
        ts_conn.close()

        usage_path = str(tmp_path / "usage_no_cus.sqlite")
        usage_conn = sqlite3.connect(usage_path)
        usage_conn.execute("""
            CREATE TABLE usage_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT, job_id TEXT, trace_length INTEGER, billed INTEGER DEFAULT 0
            )
        """)
        usage_conn.execute(
            "INSERT INTO usage_log (tenant_id, job_id, trace_length) VALUES (?, ?, ?)",
            ("t_no_cus", "job_1", 1000),
        )
        usage_conn.commit()
        usage_conn.close()

        sync_usage.USAGE_DB_PATH = usage_path
        with patch("tenant_store.open_db", return_value=tenant_store.open_db(ts_path)):
            with patch("sys.argv", ["sync_usage.py", "--dry-run"]):
                sync_usage.main()

        output = capsys.readouterr().out
        lines = [json.loads(l) for l in output.strip().split("\n") if l.strip()]
        complete = [l for l in lines if l.get("action") == "complete"]
        assert len(complete) == 1
        assert complete[0]["skipped"] == 1
        assert complete[0]["billed"] == 0
